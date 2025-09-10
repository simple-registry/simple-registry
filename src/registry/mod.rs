use chrono::Duration;
use regex::Regex;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, LazyLock};
use tracing::instrument;

pub mod blob;
pub mod blob_store;
pub mod cache;
pub mod content_discovery;
pub mod data_store;
mod error;
mod http_client;
pub mod manifest;
pub mod metadata_store;
pub mod oci;
pub mod repository;
mod scrub;
pub mod server;
pub mod task_queue;
#[cfg(test)]
mod tests;
pub mod upload;
pub mod utils;
mod version;

use crate::configuration;
use crate::configuration::{CacheStoreConfig, GlobalConfig, OidcProviderConfig, RepositoryConfig};
use crate::registry::cache::Cache;
pub use repository::Repository;

use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::MetadataStore;
pub use crate::registry::task_queue::TaskQueue;
pub use error::Error;
pub use manifest::parse_manifest_digests;
pub use server::response_body::ResponseBody;

static NAMESPACE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$").unwrap()
});

pub struct Registry {
    blob_store: Arc<dyn BlobStore + Send + Sync>,
    metadata_store: Arc<dyn MetadataStore + Send + Sync>,
    auth_token_cache: Box<dyn Cache>,
    repositories: HashMap<String, Repository>,
    update_pull_time: bool,
    scrub_dry_run: bool,
    upload_timeout: Duration,
    task_queue: TaskQueue,
}

impl Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry").finish()
    }
}

impl Registry {
    #[instrument(skip(
        repositories_config,
        blob_store,
        metadata_store,
        auth_token_cache,
        _oidc_config
    ))]
    pub fn new(
        blob_store: Arc<dyn BlobStore + Send + Sync>,
        metadata_store: Arc<dyn MetadataStore + Send + Sync>,
        repositories_config: HashMap<String, RepositoryConfig>,
        global_config: &GlobalConfig,
        auth_token_cache: &CacheStoreConfig,
        _oidc_config: &HashMap<String, OidcProviderConfig>,
    ) -> Result<Self, configuration::Error> {
        let auth_token_cache_box: Box<dyn Cache> =
            if let CacheStoreConfig::Redis(ref redis_config) = auth_token_cache {
                Box::new(cache::redis::Backend::new(redis_config.clone())?)
            } else {
                Box::new(cache::memory::Backend::new())
            };

        let mut repositories = HashMap::new();
        for (repository_name, repository_config) in repositories_config {
            let res = Repository::new(repository_config, repository_name.clone())?;
            repositories.insert(repository_name, res);
        }

        let res = Self {
            update_pull_time: global_config.update_pull_time,
            blob_store,
            metadata_store,
            auth_token_cache: auth_token_cache_box,
            repositories,
            scrub_dry_run: true,
            upload_timeout: Duration::days(1),
            task_queue: TaskQueue::new(global_config.max_concurrent_cache_jobs)?,
        };

        Ok(res)
    }

    pub fn with_scrub_dry_run(mut self, scrub_dry_run: bool) -> Self {
        self.scrub_dry_run = scrub_dry_run;
        self
    }

    pub fn with_upload_timeout(mut self, scrub_upload_timeout: Duration) -> Self {
        self.upload_timeout = scrub_upload_timeout;
        self
    }

    #[instrument]
    pub fn validate_namespace(&self, namespace: &str) -> Result<&Repository, Error> {
        if NAMESPACE_RE.is_match(namespace) {
            self.repositories
                .iter()
                .find(|(repository, _)| namespace.starts_with(*repository))
                .map(|(_, repository)| repository)
                .ok_or(Error::NameUnknown)
        } else {
            Err(Error::NameInvalid)
        }
    }

    /// Validates a registry request against access control policies.
    ///
    /// This method:
    /// 1. Checks if the request has a namespace (repository name)
    /// 2. Evaluates the repository's access policy
    /// 3. Enforces pull-through cache write restrictions
    ///
    /// # Arguments
    /// * `repository` - The target repository (if it exists)
    /// * `request` - The client request to validate
    /// * `identity` - The client's identity information
    ///
    /// # Returns
    /// * `Ok(())` if the request is allowed
    /// * `Err(Error::Unauthorized)` if the request is denied
    #[instrument(skip(repository, request))]
    pub fn validate_request(
        repository: Option<&Repository>,
        request: &server::ClientRequest,
        identity: &server::ClientIdentity,
    ) -> Result<(), Error> {
        use tracing::debug;

        let Some(namespace) = request.namespace.as_ref() else {
            return Ok(());
        };

        let Some(repository) = repository else {
            return Ok(());
        };

        debug!(
            "Evaluating access policy for namespace: {namespace} ({})",
            repository.name
        );

        let allowed = repository.access_policy.evaluate(request, identity)?;

        if !allowed {
            return Err(Error::Unauthorized("Access denied".to_string()));
        }

        if repository.is_pull_through() && request.is_write() {
            Err(Error::Unauthorized(
                "Write operations are not supported on pull-through cache repositories".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::configuration::{RepositoryAccessPolicyConfig, RepositoryRetentionPolicyConfig};
    use crate::registry::metadata_store::link_kind::LinkKind;
    use crate::registry::oci::Digest;
    use serde_json::json;

    pub fn create_test_repository_config() -> HashMap<String, RepositoryConfig> {
        let mut repositories = HashMap::new();
        repositories.insert(
            "test-repo".to_string(),
            RepositoryConfig {
                access_policy: RepositoryAccessPolicyConfig {
                    default_allow: true,
                    ..RepositoryAccessPolicyConfig::default()
                },
                retention_policy: RepositoryRetentionPolicyConfig::default(),
                ..RepositoryConfig::default()
            },
        );
        repositories
    }

    pub async fn create_test_blob(
        registry: &Registry,
        namespace: &str,
        content: &[u8],
    ) -> (Digest, Repository) {
        // Create a test blob
        let digest = registry.blob_store.create_blob(content).await.unwrap();

        // Create a tag to ensure the namespace exists
        let tag_link = LinkKind::Tag("latest".to_string());
        registry
            .metadata_store
            .create_link(namespace, &tag_link, &digest)
            .await
            .unwrap();

        // Verify the blob index is updated
        let blob_index = registry
            .metadata_store
            .read_blob_index(&digest)
            .await
            .unwrap();
        assert!(blob_index.namespace.contains_key(namespace));
        let namespace_links = blob_index.namespace.get(namespace).unwrap();
        assert!(namespace_links.contains(&tag_link));

        // Create a non-pull-through repository
        let repository = Repository::new(
            RepositoryConfig {
                upstream: Vec::new(),
                access_policy: RepositoryAccessPolicyConfig::default(),
                retention_policy: RepositoryRetentionPolicyConfig { rules: Vec::new() },
            },
            "test-repo".to_string(),
        )
        .unwrap();

        (digest, repository)
    }

    pub fn create_test_manifest() -> (Vec<u8>, String) {
        let manifest = json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "size": 1234
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    "size": 5678
                }
            ]
        });

        let content = serde_json::to_vec(&manifest).unwrap();
        let media_type = "application/vnd.docker.distribution.manifest.v2+json".to_string();
        (content, media_type)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::configuration::{
        RepositoryAccessPolicyConfig, RepositoryConfig, RepositoryRetentionPolicyConfig,
    };
    use crate::registry::oci::Reference;
    use crate::registry::server::{ClientIdentity, ClientRequest};
    use crate::registry::tests::FSRegistryTestCase;

    fn create_default_deny_repo(rules: Vec<String>) -> Repository {
        let config = RepositoryConfig {
            retention_policy: RepositoryRetentionPolicyConfig::default(),
            access_policy: RepositoryAccessPolicyConfig {
                default_allow: false,
                rules,
            },
            ..RepositoryConfig::default()
        };

        Repository::new(config, "policy-deny-repo".to_string()).unwrap()
    }

    fn create_default_allow_repo(rules: Vec<String>) -> Repository {
        let config = RepositoryConfig {
            access_policy: RepositoryAccessPolicyConfig {
                default_allow: true,
                rules,
            },
            retention_policy: RepositoryRetentionPolicyConfig::default(),
            ..RepositoryConfig::default()
        };

        Repository::new(config, "policy-allow-repo".to_string()).unwrap()
    }

    #[tokio::test]
    async fn test_validate_request_no_namespace() {
        let request = ClientRequest::list_catalog();
        let identity = ClientIdentity::default();

        assert!(Registry::validate_request(None, &request, &identity).is_ok());
    }

    #[tokio::test]
    async fn test_validate_request_no_repository() {
        let reference = Reference::Tag("latest".to_string());

        let request = ClientRequest::get_manifest("policy-deny-repo", &reference);
        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };

        assert!(Registry::validate_request(None, &request, &identity).is_ok());

        let request = ClientRequest::get_manifest("policy-deny-repo", &reference);
        let identity = ClientIdentity {
            username: Some("admin".to_string()),
            ..ClientIdentity::default()
        };

        assert!(Registry::validate_request(None, &request, &identity).is_ok());
    }

    #[tokio::test]
    async fn test_validate_request_default_allow_no_rules() {
        let mut t = FSRegistryTestCase::new();
        let reference = Reference::Tag("latest".to_string());

        t.registry_mut().repositories.insert(
            "policy-allow-repo".to_string(),
            create_default_allow_repo(Vec::new()),
        );

        let request = ClientRequest::get_manifest("policy-allow-repo", &reference);
        let identity = ClientIdentity {
            username: Some("whatever-identity".to_string()),
            ..ClientIdentity::default()
        };
        let repository = t
            .registry()
            .validate_namespace("policy-allow-repo")
            .unwrap();

        assert!(Registry::validate_request(Some(repository), &request, &identity).is_ok());
    }

    #[tokio::test]
    async fn test_validate_request_default_deny_no_rules() {
        let mut t = FSRegistryTestCase::new();
        let reference = Reference::Tag("latest".to_string());

        t.registry_mut().repositories.insert(
            "policy-deny-repo".to_string(),
            create_default_deny_repo(Vec::new()),
        );

        let request = ClientRequest::get_manifest("policy-deny-repo", &reference);
        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };
        let repository = t.registry().validate_namespace("policy-deny-repo").unwrap();

        assert!(Registry::validate_request(Some(repository), &request, &identity).is_err());
    }

    #[tokio::test]
    async fn test_validate_request_default_allow() {
        let mut t = FSRegistryTestCase::new();
        let reference = Reference::Tag("latest".to_string());

        let rules = vec!["identity.username == 'forbidden'".to_string()];
        t.registry_mut().repositories.insert(
            "policy-allow-repo".to_string(),
            create_default_allow_repo(rules),
        );

        let request = ClientRequest::get_manifest("policy-allow-repo", &reference);
        let identity = ClientIdentity {
            username: Some("whatever-identity".to_string()),
            ..ClientIdentity::default()
        };
        let repository = t
            .registry()
            .validate_namespace("policy-allow-repo")
            .unwrap();

        assert!(Registry::validate_request(Some(repository), &request, &identity).is_ok());

        let request = ClientRequest::get_manifest("policy-allow-repo", &reference);
        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };
        let repository = t
            .registry()
            .validate_namespace("policy-allow-repo")
            .unwrap();

        assert!(Registry::validate_request(Some(repository), &request, &identity).is_err());
    }

    #[tokio::test]
    async fn test_validate_request_default_deny() {
        let mut t = FSRegistryTestCase::new();
        let reference = Reference::Tag("latest".to_string());

        let rules = vec!["identity.username == 'admin'".to_string()];
        t.registry_mut().repositories.insert(
            "policy-deny-repo".to_string(),
            create_default_deny_repo(rules),
        );

        let request = ClientRequest::get_manifest("policy-deny-repo", &reference);
        let identity = ClientIdentity {
            username: Some("admin".to_string()),
            ..ClientIdentity::default()
        };
        let repository = t.registry().validate_namespace("policy-deny-repo").unwrap();

        assert!(Registry::validate_request(Some(repository), &request, &identity).is_ok());

        let request = ClientRequest::get_manifest("policy-deny-repo", &reference);
        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };
        let repository = t.registry().validate_namespace("policy-deny-repo").unwrap();

        assert!(Registry::validate_request(Some(repository), &request, &identity).is_err());
    }
}
