use chrono::Duration;
use hyper::http::request::Parts;
use regex::Regex;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, LazyLock};
use tracing::{debug, error, info, instrument};

pub mod blob;
pub mod blob_store;
pub mod cache;
pub mod client;
pub mod content_discovery;
pub mod data_store;
mod error;
pub mod manifest;
pub mod metadata_store;
pub mod oci;
mod path_builder;
pub mod repository;
mod scrub;
pub mod server;
pub mod task_queue;
#[cfg(test)]
mod tests;
pub mod upload;
mod version;

use crate::configuration;
use crate::configuration::{CacheStoreConfig, GlobalConfig, RepositoryConfig};
use crate::registry::cache::Cache;
use crate::registry::server::auth::webhook::WebhookAuthorizer;
pub use repository::Repository;
use repository::{AccessPolicy, RetentionPolicy};

use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::server::route::Route;
use crate::registry::server::ClientIdentity;
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
    repositories: HashMap<String, Repository>,
    global_access_policy: Option<AccessPolicy>,
    global_retention_policy: Option<RetentionPolicy>,
    global_immutable_tags: bool,
    global_immutable_tags_exclusions: Vec<Regex>,
    global_authorization_webhook: Option<String>,
    webhooks: HashMap<String, Arc<WebhookAuthorizer>>,
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

fn log_denial(reason: &str, identity: &ClientIdentity) {
    info!("Access denied: {reason} | Identity: {identity:?}");
}

impl Registry {
    #[instrument(skip(
        repositories_config,
        blob_store,
        metadata_store,
        auth_token_cache,
        auth_config
    ))]
    pub fn new(
        blob_store: Arc<dyn BlobStore + Send + Sync>,
        metadata_store: Arc<dyn MetadataStore + Send + Sync>,
        repositories_config: HashMap<String, RepositoryConfig>,
        global_config: &GlobalConfig,
        auth_token_cache: &CacheStoreConfig,
        auth_config: &configuration::AuthConfig,
    ) -> Result<Self, configuration::Error> {
        let auth_token_cache_arc: Arc<dyn Cache> =
            if let CacheStoreConfig::Redis(ref redis_config) = auth_token_cache {
                Arc::new(cache::redis::Backend::new(redis_config.clone())?)
            } else {
                Arc::new(cache::memory::Backend::new())
            };

        let mut repositories = HashMap::new();
        for (repository_name, repository_config) in repositories_config {
            let res = Repository::new(
                repository_name.clone(),
                repository_config,
                &auth_token_cache_arc,
            )?;
            repositories.insert(repository_name, res);
        }

        let global_access_policy = if global_config.access_policy.rules.is_empty() {
            None
        } else {
            Some(AccessPolicy::new(&global_config.access_policy)?)
        };

        let global_retention_policy = if global_config.retention_policy.rules.is_empty() {
            None
        } else {
            Some(RetentionPolicy::new(&global_config.retention_policy)?)
        };

        let global_immutable_tags_exclusions = global_config
            .immutable_tags_exclusions
            .iter()
            .filter_map(|p| match Regex::new(p) {
                Ok(regex) => Some(regex),
                Err(e) => {
                    error!("Invalid global regex pattern '{}': {}", p, e);
                    None
                }
            })
            .collect();

        // Initialize webhooks
        let mut webhooks = HashMap::new();
        for (name, webhook_config) in &auth_config.webhook {
            let authorizer = WebhookAuthorizer::new(
                name.clone(),
                webhook_config.clone(),
                auth_token_cache_arc.clone(),
            )
            .map_err(|e| {
                configuration::Error::ConfigurationFileFormat(format!(
                    "Failed to initialize webhook '{name}': {e}"
                ))
            })?;
            webhooks.insert(name.clone(), Arc::new(authorizer));
        }

        let res = Self {
            update_pull_time: global_config.update_pull_time,
            blob_store,
            metadata_store,
            repositories,
            global_access_policy,
            global_retention_policy,
            global_immutable_tags: global_config.immutable_tags,
            global_immutable_tags_exclusions,
            global_authorization_webhook: global_config.authorization_webhook.clone(),
            webhooks,
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
    pub fn get_repository_for_namespace(&self, namespace: &str) -> Result<&Repository, Error> {
        if NAMESPACE_RE.is_match(namespace) {
            self.repositories
                .iter()
                .find(|(repository, _)| {
                    namespace == repository.as_str()
                        || namespace.starts_with(&format!("{repository}/"))
                })
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
    /// 2. Evaluates global access policy first (if defined)
    /// 3. Evaluates the repository's access policy
    /// 4. Enforces pull-through cache write restrictions
    ///
    /// # Arguments
    /// * `repository` - The target repository (if it exists)
    /// * `request` - The client request to validate
    /// * `identity` - The client's identity information
    ///
    /// # Returns
    /// * `Ok(())` if the request is allowed
    /// * `Err(Error::Unauthorized)` if the request is denied
    #[instrument(skip(self, request))]
    pub async fn validate_request(
        &self,
        route: &Route<'_>,
        identity: &ClientIdentity,
        request: &Parts,
    ) -> Result<(), Error> {
        if !identity.token_scopes.is_empty() {
            use crate::registry::server::auth::token::route_requires_scope;

            let has_required_scope = identity
                .token_scopes
                .iter()
                .any(|scope| route_requires_scope(route, scope));

            if !has_required_scope {
                log_denial("token scope", identity);
                return Err(Error::Denied(
                    "Token does not grant access to this resource".to_string(),
                ));
            }

            return Ok(());
        }

        if let Some(global_policy) = &self.global_access_policy {
            debug!("Evaluating global access policy");
            let allowed = global_policy.evaluate(route, identity)?;
            if !allowed {
                log_denial("global policy", identity);
                return Err(Error::Unauthorized(
                    "Access denied by global policy".to_string(),
                ));
            }
        }

        if let Some(namespace) = route.get_namespace() {
            if let Ok(repository) = self.get_repository_for_namespace(namespace) {
                debug!(
                    "Evaluating repository access policy for namespace: {namespace} ({})",
                    repository.name
                );

                let allowed = repository.access_policy.evaluate(route, identity)?;
                if !allowed {
                    log_denial(
                        &format!("repository '{}' policy", repository.name),
                        identity,
                    );
                    return Err(Error::Unauthorized("Access denied".to_string()));
                }

                // Check webhook authorization
                let webhook_name = repository
                    .authorization_webhook
                    .as_ref()
                    .filter(|name| !name.is_empty())
                    .or(self.global_authorization_webhook.as_ref());

                if let Some(webhook_name) = webhook_name {
                    debug!("Evaluating webhook authorization: {}", webhook_name);

                    let webhook = self
                        .webhooks
                        .get(webhook_name)
                        .expect("webhook validated at config load");

                    // Reconstruct a minimal Request from parts for the webhook
                    let allowed = webhook.authorize(route, identity, request).await?;
                    if !allowed {
                        log_denial(&format!("webhook '{webhook_name}'"), identity);
                        return Err(Error::Unauthorized("Access denied by webhook".to_string()));
                    }
                }

                if repository.is_pull_through() && route.is_write() {
                    return Err(Error::Unauthorized(
                        "Write operations are not supported on pull-through cache repositories"
                            .to_string(),
                    ));
                }
            } else if self.global_access_policy.is_none() {
                return Err(Error::NotFound);
            }
        } else {
            // For routes without namespace, check global webhook
            if let Some(webhook_name) = &self.global_authorization_webhook {
                debug!("Evaluating global webhook authorization: {}", webhook_name);

                let webhook = self
                    .webhooks
                    .get(webhook_name)
                    .expect("webhook validated at config load");

                let allowed = webhook.authorize(route, identity, request).await?;
                if !allowed {
                    log_denial(&format!("global webhook '{webhook_name}'"), identity);
                    return Err(Error::Unauthorized("Access denied by webhook".to_string()));
                }
            }
        }

        Ok(())
    }

    fn is_tag_mutable(&self, repository: &Repository, tag: &str) -> bool {
        let immutable = repository.immutable_tags || self.global_immutable_tags;

        if !immutable {
            return true;
        }

        let exclusions = if repository.immutable_tags_exclusions.is_empty() {
            &self.global_immutable_tags_exclusions
        } else {
            &repository.immutable_tags_exclusions
        };

        exclusions.iter().any(|pattern| pattern.is_match(tag))
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::registry::metadata_store::link_kind::LinkKind;
    use crate::registry::oci::Digest;
    use crate::registry::repository::access_policy::RepositoryAccessPolicyConfig;
    use crate::registry::repository::retention_policy::RepositoryRetentionPolicyConfig;
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

    pub fn create_test_registry(
        blob_store: Arc<dyn BlobStore + Send + Sync>,
        metadata_store: Arc<dyn MetadataStore + Send + Sync>,
    ) -> Registry {
        let repositories_config = create_test_repository_config();
        let global = GlobalConfig::default();
        let token_cache = CacheStoreConfig::default();

        Registry::new(
            blob_store,
            metadata_store,
            repositories_config,
            &global,
            &token_cache,
            &configuration::AuthConfig::default(),
        )
        .unwrap()
        .with_upload_timeout(Duration::seconds(0))
        .with_scrub_dry_run(false)
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
        let cache: Arc<dyn Cache> = Arc::new(cache::memory::Backend::new());
        let repository = Repository::new(
            "test-repo".to_string(),
            RepositoryConfig {
                upstream: Vec::new(),
                access_policy: RepositoryAccessPolicyConfig::default(),
                retention_policy: RepositoryRetentionPolicyConfig { rules: Vec::new() },
                immutable_tags: false,
                immutable_tags_exclusions: Vec::new(),
                authorization_webhook: None,
            },
            &cache,
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
    use crate::configuration::{CacheStoreConfig, GlobalConfig, RepositoryConfig};
    use crate::registry::blob_store::fs::{Backend as FSBlobStore, BackendConfig as FSBlobConfig};
    use crate::registry::metadata_store::fs::{
        Backend as FSMetadataStore, BackendConfig as FSMetadataConfig,
    };
    use crate::registry::oci::Reference;
    use crate::registry::repository::access_policy::RepositoryAccessPolicyConfig;
    use crate::registry::repository::retention_policy::RepositoryRetentionPolicyConfig;
    use crate::registry::server::ClientIdentity;
    use crate::registry::tests::FSRegistryTestCase;
    use hyper::Request;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn create_default_deny_repo(rules: Vec<String>) -> Repository {
        let config = RepositoryConfig {
            retention_policy: RepositoryRetentionPolicyConfig::default(),
            access_policy: RepositoryAccessPolicyConfig {
                default_allow: false,
                rules,
            },
            ..RepositoryConfig::default()
        };

        let cache: Arc<dyn Cache> = Arc::new(cache::memory::Backend::new());
        Repository::new("policy-deny-repo".to_string(), config, &cache).unwrap()
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

        let cache: Arc<dyn Cache> = Arc::new(cache::memory::Backend::new());
        Repository::new("policy-allow-repo".to_string(), config, &cache).unwrap()
    }

    #[tokio::test]
    async fn test_validate_request_no_namespace() {
        let t = FSRegistryTestCase::new();
        let route = Route::ListCatalog {
            n: None,
            last: None,
        };
        let identity = ClientIdentity::default();

        assert!(t
            .registry()
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_request_no_repository() {
        let t = FSRegistryTestCase::new();
        let reference = Reference::Tag("latest".to_string());

        let route = Route::GetManifest {
            namespace: "policy-deny-repo",
            reference,
        };
        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };

        // No repository and no global policy - should deny
        assert!(t
            .registry()
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_err());

        let identity = ClientIdentity {
            username: Some("admin".to_string()),
            ..ClientIdentity::default()
        };

        // No repository and no global policy - should deny
        assert!(t
            .registry()
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_request_default_allow_no_rules() {
        let mut t = FSRegistryTestCase::new();
        let reference = Reference::Tag("latest".to_string());

        t.registry_mut().repositories.insert(
            "policy-allow-repo".to_string(),
            create_default_allow_repo(Vec::new()),
        );

        let route = Route::GetManifest {
            namespace: "policy-allow-repo",
            reference,
        };
        let identity = ClientIdentity {
            username: Some("whatever-identity".to_string()),
            ..ClientIdentity::default()
        };

        assert!(t
            .registry()
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_request_default_deny_no_rules() {
        let mut t = FSRegistryTestCase::new();
        let reference = Reference::Tag("latest".to_string());

        t.registry_mut().repositories.insert(
            "policy-deny-repo".to_string(),
            create_default_deny_repo(Vec::new()),
        );

        let route = Route::GetManifest {
            namespace: "policy-deny-repo",
            reference,
        };
        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };

        assert!(t
            .registry()
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_err());
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

        let route = Route::GetManifest {
            namespace: "policy-allow-repo",
            reference,
        };
        let identity = ClientIdentity {
            username: Some("whatever-identity".to_string()),
            ..ClientIdentity::default()
        };

        assert!(t
            .registry()
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_ok());

        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };

        assert!(t
            .registry()
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_err());
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

        let route = Route::GetManifest {
            namespace: "policy-deny-repo",
            reference,
        };
        let identity = ClientIdentity {
            username: Some("admin".to_string()),
            ..ClientIdentity::default()
        };

        assert!(t
            .registry()
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_ok());

        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };

        assert!(t
            .registry()
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_global_access_policy_deny() {
        let global_config = GlobalConfig {
            access_policy: RepositoryAccessPolicyConfig {
                default_allow: false,
                rules: vec!["identity.username == 'admin'".to_string()],
            },
            ..Default::default()
        };

        let temp_dir = std::env::temp_dir().to_string_lossy().to_string();
        let blob_config = FSBlobConfig {
            root_dir: temp_dir.clone(),
            sync_to_disk: false,
        };
        let blob_store = Arc::new(FSBlobStore::new(blob_config));
        let metadata_config = FSMetadataConfig {
            root_dir: temp_dir,
            redis: None,
            sync_to_disk: false,
        };
        let metadata_store = Arc::new(FSMetadataStore::new(metadata_config).unwrap());
        let registry = Registry::new(
            blob_store,
            metadata_store,
            HashMap::new(),
            &global_config,
            &CacheStoreConfig::Memory,
            &configuration::AuthConfig::default(),
        )
        .unwrap();

        let reference = Reference::Tag("latest".to_string());
        let route = Route::GetManifest {
            namespace: "test-namespace",
            reference,
        };

        // Admin should be allowed by global policy
        let identity = ClientIdentity {
            username: Some("admin".to_string()),
            ..ClientIdentity::default()
        };
        assert!(registry
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_ok());

        // Non-admin should be denied by global policy
        let identity = ClientIdentity {
            username: Some("user".to_string()),
            ..ClientIdentity::default()
        };
        assert!(registry
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_global_and_repository_policies() {
        let global_config = GlobalConfig {
            access_policy: RepositoryAccessPolicyConfig {
                default_allow: true,
                rules: vec!["identity.username == 'banned'".to_string()],
            },
            ..Default::default()
        };

        let temp_dir = std::env::temp_dir().to_string_lossy().to_string();
        let blob_config = FSBlobConfig {
            root_dir: temp_dir.clone(),
            sync_to_disk: false,
        };
        let blob_store = Arc::new(FSBlobStore::new(blob_config));
        let metadata_config = FSMetadataConfig {
            root_dir: temp_dir,
            redis: None,
            sync_to_disk: false,
        };
        let metadata_store = Arc::new(FSMetadataStore::new(metadata_config).unwrap());
        let mut registry = Registry::new(
            blob_store,
            metadata_store,
            HashMap::new(),
            &global_config,
            &CacheStoreConfig::Memory,
            &configuration::AuthConfig::default(),
        )
        .unwrap();

        // Add a repository with specific policy
        registry.repositories.insert(
            "restricted-repo".to_string(),
            create_default_deny_repo(vec!["identity.username == 'special'".to_string()]),
        );

        let reference = Reference::Tag("latest".to_string());
        let route = Route::GetManifest {
            namespace: "restricted-repo",
            reference,
        };

        // Banned user should be denied by global policy
        let identity = ClientIdentity {
            username: Some("banned".to_string()),
            ..ClientIdentity::default()
        };
        assert!(registry
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_err());

        // Special user should be allowed (passes both global and repo policies)
        let identity = ClientIdentity {
            username: Some("special".to_string()),
            ..ClientIdentity::default()
        };
        assert!(registry
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_ok());

        // Regular user should be denied by repository policy
        let identity = ClientIdentity {
            username: Some("regular".to_string()),
            ..ClientIdentity::default()
        };
        assert!(registry
            .validate_request(&route, &identity, &Request::new(()).into_parts().0)
            .await
            .is_err());
    }

    #[test]
    fn test_namespace_to_repository_matching() {
        use crate::configuration::{CacheStoreConfig, GlobalConfig, RepositoryConfig};
        use crate::registry::repository::access_policy::RepositoryAccessPolicyConfig;
        use crate::registry::repository::retention_policy::RepositoryRetentionPolicyConfig;

        let blob_store = Arc::new(blob_store::fs::Backend::new(
            blob_store::fs::BackendConfig {
                root_dir: "/tmp/test".into(),
                sync_to_disk: false,
            },
        ));

        let metadata_store = Arc::new(
            metadata_store::fs::Backend::new(metadata_store::fs::BackendConfig {
                root_dir: "/tmp/test".into(),
                sync_to_disk: false,
                redis: None,
            })
            .unwrap(),
        );

        let mut repositories_config = HashMap::new();
        repositories_config.insert(
            "test".to_string(),
            RepositoryConfig {
                upstream: vec![],
                access_policy: RepositoryAccessPolicyConfig::default(),
                retention_policy: RepositoryRetentionPolicyConfig::default(),
                immutable_tags: false,
                immutable_tags_exclusions: vec![],
                authorization_webhook: None,
            },
        );
        repositories_config.insert(
            "test-immutable".to_string(),
            RepositoryConfig {
                upstream: vec![],
                access_policy: RepositoryAccessPolicyConfig::default(),
                retention_policy: RepositoryRetentionPolicyConfig::default(),
                immutable_tags: true,
                immutable_tags_exclusions: vec![],
                authorization_webhook: None,
            },
        );

        let global_config = GlobalConfig::default();

        let registry = Registry::new(
            blob_store,
            metadata_store,
            repositories_config,
            &global_config,
            &CacheStoreConfig::Memory,
            &configuration::AuthConfig::default(),
        )
        .unwrap();

        // Exact match should work
        assert!(registry.get_repository_for_namespace("test").is_ok());
        assert!(registry
            .get_repository_for_namespace("test-immutable")
            .is_ok());

        // Path prefix should work
        assert!(registry.get_repository_for_namespace("test/foo").is_ok());
        assert!(registry
            .get_repository_for_namespace("test/foo/bar")
            .is_ok());
        assert!(registry
            .get_repository_for_namespace("test-immutable/foo")
            .is_ok());

        // Non-path prefix should NOT match
        assert!(registry.get_repository_for_namespace("testing").is_err());
        assert!(registry.get_repository_for_namespace("test123").is_err());
        assert!(registry.get_repository_for_namespace("test_foo").is_err());

        // Unknown namespaces should fail
        assert!(registry.get_repository_for_namespace("unknown").is_err());
        assert!(registry
            .get_repository_for_namespace("unknown/foo")
            .is_err());
    }
}
