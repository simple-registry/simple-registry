use regex::Regex;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, LazyLock};
use tracing::instrument;

pub mod blob;
pub mod blob_store;
pub mod cache;
pub mod client;
pub mod content_discovery;
pub mod data_store;
mod error;
pub mod manifest;
pub mod metadata_store;
mod path_builder;
pub mod repository;
pub mod task_queue;
#[cfg(test)]
mod tests;
pub mod upload;
mod version;

use crate::configuration;
use crate::configuration::{GlobalConfig, RepositoryConfig};
use crate::registry::cache::Cache;
pub use repository::Repository;

use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::MetadataStore;
pub use crate::registry::task_queue::TaskQueue;
pub use error::Error;
pub use manifest::parse_manifest_digests;

static NAMESPACE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$").unwrap()
});

pub struct Registry {
    blob_store: Arc<dyn BlobStore + Send + Sync>,
    metadata_store: Arc<dyn MetadataStore + Send + Sync>,
    repositories: Arc<HashMap<String, Repository>>,
    update_pull_time: bool,
    task_queue: TaskQueue,
}

impl Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry").finish()
    }
}

impl Registry {
    #[instrument(skip(repositories_config, blob_store, metadata_store, auth_token_cache))]
    pub fn new(
        blob_store: Arc<dyn BlobStore + Send + Sync>,
        metadata_store: Arc<dyn MetadataStore + Send + Sync>,
        repositories_config: HashMap<String, RepositoryConfig>,
        global_config: &GlobalConfig,
        auth_token_cache: &cache::CacheStoreConfig,
    ) -> Result<Self, configuration::Error> {
        let auth_token_cache_arc: Arc<dyn Cache> =
            if let cache::CacheStoreConfig::Redis(ref redis_config) = auth_token_cache {
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

        let res = Self {
            update_pull_time: global_config.update_pull_time,
            blob_store,
            metadata_store,
            repositories: Arc::new(repositories),
            task_queue: TaskQueue::new(global_config.max_concurrent_cache_jobs)?,
        };

        Ok(res)
    }

    pub fn get_repository(&self, name: &str) -> Result<&Repository, Error> {
        self.repositories
            .get(name)
            .ok_or_else(|| Error::Internal(format!("Repository '{name}' not found")))
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
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::registry::metadata_store::link_kind::LinkKind;
    use crate::oci::Digest;
    use crate::registry::repository::access_policy::RepositoryAccessPolicyConfig;
    use crate::registry::repository::retention_policy::RepositoryRetentionPolicyConfig;

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
        let token_cache = cache::CacheStoreConfig::default();

        Registry::new(
            blob_store,
            metadata_store,
            repositories_config,
            &global,
            &token_cache,
        )
        .unwrap()
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
}
