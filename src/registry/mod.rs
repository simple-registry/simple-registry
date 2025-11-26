use regex::Regex;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, LazyLock};
use tracing::instrument;

mod access_policy;
pub mod blob;
pub mod blob_store;
pub mod content_discovery;
pub mod data_store;
mod error;
pub mod manifest;
pub mod metadata_store;
pub mod pagination;
mod path_builder;
pub mod repository;
mod retention_policy;
pub mod task_queue;
#[cfg(test)]
pub mod tests;
pub mod upload;
mod version;

use crate::cache;

pub use repository::Repository;

use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::task_queue::TaskQueue;
pub use access_policy::{AccessPolicy, AccessPolicyConfig};
pub use error::Error;
pub use manifest::parse_manifest_digests;
pub use retention_policy::{ManifestImage, RetentionPolicy, RetentionPolicyConfig};

static NAMESPACE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$").unwrap()
});

pub struct Registry {
    blob_store: Arc<dyn BlobStore + Send + Sync>,
    metadata_store: Arc<dyn MetadataStore + Send + Sync>,
    repositories: Arc<HashMap<String, Repository>>,
    enable_redirect: bool,
    update_pull_time: bool,
    task_queue: TaskQueue,
}

impl Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry").finish()
    }
}

impl Registry {
    #[instrument(skip(blob_store, metadata_store, repositories))]
    pub fn new(
        blob_store: Arc<dyn BlobStore>,
        metadata_store: Arc<dyn MetadataStore>,
        repositories: Arc<HashMap<String, Repository>>,
        update_pull_time: bool,
        enable_redirect: bool,
        concurrent_cache_jobs: usize,
    ) -> Result<Self, Error> {
        let res = Self {
            update_pull_time,
            enable_redirect,
            blob_store,
            metadata_store,
            repositories,
            task_queue: TaskQueue::new(concurrent_cache_jobs, "cache-worker")?,
        };

        Ok(res)
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
    use crate::configuration::GlobalConfig;
    use crate::oci::Digest;
    use crate::registry::access_policy::AccessPolicyConfig;
    use crate::registry::metadata_store::link_kind::LinkKind;
    use crate::registry::retention_policy::RetentionPolicyConfig;

    pub fn create_test_repositories() -> Arc<HashMap<String, Repository>> {
        let token_cache = cache::Config::default().to_backend().unwrap();

        let config = repository::Config {
            access_policy: AccessPolicyConfig {
                default_allow: true,
                ..AccessPolicyConfig::default()
            },
            retention_policy: RetentionPolicyConfig::default(),
            ..repository::Config::default()
        };

        let mut repositories = HashMap::new();
        repositories.insert(
            "test-repo".to_string(),
            Repository::new("test-repo", &config, &token_cache).unwrap(),
        );

        Arc::new(repositories)
    }

    pub fn create_test_registry(
        blob_store: Arc<dyn BlobStore + Send + Sync>,
        metadata_store: Arc<dyn MetadataStore + Send + Sync>,
    ) -> Registry {
        let repositories_config = create_test_repositories();
        let global = GlobalConfig::default();

        Registry::new(
            blob_store,
            metadata_store,
            repositories_config,
            global.update_pull_time,
            global.enable_redirect,
            global.max_concurrent_cache_jobs,
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
        let cache = cache::Config::Memory.to_backend().unwrap();
        let repository = Repository::new(
            "test-repo",
            &repository::Config {
                upstream: Vec::new(),
                access_policy: AccessPolicyConfig::default(),
                retention_policy: RetentionPolicyConfig { rules: Vec::new() },
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
