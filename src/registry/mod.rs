use chrono::{Duration, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, LazyLock};
use tracing::instrument;

pub mod api;
mod blob;
pub mod blob_store;
pub mod cache_store;
mod content_discovery;
mod error;
mod http_client;
pub mod lock_store;
mod manifest;
pub mod metadata_store;
pub mod oci_types;
mod policy;
pub mod policy_types;
mod reader;
mod repository;
mod scrub;
#[cfg(test)]
mod tests;
mod upload;
pub mod utils;

use crate::configuration;
use crate::configuration::{CacheStoreConfig, GlobalConfig, LockStoreConfig, RepositoryConfig};
use crate::registry::cache_store::CacheStore;
pub use repository::Repository;

use crate::registry::blob_store::{BlobStore, LinkMetadata};
use crate::registry::lock_store::LockStore;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::oci_types::Digest;
pub use crate::registry::utils::{BlobLink, TaskQueue};
pub use error::Error;
pub use manifest::parse_manifest_digests;
pub use upload::StartUploadResponse;

static NAMESPACE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$").unwrap()
});

pub struct Registry<B, M> {
    blob_store: Arc<B>,
    metadata_store: Arc<M>,
    lock_store: LockStore,
    auth_token_cache: CacheStore,
    repositories: HashMap<String, Repository>,
    update_pull_time: bool,
    scrub_dry_run: bool,
    upload_timeout: Duration,
    task_queue: TaskQueue,
}

impl<B, M> Debug for Registry<B, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry").finish()
    }
}

impl<B, M> Registry<B, M>
where
    B: BlobStore,
    M: MetadataStore,
{
    #[instrument(skip(repositories_config, blob_store, metadata_store, auth_token_cache))]
    pub fn new(
        blob_store: Arc<B>,
        metadata_store: Arc<M>,
        repositories_config: HashMap<String, RepositoryConfig>,
        global_config: &GlobalConfig,
        auth_token_cache: CacheStoreConfig,
        lock_store: LockStoreConfig,
    ) -> Result<Self, configuration::Error> {
        let lock_store = LockStore::new(lock_store)?;
        let auth_token_cache = CacheStore::new(auth_token_cache)?;

        let mut repositories = HashMap::new();
        for (repository_name, repository_config) in repositories_config {
            let res = Repository::new(repository_config, repository_name.clone())?;
            repositories.insert(repository_name, res);
        }

        let res = Self {
            update_pull_time: global_config.update_pull_time,
            blob_store,
            metadata_store,
            lock_store,
            auth_token_cache,
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

    // TODO: move this logic to metadata store layer
    async fn create_link(
        &self,
        namespace: &str,
        link: &BlobLink,
        digest: &Digest,
    ) -> Result<LinkMetadata, Error> {
        let _guard = self.lock_store.acquire_lock(link.to_string()).await?;
        let link_data = self.metadata_store.read_link(namespace, link).await;

        // overwriting an existing link!
        if let Ok(link_data) = link_data {
            if &link_data.target != digest {
                let _blob_guard = self
                    .lock_store
                    .acquire_lock(link_data.target.as_str())
                    .await?;

                self.metadata_store
                    .update_blob_index(namespace, &link_data.target, |index| {
                        index.remove(link);
                    })
                    .await?;

                let _blob_guard = self.lock_store.acquire_lock(digest.as_str()).await?;
                self.metadata_store
                    .update_blob_index(namespace, digest, |index| {
                        index.insert(link.clone());
                    })
                    .await?;
            }
        } else {
            let _blob_guard = self.lock_store.acquire_lock(digest.as_str()).await?;
            self.metadata_store
                .update_blob_index(namespace, digest, |index| {
                    index.insert(link.clone());
                })
                .await?;
        }

        let link_data = LinkMetadata {
            target: digest.clone(),
            created_at: Some(Utc::now()),
            accessed_at: None,
        };
        self.metadata_store
            .write_link(namespace, link, &link_data)
            .await?;
        Ok(link_data)
    }

    // TODO: move this logic to metadata store layer
    #[instrument(skip(self))]
    async fn read_link(&self, name: &str, link: &BlobLink) -> Result<LinkMetadata, Error> {
        let _guard = self.lock_store.acquire_lock(link.to_string()).await?;

        if self.update_pull_time {
            let mut link_data = self.metadata_store.read_link(name, link).await?;
            link_data.accessed_at = Some(Utc::now());

            self.metadata_store
                .write_link(name, link, &link_data)
                .await?;
            Ok(link_data)
        } else {
            Ok(self.metadata_store.read_link(name, link).await?)
        }
    }

    // TODO: move this logic to metadata store layer
    #[instrument(skip(self))]
    async fn delete_link(&self, namespace: &str, link: &BlobLink) -> Result<(), Error> {
        let _guard = self.lock_store.acquire_lock(link.to_string()).await?;
        let metadata = self.metadata_store.read_link(namespace, link).await;

        let digest = match metadata {
            Ok(link_data) => link_data.target,
            Err(blob_store::Error::ReferenceNotFound) => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        let _blob_guard = self.lock_store.acquire_lock(digest.as_str()).await?;

        self.metadata_store.delete_link(namespace, link).await?;
        self.metadata_store
            .update_blob_index(namespace, &digest, |index| {
                index.remove(link);
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::configuration::{RepositoryAccessPolicyConfig, RepositoryRetentionPolicyConfig};
    use crate::registry::oci_types::Digest;
    use crate::registry::utils::BlobLink;
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

    pub async fn create_test_blob<B: BlobStore, M: MetadataStore>(
        registry: &Registry<B, M>,
        namespace: &str,
        content: &[u8],
    ) -> (Digest, Repository) {
        // Create a test blob
        let digest = registry.blob_store.create_blob(content).await.unwrap();

        // Create a tag to ensure the namespace exists
        let tag_link = BlobLink::Tag("latest".to_string());
        registry
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
