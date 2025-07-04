use chrono::{Duration, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, LazyLock};
use tracing::instrument;

pub mod api;
mod blob;
pub mod cache_store;
mod content_discovery;
pub mod data_store;
mod error;
mod http_client;
pub mod lock_store;
mod manifest;
pub mod oci_types;
mod policy;
pub mod policy_types;
mod reader;
mod repository;
mod scrub;
mod upload;
mod utils;

use crate::configuration;
use crate::configuration::RepositoryConfig;
use crate::registry::cache_store::CacheStore;
pub use repository::Repository;

use crate::registry::data_store::{DataStore, LinkMetadata};
use crate::registry::lock_store::LockStore;
use crate::registry::oci_types::Digest;
use crate::registry::utils::BlobLink;
pub use error::Error;
pub use manifest::parse_manifest_digests;
pub use upload::StartUploadResponse;

static NAMESPACE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$").unwrap()
});

pub struct Registry<D> {
    store: Arc<D>,
    lock_store: Arc<LockStore>,
    repositories: HashMap<String, Repository>,
    update_pull_time: bool,
    scrub_dry_run: bool,
    scrub_upload_timeout: Duration,
}

impl<D> Debug for Registry<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry").finish()
    }
}

impl<D: DataStore> Registry<D> {
    #[instrument(skip(repositories_config, storage_engine, cache_store, lock_store))]
    pub fn new(
        repositories_config: HashMap<String, RepositoryConfig>,
        storage_engine: Arc<D>,
        cache_store: Arc<CacheStore>,
        lock_store: Arc<LockStore>,
    ) -> Result<Self, configuration::Error> {
        let mut repositories = HashMap::new();
        for (repository_name, repository_config) in repositories_config {
            let res = Repository::new(repository_config, repository_name.clone(), &cache_store)?;
            repositories.insert(repository_name, res);
        }

        let res = Self {
            update_pull_time: false, // TODO: expose configuration option
            store: storage_engine,
            lock_store,
            repositories,
            scrub_dry_run: true,
            scrub_upload_timeout: Duration::days(1),
        };

        Ok(res)
    }

    pub fn with_dry_run(mut self, scrub_dry_run: bool) -> Self {
        self.scrub_dry_run = scrub_dry_run;
        self
    }

    pub fn with_upload_timeout(mut self, scrub_upload_timeout: Duration) -> Self {
        self.scrub_upload_timeout = scrub_upload_timeout;
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

    async fn create_link(
        &self,
        namespace: &str,
        link: &BlobLink,
        digest: &Digest,
    ) -> Result<LinkMetadata, Error> {
        let _guard = self.lock_store.acquire_lock(link.to_string()).await?;
        let link_data = self.store.read_link(namespace, link).await;

        // overwriting an existing link!
        if let Ok(link_data) = link_data {
            if &link_data.target != digest {
                let _blob_guard = self
                    .lock_store
                    .acquire_lock(link_data.target.as_str())
                    .await?;

                self.store
                    .update_blob_index(namespace, &link_data.target, |index| {
                        index.remove(link);
                    })
                    .await?;

                let _blob_guard = self.lock_store.acquire_lock(digest.as_str()).await?;
                self.store
                    .update_blob_index(namespace, digest, |index| {
                        index.insert(link.clone());
                    })
                    .await?;
            }
        } else {
            let _blob_guard = self.lock_store.acquire_lock(digest.as_str()).await?;
            self.store
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
        self.store.write_link(namespace, link, &link_data).await?;
        Ok(link_data)
    }

    #[instrument(skip(self))]
    async fn read_link(&self, name: &str, link: &BlobLink) -> Result<LinkMetadata, Error> {
        let _guard = self.lock_store.acquire_lock(link.to_string()).await?;

        if self.update_pull_time {
            let mut link_data = self.store.read_link(name, link).await?;
            link_data.accessed_at = Some(Utc::now());

            self.store.write_link(name, link, &link_data).await?;
            Ok(link_data)
        } else {
            Ok(self.store.read_link(name, link).await?)
        }
    }

    #[instrument(skip(self))]
    async fn delete_link(&self, namespace: &str, link: &BlobLink) -> Result<(), Error> {
        let _guard = self.lock_store.acquire_lock(link.to_string()).await?;
        let metadata = self.store.read_link(namespace, link).await;

        let digest = match metadata {
            Ok(link_data) => link_data.target,
            Err(data_store::Error::ReferenceNotFound) => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        let _blob_guard = self.lock_store.acquire_lock(digest.as_str()).await?;

        self.store.delete_link(namespace, link).await?;
        self.store
            .update_blob_index(namespace, &digest, |index| {
                index.remove(link);
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use crate::configuration::{
        CacheStoreConfig, LockStoreConfig, RepositoryAccessPolicyConfig,
        RepositoryRetentionPolicyConfig, StorageFSConfig, StorageS3Config,
    };
    use crate::registry::data_store::{FSBackend, S3Backend};
    use crate::registry::oci_types::Digest;
    use crate::registry::utils::BlobLink;
    use bytesize::ByteSize;
    use serde_json::json;
    use tempfile::TempDir;
    use uuid::Uuid;

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

    pub async fn create_test_fs_backend() -> (Registry<FSBackend>, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let root_dir = temp_dir.path().to_str().unwrap().to_string();

        let config = StorageFSConfig { root_dir };
        let backend = Arc::new(FSBackend::new(config));

        let repositories_config = create_test_repository_config();
        let token_cache = Arc::new(CacheStore::new(CacheStoreConfig::default()).unwrap());
        let lock_store = Arc::new(LockStore::new(LockStoreConfig::default()).unwrap());

        let registry =
            Registry::new(repositories_config, backend, token_cache, lock_store).unwrap();

        (registry, temp_dir)
    }

    pub async fn create_test_s3_backend() -> Registry<S3Backend> {
        let config = StorageS3Config {
            endpoint: "http://127.0.0.1:9000".to_string(),
            region: "region".to_string(),
            bucket: "registry".to_string(),
            access_key_id: "root".to_string(),
            secret_key: "roottoor".to_string(),
            key_prefix: Some(format!("test-{}", Uuid::new_v4())),
            multipart_copy_threshold: ByteSize::mb(100),
            multipart_copy_chunk_size: ByteSize::mb(10),
            multipart_copy_jobs: 4,
            multipart_part_size: ByteSize::mb(5),
        };

        let lock_store = Arc::new(LockStore::new(LockStoreConfig::default()).unwrap());
        let backend = Arc::new(S3Backend::new(config));

        let repositories_config = create_test_repository_config();
        let token_cache = Arc::new(CacheStore::new(CacheStoreConfig::default()).unwrap());

        Registry::new(repositories_config, backend, token_cache, lock_store).unwrap()
    }

    pub async fn create_test_blob<D: DataStore>(
        registry: &Registry<D>,
        namespace: &str,
        content: &[u8],
    ) -> (Digest, Repository) {
        // Create a test blob
        let digest = registry.store.create_blob(content).await.unwrap();

        // Create a tag to ensure the namespace exists
        let tag_link = BlobLink::Tag("latest".to_string());
        registry
            .create_link(namespace, &tag_link, &digest)
            .await
            .unwrap();

        // Verify the blob index is updated
        let blob_index = registry.store.read_blob_index(&digest).await.unwrap();
        assert!(blob_index.namespace.contains_key(namespace));
        let namespace_links = blob_index.namespace.get(namespace).unwrap();
        assert!(namespace_links.contains(&tag_link));

        // Create a non-pull-through repository
        let token_cache = Arc::new(CacheStore::new(CacheStoreConfig::default()).unwrap());
        let repository = Repository::new(
            RepositoryConfig {
                upstream: Vec::new(),
                access_policy: RepositoryAccessPolicyConfig::default(),
                retention_policy: RepositoryRetentionPolicyConfig { rules: Vec::new() },
            },
            "test-repo".to_string(),
            &token_cache,
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
