use chrono::Duration;
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
mod repository;
mod scrub;
mod upload;
mod utils;

use crate::configuration;
use crate::configuration::RepositoryConfig;
use crate::registry::cache_store::CacheStore;
pub use repository::Repository;

use crate::registry::data_store::DataStore;
pub use error::Error;
pub use manifest::parse_manifest_digests;
pub use upload::StartUploadResponse;

static NAMESPACE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$").unwrap()
});

pub struct Registry<D> {
    storage_engine: Arc<D>,
    repositories: HashMap<String, Repository>,
    scrub_dry_run: bool,
    scrub_upload_timeout: Duration,
}

impl<D> Debug for Registry<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry").finish()
    }
}

impl<D: DataStore> Registry<D> {
    #[instrument(skip(repositories_config, storage_engine, token_cache))]
    pub fn new(
        repositories_config: HashMap<String, RepositoryConfig>,
        storage_engine: Arc<D>,
        token_cache: Arc<CacheStore>,
    ) -> Result<Self, configuration::Error> {
        let mut repositories = HashMap::new();
        for (repository_name, repository_config) in repositories_config {
            let res = Repository::new(repository_config, repository_name.clone(), &token_cache)?;
            repositories.insert(repository_name, res);
        }

        let res = Self {
            storage_engine,
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
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use crate::configuration::{
        CacheStoreConfig, DataSize, LockStoreConfig, RepositoryAccessPolicyConfig,
        RepositoryRetentionPolicyConfig, StorageFSConfig, StorageS3Config,
    };
    use crate::registry::data_store::{FSBackend, S3Backend};
    use crate::registry::oci_types::Digest;
    use crate::registry::utils::DataLink;
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
        let lock_store = lock_store::LockStore::new(LockStoreConfig::default()).unwrap();
        let backend = FSBackend::new(config, lock_store);
        let backend = Arc::new(backend);

        let repositories_config = create_test_repository_config();
        let token_cache = Arc::new(CacheStore::new(CacheStoreConfig::default()).unwrap());

        let registry = Registry::new(repositories_config, backend, token_cache).unwrap();

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
            multipart_copy_threshold: DataSize::WithUnit(100, "MB".to_string()),
            multipart_copy_chunk_size: DataSize::WithUnit(10, "MB".to_string()),
            multipart_copy_jobs: 4,
            multipart_part_size: DataSize::WithUnit(5, "MB".to_string()),
        };

        let lock_store = lock_store::LockStore::new(LockStoreConfig::default()).unwrap();
        let backend = S3Backend::new(config, lock_store);
        let backend = Arc::new(backend);

        let repositories_config = create_test_repository_config();
        let token_cache = Arc::new(CacheStore::new(CacheStoreConfig::default()).unwrap());

        Registry::new(repositories_config, backend, token_cache).unwrap()
    }

    pub async fn create_test_blob<D: DataStore>(
        registry: &Registry<D>,
        namespace: &str,
        content: &[u8],
    ) -> (Digest, Repository) {
        // Create a test blob
        let digest = registry.storage_engine.create_blob(content).await.unwrap();

        // Create a tag to ensure the namespace exists
        let tag_link = DataLink::Tag("latest".to_string());
        registry
            .storage_engine
            .create_link(namespace, &tag_link, &digest)
            .await
            .unwrap();

        // Verify the blob index is updated
        let blob_index = registry
            .storage_engine
            .read_blob_index(&digest)
            .await
            .unwrap();
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
