use crate::configuration::{CacheStoreConfig, GlobalConfig, LockStoreConfig, RepositoryConfig};
use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::test_utils::create_test_repository_config;
use crate::registry::{blob_store, Registry, Repository};
use bytesize::ByteSize;
use chrono::Duration;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use uuid::Uuid;

pub struct FSBlobStoreBackendTestCase {
    fs_backend: blob_store::fs::Backend,
    pub temp_dir: TempDir,
}

impl FSBlobStoreBackendTestCase {
    pub fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir for FSBackendConfig");

        let path = temp_dir.path().to_string_lossy().to_string();
        let fs_backend =
            blob_store::fs::Backend::new(blob_store::fs::BackendConfig { root_dir: path });

        FSBlobStoreBackendTestCase {
            fs_backend,
            temp_dir,
        }
    }

    pub fn path(&self) -> &Path {
        self.temp_dir.path()
    }

    pub fn backend(&self) -> &blob_store::fs::Backend {
        &self.fs_backend
    }
}

pub struct FSMetadataStoreBackendTestCase {
    fs_backend: metadata_store::fs::Backend,
    _temp_dir: TempDir,
}

impl FSMetadataStoreBackendTestCase {
    pub fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir for FSBackendConfig");

        let path = temp_dir.path().to_string_lossy().to_string();
        let fs_backend =
            metadata_store::fs::Backend::new(metadata_store::fs::BackendConfig { root_dir: path });

        FSMetadataStoreBackendTestCase {
            fs_backend,
            _temp_dir: temp_dir,
        }
    }

    pub fn backend(&self) -> &metadata_store::fs::Backend {
        &self.fs_backend
    }
}

pub struct FSRegistryTestCase {
    fs_blob_store: Arc<blob_store::fs::Backend>,
    fs_metadata_store: Arc<metadata_store::fs::Backend>,
    fs_registry: Registry<blob_store::fs::Backend, metadata_store::fs::Backend>,
    _temp_dir: TempDir,
}

impl FSRegistryTestCase {
    pub fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir for FSBackendConfig");
        let path = temp_dir.path().to_string_lossy().to_string();

        let fs_blob_store = blob_store::fs::Backend::new(blob_store::fs::BackendConfig {
            root_dir: path.clone(),
        });
        let fs_blob_store = Arc::new(fs_blob_store);

        let fs_metadata_store =
            metadata_store::fs::Backend::new(metadata_store::fs::BackendConfig { root_dir: path });
        let fs_metadata_store = Arc::new(fs_metadata_store);

        let repositories_config = create_test_repository_config();
        let global = GlobalConfig::default();
        let token_cache = CacheStoreConfig::default();
        let lock_store = LockStoreConfig::default();

        let registry = Registry::new(
            fs_blob_store.clone(),
            fs_metadata_store.clone(),
            repositories_config,
            &global,
            token_cache,
            lock_store,
        )
        .unwrap()
        .with_upload_timeout(Duration::seconds(0))
        .with_scrub_dry_run(false);

        Self {
            fs_blob_store,
            fs_metadata_store,
            fs_registry: registry,
            _temp_dir: temp_dir,
        }
    }

    pub fn registry(&self) -> &Registry<blob_store::fs::Backend, metadata_store::fs::Backend> {
        &self.fs_registry
    }

    pub fn registry_mut(
        &mut self,
    ) -> &mut Registry<blob_store::fs::Backend, metadata_store::fs::Backend> {
        &mut self.fs_registry
    }

    pub fn set_repository_config(
        &mut self,
        repositories_config: HashMap<String, RepositoryConfig>,
    ) {
        prepare_with_repository_config(&mut self.fs_registry, repositories_config)
    }

    pub fn blob_store(&self) -> &blob_store::fs::Backend {
        &self.fs_blob_store
    }

    pub fn metadata_store(&self) -> &metadata_store::fs::Backend {
        &self.fs_metadata_store
    }
}

pub struct S3BlobStoreBackendTestCase {
    key_prefix: String,
    s3_backend: blob_store::s3::Backend,
}

impl S3BlobStoreBackendTestCase {
    pub fn new() -> Self {
        let key_prefix = format!("test-{}", Uuid::new_v4());
        let s3_backend = blob_store::s3::Backend::new(blob_store::s3::BackendConfig {
            access_key_id: "root".to_string(),
            secret_key: "roottoor".to_string(),
            endpoint: "http://127.0.0.1:9000".to_string(),
            region: "region".to_string(),
            bucket: "registry".to_string(),
            key_prefix: key_prefix.clone(),
            multipart_copy_threshold: ByteSize::mb(5),
            multipart_copy_chunk_size: ByteSize::mb(5),
            multipart_copy_jobs: 4,
            multipart_part_size: ByteSize::mb(5),
        });

        Self {
            key_prefix,
            s3_backend,
        }
    }

    pub fn backend(&self) -> &blob_store::s3::Backend {
        &self.s3_backend
    }
}

impl Drop for S3BlobStoreBackendTestCase {
    fn drop(&mut self) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let key_prefix = self.key_prefix.clone();
            let backend = self.s3_backend.clone();
            handle.spawn(async move {
                if let Err(e) = backend.delete_object_with_prefix(&key_prefix).await {
                    println!("Warning: Failed to clean up S3BlobStoreBackendTestCase data: {e:?}");
                }
            });
        }
    }
}

pub struct S3MetadataStoreBackendTestCase {
    key_prefix: String,
    s3_backend: metadata_store::s3::Backend,
}

impl S3MetadataStoreBackendTestCase {
    pub fn new() -> Self {
        let key_prefix = format!("test-{}", Uuid::new_v4());

        let s3_backend = metadata_store::s3::Backend::new(metadata_store::s3::BackendConfig {
            access_key_id: "root".to_string(),
            secret_key: "roottoor".to_string(),
            endpoint: "http://127.0.0.1:9000".to_string(),
            region: "region".to_string(),
            bucket: "registry".to_string(),
            key_prefix: key_prefix.clone(),
        });

        Self {
            key_prefix,
            s3_backend,
        }
    }

    pub fn backend(&self) -> &metadata_store::s3::Backend {
        &self.s3_backend
    }
}

impl Drop for S3MetadataStoreBackendTestCase {
    fn drop(&mut self) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let key_prefix = self.key_prefix.clone();
            let backend = self.s3_backend.clone();
            handle.spawn(async move {
                if let Err(e) = backend.delete_object_with_prefix(&key_prefix).await {
                    println!(
                        "Warning: Failed to clean up S3MetadataStoreBackendTestCase data: {e:?}"
                    );
                }
            });
        }
    }
}

pub struct S3RegistryTestCase {
    key_prefix: String,
    s3_blob_store: Arc<blob_store::s3::Backend>,
    s3_metadata_store: Arc<metadata_store::s3::Backend>,
    s3_registry: Registry<blob_store::s3::Backend, metadata_store::s3::Backend>,
}

impl S3RegistryTestCase {
    pub fn new() -> Self {
        let key_prefix = format!("test-{}", Uuid::new_v4());

        let blob_store = blob_store::s3::Backend::new(blob_store::s3::BackendConfig {
            access_key_id: "root".to_string(),
            secret_key: "roottoor".to_string(),
            endpoint: "http://127.0.0.1:9000".to_string(),
            region: "region".to_string(),
            bucket: "registry".to_string(),
            key_prefix: key_prefix.clone(),
            multipart_copy_threshold: ByteSize::mb(5),
            multipart_copy_chunk_size: ByteSize::mb(5),
            multipart_copy_jobs: 4,
            multipart_part_size: ByteSize::mb(5),
        });
        let blob_store = Arc::new(blob_store);

        let metadata_store = metadata_store::s3::Backend::new(metadata_store::s3::BackendConfig {
            access_key_id: "root".to_string(),
            secret_key: "roottoor".to_string(),
            endpoint: "http://127.0.0.1:9000".to_string(),
            region: "region".to_string(),
            bucket: "registry".to_string(),
            key_prefix: key_prefix.clone(),
        });
        let metadata_store = Arc::new(metadata_store);

        let repositories_config = create_test_repository_config();
        let global = GlobalConfig::default();
        let token_cache = CacheStoreConfig::default();
        let lock_store = LockStoreConfig::default();

        let registry = Registry::new(
            blob_store.clone(),
            metadata_store.clone(),
            repositories_config,
            &global,
            token_cache,
            lock_store,
        )
        .unwrap()
        .with_upload_timeout(Duration::seconds(0))
        .with_scrub_dry_run(false);

        Self {
            key_prefix,
            s3_blob_store: blob_store,
            s3_metadata_store: metadata_store,
            s3_registry: registry,
        }
    }

    pub fn set_repository_config(
        &mut self,
        repositories_config: HashMap<String, RepositoryConfig>,
    ) {
        prepare_with_repository_config(&mut self.s3_registry, repositories_config)
    }

    pub fn registry(&self) -> &Registry<blob_store::s3::Backend, metadata_store::s3::Backend> {
        &self.s3_registry
    }

    pub fn blob_store(&self) -> &blob_store::s3::Backend {
        &self.s3_blob_store
    }

    pub fn metadata_store(&self) -> &metadata_store::s3::Backend {
        &self.s3_metadata_store
    }
}

impl Drop for S3RegistryTestCase {
    fn drop(&mut self) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let key_prefix = self.key_prefix.clone();
            let blob_store = self.s3_blob_store.clone();
            handle.spawn(async move {
                if let Err(e) = blob_store.delete_object_with_prefix(&key_prefix).await {
                    println!("Warning: Failed to clean up S3RegistryTestCase data: {e:?}");
                }
            });
        }
    }
}

fn prepare_with_repository_config<B: BlobStore, M: MetadataStore>(
    registry: &mut Registry<B, M>,
    repositories_config: HashMap<String, RepositoryConfig>,
) {
    let mut repositories = HashMap::new();
    for (repository_name, repository_config) in repositories_config {
        let res = Repository::new(repository_config, repository_name.clone()).unwrap();
        repositories.insert(repository_name, res);
    }

    registry.repositories = repositories;
}
