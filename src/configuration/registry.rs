use crate::configuration::{GlobalConfig, RepositoryConfig};
use crate::registry::{blob_store, cache, metadata_store, Registry};
use std::collections::HashMap;
use tracing::info;

pub fn create_registry(
    registry_config: &GlobalConfig,
    blob_store_config: &blob_store::BlobStorageConfig,
    metadata_store_config: Option<metadata_store::MetadataStoreConfig>,
    repository_config: HashMap<String, RepositoryConfig>,
    cache_config: &cache::CacheStoreConfig,
) -> Result<Registry, crate::command::Error> {
    let metadata_store_config = match metadata_store_config {
        Some(config) => config,
        None => match &blob_store_config {
            blob_store::BlobStorageConfig::FS(config) => {
                metadata_store::MetadataStoreConfig::FS(metadata_store::fs::BackendConfig {
                    root_dir: config.root_dir.clone(),
                    redis: None,
                    sync_to_disk: config.sync_to_disk,
                })
            }
            blob_store::BlobStorageConfig::S3(config) => {
                info!("Auto-configuring S3 metadata-store from blob-store");
                metadata_store::MetadataStoreConfig::S3(metadata_store::s3::BackendConfig {
                    bucket: config.bucket.clone(),
                    region: config.region.clone(),
                    endpoint: config.endpoint.clone(),
                    access_key_id: config.access_key_id.clone(),
                    secret_key: config.secret_key.clone(),
                    key_prefix: config.key_prefix.clone(),
                    redis: None,
                })
            }
        },
    };

    let blob_store = blob_store_config.to_backend()?;
    let metadata_store = metadata_store_config.to_backend()?;

    Registry::new(
        blob_store,
        metadata_store,
        repository_config,
        registry_config,
        cache_config,
    )
    .map_err(crate::command::Error::Configuration)
}
