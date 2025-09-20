use crate::configuration::{BlobStorageConfig, Configuration, Error, MetadataStoreConfig};
use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::{blob_store, metadata_store, Registry};
use std::sync::Arc;

pub fn create_blob_store(config: &BlobStorageConfig) -> Arc<dyn BlobStore + Send + Sync> {
    match config {
        BlobStorageConfig::FS(fs_config) => {
            Arc::new(blob_store::fs::Backend::new(fs_config.clone()))
        }
        BlobStorageConfig::S3(s3_config) => {
            Arc::new(blob_store::s3::Backend::new(s3_config.clone()))
        }
    }
}

pub fn create_metadata_store(
    config: &MetadataStoreConfig,
) -> Result<Arc<dyn MetadataStore + Send + Sync>, crate::command::Error> {
    match config {
        MetadataStoreConfig::FS(fs_config) => Ok(Arc::new(
            metadata_store::fs::Backend::new(fs_config.clone())
                .map_err(crate::command::Error::Configuration)?,
        )),
        MetadataStoreConfig::S3(s3_config) => Ok(Arc::new(
            metadata_store::s3::Backend::new(s3_config.clone())
                .map_err(crate::command::Error::Configuration)?,
        )),
        MetadataStoreConfig::Unspecified => Err(crate::command::Error::Configuration(
            Error::ConfigurationFileFormat(
                "Metadata store configuration is unspecified".to_string(),
            ),
        )),
    }
}

pub fn create_registry(config: &Configuration) -> Result<Registry, crate::command::Error> {
    let blob_store = create_blob_store(&config.blob_store);
    let metadata_store = create_metadata_store(&config.metadata_store)?;

    Registry::new(
        blob_store,
        metadata_store,
        config.repository.clone(),
        &config.global,
        &config.cache,
    )
    .map_err(crate::command::Error::Configuration)
}
