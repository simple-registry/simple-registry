use crate::registry::blob_store::{fs, s3, BlobStore, Error};
use crate::registry::data_store;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum BlobStorageConfig {
    #[serde(rename = "fs")]
    FS(data_store::fs::BackendConfig),
    #[serde(rename = "s3")]
    S3(data_store::s3::BackendConfig),
}

impl Default for BlobStorageConfig {
    fn default() -> Self {
        BlobStorageConfig::FS(data_store::fs::BackendConfig::default())
    }
}

impl BlobStorageConfig {
    pub fn to_backend(&self) -> Result<Arc<dyn BlobStore>, Error> {
        match self {
            BlobStorageConfig::FS(config) => Ok(Arc::new(fs::Backend::new(config))),
            BlobStorageConfig::S3(config) => Ok(Arc::new(s3::Backend::new(config)?)),
        }
    }
}
