use crate::registry::metadata_store;
use crate::registry::metadata_store::{Error, MetadataStore};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum MetadataStoreConfig {
    #[serde(rename = "fs")]
    FS(metadata_store::fs::BackendConfig),
    #[serde(rename = "s3")]
    S3(metadata_store::s3::BackendConfig),
}

impl MetadataStoreConfig {
    pub fn to_backend(&self) -> Result<std::sync::Arc<dyn MetadataStore + Send + Sync>, Error> {
        match self {
            MetadataStoreConfig::FS(config) => Ok(std::sync::Arc::new(
                metadata_store::fs::Backend::new(config)?,
            )),
            MetadataStoreConfig::S3(config) => Ok(std::sync::Arc::new(
                metadata_store::s3::Backend::new(config)?,
            )),
        }
    }
}
