use crate::registry::cache;
use crate::registry::cache::{Cache, Error};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub enum CacheStoreConfig {
    #[default]
    #[serde(rename = "memory")]
    Memory,
    #[serde(rename = "redis")]
    Redis(cache::redis::BackendConfig),
}

impl CacheStoreConfig {
    pub fn to_backend(&self) -> Result<Arc<dyn Cache + Send + Sync>, Error> {
        match self {
            CacheStoreConfig::Redis(redis_config) => {
                Ok(Arc::new(cache::redis::Backend::new(redis_config.clone())?))
            }
            CacheStoreConfig::Memory => Ok(Arc::new(cache::memory::Backend::new())),
        }
    }
}
