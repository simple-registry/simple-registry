use crate::cache;
use crate::cache::{Cache, Error};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub enum Config {
    #[default]
    #[serde(rename = "memory")]
    Memory,
    #[serde(rename = "redis")]
    Redis(cache::redis::BackendConfig),
}

impl Config {
    pub fn to_backend(&self) -> Result<Arc<dyn Cache>, Error> {
        match self {
            Config::Redis(config) => Ok(Arc::new(cache::redis::Backend::new(config)?)),
            Config::Memory => Ok(Arc::new(cache::memory::Backend::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::redis::BackendConfig;
    use std::any::TypeId;

    #[tokio::test]
    async fn test_memory_backend() {
        let config = Config::Memory;
        let backend = config.to_backend();

        assert!(backend.is_ok());

        let backend = backend.unwrap();
        assert_eq!((*backend).type_id(), TypeId::of::<cache::memory::Backend>());
    }

    #[tokio::test]
    async fn test_redis_backend() {
        let config = Config::Redis(BackendConfig {
            url: "redis://localhost:6379/0".to_string(),
            key_prefix: "test_cache_config".to_string(),
        });
        let backend = config.to_backend();

        assert!(backend.is_ok());

        let backend = backend.unwrap();
        assert_eq!((*backend).type_id(), TypeId::of::<cache::redis::Backend>());
    }
}
