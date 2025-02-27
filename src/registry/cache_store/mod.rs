use std::fmt::Debug;

mod error;
mod memory_backend;
mod redis_backend;

pub use error::Error;

use crate::configuration::CacheStoreConfig;
use memory_backend::MemoryBackend;
use redis_backend::RedisBackend;

#[derive(Debug)]
enum Backend {
    Memory(MemoryBackend),
    Redis(RedisBackend),
}

/// A cache store that can store and retrieve values with a given ttl
/// The underlying implementation can be either in-memory or backed by a Redis-compatible backend
#[derive(Debug)]
pub struct CacheStore {
    backend: Backend,
}

impl CacheStore {
    /// Create a new cache store
    ///
    /// The implementation of the cache store is determined by the configuration.
    ///
    /// # Arguments
    ///
    /// * `cache_config` - The configuration for the cache store
    ///
    /// # Returns
    ///
    /// * `Ok(CacheStore)` if the cache store was created successfully
    ///
    /// # Errors
    ///
    /// * `Error::StorageError` if the cache store could not be created
    pub fn new(config: CacheStoreConfig) -> Result<Self, Error> {
        let backend = match config.redis {
            Some(config) => Backend::Redis(RedisBackend::new(&config.url, config.key_prefix)?),
            None => Backend::Memory(MemoryBackend::new()),
        };
        Ok(CacheStore { backend })
    }

    /// Store a value with a given ttl in the cache
    ///
    /// # Arguments
    ///
    /// * `key` - The key to store the value under
    /// * `value` - The value to store
    /// * `expires_in` - The time in seconds until the value expires
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the value was stored successfully
    /// * `Err(Error)` if the value could not be stored
    ///
    /// # Errors
    ///
    /// * `Error::StorageError` if the value could not be stored for some reason
    pub async fn store(&self, key: &str, value: &str, expires_in: u64) -> Result<(), Error> {
        match &self.backend {
            Backend::Memory(cache) => cache.store(key, value, expires_in).await,
            Backend::Redis(cache) => cache.store(key, value, expires_in).await,
        }
    }

    /// Retrieve a value from the cache
    ///
    /// # Arguments
    ///
    /// * `key` - The key to retrieve the value for
    ///
    /// # Returns
    ///
    /// * `Ok(String)` if the value was found in the cache
    /// * `Err(Error)` if the value was not found in the cache or could not be retrieved
    ///
    /// # Errors
    ///
    /// * `Error::StorageError` if the value could not be retrieved for some reason
    /// * `Error::NotFound` if the value was not found in the cache
    pub async fn retrieve(&self, key: &str) -> Result<String, Error> {
        match &self.backend {
            Backend::Memory(cache) => cache.retrieve(key).await,
            Backend::Redis(cache) => cache.retrieve(key).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration;
    use crate::configuration::CacheStoreConfig;

    #[tokio::test]
    async fn test_new_cache() {
        let config = CacheStoreConfig::default();
        let cache = CacheStore::new(config).expect("Failed to create cache");

        let Backend::Memory(_) = cache.backend else {
            assert!(false);
            return;
        };

        let config = CacheStoreConfig {
            redis: Some(configuration::RedisCacheConfig {
                url: "redis://localhost:6379".to_string(),
                key_prefix: "test_new_cache".to_owned(),
            }),
        };
        let cache = CacheStore::new(config).unwrap();

        let Backend::Redis(_) = cache.backend else {
            assert!(false);
            return;
        };
    }
}
