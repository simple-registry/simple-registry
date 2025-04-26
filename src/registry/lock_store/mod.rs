use crate::configuration::LockStoreConfig;
use std::fmt::Debug;
use tracing::{debug, instrument};

mod error;
mod memory_backend;
mod redis_backend;

pub use error::Error;
use memory_backend::{MemoryBackend, MemoryLockGuard};
use redis_backend::{RedisBackend, RedisLockGuard};

#[derive(Debug)]
enum Backend {
    Redis(RedisBackend),
    Memory(MemoryBackend),
}

pub enum WriteLockGuard {
    Redis(RedisLockGuard),
    Memory(MemoryLockGuard),
}

/// A lock store that can acquire exclusive locks for a given key
/// The underlying implementation can be either in-memory or backed by a Redis-compatible backend
#[derive(Debug)]
pub struct LockStore {
    backend: Backend,
}

impl LockStore {
    /// Create a new lock store
    ///
    /// The implementation of the lock store is determined by the configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the lock store
    ///
    /// # Returns
    ///
    /// * `Ok(LockStore)` if the lock store was created successfully
    ///
    /// # Errors
    ///
    /// * `Error::BackendError` if the lock store could not be created
    pub fn new(config: LockStoreConfig) -> Result<Self, Error> {
        let backend = match config.redis {
            Some(config) => Backend::Redis(RedisBackend::new(
                &config.url,
                config.ttl,
                config.key_prefix,
            )?),
            None => Backend::Memory(MemoryBackend::new()),
        };

        Ok(LockStore { backend })
    }

    /// Acquire an exclusive lock for a given key.
    /// This will block until the lock is acquired.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to acquire the lock for
    ///
    /// # Returns
    ///
    /// * `Ok(WriteLockGuard)` if the lock was acquired successfully
    ///
    /// # Errors
    ///
    /// * `Error::BackendError` if the lock could not be acquired
    #[instrument(skip(self))]
    pub async fn acquire_write_lock<S>(&self, key: S) -> Result<WriteLockGuard, Error>
    where
        S: AsRef<str> + Debug,
    {
        match &self.backend {
            Backend::Redis(lock) => {
                let guard = lock
                    .acquire_lock(key.as_ref())
                    .await
                    .map(WriteLockGuard::Redis)?;
                if let WriteLockGuard::Redis(_redis_guard) = &guard {
                    debug!("Acquired write lock for key");
                }

                Ok(guard)
            }
            Backend::Memory(lock) => {
                let guard = WriteLockGuard::Memory(lock.acquire_lock(key.as_ref()).await);
                if let WriteLockGuard::Memory(_in_memory_guard) = &guard {
                    debug!("Acquired write lock for key");
                }

                Ok(guard)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration;
    use crate::configuration::LockStoreConfig;

    #[tokio::test]
    async fn test_new_lock_store() {
        let config = LockStoreConfig::default();
        let lock_store = LockStore::new(config).expect("Failed to create lock store");

        let Backend::Memory(_) = lock_store.backend else {
            panic!("Expected Memory backend");
        };

        let config = LockStoreConfig {
            redis: Some(configuration::RedisLockStoreConfig {
                url: "redis://localhost:6379".to_string(),
                ttl: 10,
                key_prefix: "test_new_lock_store".to_owned(),
            }),
        };
        let lock_store = LockStore::new(config).expect("Failed to create lock store");
        let Backend::Redis(_) = lock_store.backend else {
            panic!("Expected Redis backend");
        };
    }
}
