use crate::configuration::LockStoreConfig;
use std::fmt::Debug;
use tracing::{debug, instrument};

mod error;
mod memory_backend;
mod redis_backend;

pub use error::Error;
use memory_backend::{MemoryBackend, MemoryReadLockGuard, MemoryWriteLockGuard};
use redis_backend::{RedisBackend, RedisLockGuard};

#[derive(Debug)]
enum Backend {
    Redis(RedisBackend),
    Memory(MemoryBackend),
}

pub enum ReadLockGuard {
    Redis(RedisLockGuard),
    Memory(MemoryReadLockGuard),
}

pub enum WriteLockGuard {
    Redis(RedisLockGuard),
    Memory(MemoryWriteLockGuard),
}

/// A lock store that can acquire read and write locks for a given key
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

    /// Acquire a read lock for a given key.
    ///
    /// This will block until the read lock is acquired.
    /// Multiple read locks can be acquired for the same key at the same time.
    /// If a write lock is acquired for the key, no read locks can be acquired until the write lock is released.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to acquire the read lock for
    ///
    /// # Returns
    ///
    /// * `Ok(ReadLockGuard)` if the read lock was acquired successfully
    ///
    /// # Errors
    ///
    /// * `Error::BackendError` if the read lock could not be acquired
    #[instrument(skip(self))]
    pub async fn acquire_read_lock(&self, key: &str) -> Result<ReadLockGuard, Error> {
        match &self.backend {
            Backend::Redis(lock) => {
                let guard = lock
                    .acquire_read_lock(key)
                    .await
                    .map(ReadLockGuard::Redis)?;
                if let ReadLockGuard::Redis(_guard_inner) = &guard {
                    debug!("Acquired read lock for key");
                }

                Ok(guard)
            }
            Backend::Memory(lock) => {
                let guard = ReadLockGuard::Memory(lock.acquire_read_lock(key).await);
                if let ReadLockGuard::Memory(_guard_inner) = &guard {
                    debug!("Acquired read lock for key");
                }

                Ok(guard)
            }
        }
    }

    /// Acquire a write lock for a given key.
    /// This will block until the write lock is acquired.
    /// A write lock cannot be acquired if there is already another read or write lock on the key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to acquire the write lock for
    ///
    /// # Returns
    ///
    /// * `Ok(WriteLockGuard)` if the write lock was acquired successfully
    ///
    /// # Errors
    ///
    /// * `Error::BackendError` if the write lock could not be acquired
    #[instrument(skip(self))]
    pub async fn acquire_write_lock(&self, key: &str) -> Result<WriteLockGuard, Error> {
        match &self.backend {
            Backend::Redis(lock) => {
                let guard = lock
                    .acquire_write_lock(key)
                    .await
                    .map(WriteLockGuard::Redis)?;
                if let WriteLockGuard::Redis(_redis_guard) = &guard {
                    debug!("Acquired write lock for key");
                }

                Ok(guard)
            }
            Backend::Memory(lock) => {
                let guard = WriteLockGuard::Memory(lock.acquire_write_lock(key).await);
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
            assert!(false);
            return;
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
            assert!(false);
            return;
        };
    }
}
