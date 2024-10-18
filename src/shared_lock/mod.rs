use crate::error::RegistryError;
use crate::shared_lock::memory::{InMemoryReadLockGuard, InMemoryRwLock, InMemoryWriteLockGuard};
use crate::shared_lock::redis::{RedisLockGuard, RedisRwLock};
use tracing::error;

mod memory;
mod redis;

#[derive(Debug)]
pub enum SharedRwLock {
    Redis(RedisRwLock),
    InMemory(InMemoryRwLock),
}

pub enum ReadGuard {
    Redis(RedisLockGuard),
    InMemory(InMemoryReadLockGuard),
}

pub enum WriteGuard {
    Redis(RedisLockGuard),
    InMemory(InMemoryWriteLockGuard),
}

impl SharedRwLock {
    pub fn new_in_memory() -> Self {
        SharedRwLock::InMemory(InMemoryRwLock::default())
    }

    pub fn new_redis(redis_url: &str, lock_ttl: usize) -> Result<Self, RegistryError> {
        let redis_lock = RedisRwLock::new(redis_url, lock_ttl).map_err(|err| {
            error!("Unable to create Redis lock: {}", err);
            RegistryError::InternalServerError(Some("Unable to create Redis lock".to_string()))
        })?;
        Ok(SharedRwLock::Redis(redis_lock))
    }

    pub async fn read_lock(&self, lock_key: String) -> Result<ReadGuard, RegistryError> {
        match self {
            SharedRwLock::Redis(lock) => lock.read_lock(lock_key).await.map(ReadGuard::Redis),
            SharedRwLock::InMemory(lock) => Ok(ReadGuard::InMemory(lock.read_lock(lock_key).await)),
        }
    }

    pub async fn write_lock(&self, lock_key: String) -> Result<WriteGuard, RegistryError> {
        match self {
            SharedRwLock::Redis(lock) => lock.write_lock(lock_key).await.map(WriteGuard::Redis),
            SharedRwLock::InMemory(lock) => {
                Ok(WriteGuard::InMemory(lock.write_lock(lock_key).await))
            }
        }
    }
}
