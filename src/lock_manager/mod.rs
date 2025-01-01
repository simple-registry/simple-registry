use crate::error::RegistryError;
use crate::lock_manager::memory::{
    InMemoryReadLockGuard, InMemoryWriteLockGuard, MemoryLockManager,
};
use crate::lock_manager::redis::{RedisLockGuard, RedisLockManager};
use tracing::error;

mod memory;
mod redis;

#[derive(Debug, Clone)]
pub enum LockManager {
    Redis(RedisLockManager),
    InMemory(MemoryLockManager),
}

pub enum ReadGuard {
    Redis(RedisLockGuard),
    InMemory(InMemoryReadLockGuard),
}

pub enum WriteGuard {
    Redis(RedisLockGuard),
    InMemory(InMemoryWriteLockGuard),
}

impl LockManager {
    pub fn new_in_memory() -> Self {
        LockManager::InMemory(MemoryLockManager::new())
    }

    pub fn new_redis(redis_url: &str, lock_ttl: usize) -> Result<Self, RegistryError> {
        let redis_lock = RedisLockManager::new(redis_url, lock_ttl).map_err(|err| {
            error!("Unable to create Redis lock: {}", err);
            RegistryError::InternalServerError(Some("Unable to create Redis lock".to_string()))
        })?;
        Ok(LockManager::Redis(redis_lock))
    }

    pub async fn read_lock(&self, lock_key: String) -> Result<ReadGuard, RegistryError> {
        match self {
            LockManager::Redis(lock) => lock.read_lock(lock_key).await.map(ReadGuard::Redis),
            LockManager::InMemory(lock) => Ok(ReadGuard::InMemory(lock.read_lock(lock_key).await)),
        }
    }

    pub async fn write_lock(&self, lock_key: String) -> Result<WriteGuard, RegistryError> {
        match self {
            LockManager::Redis(lock) => lock.write_lock(lock_key).await.map(WriteGuard::Redis),
            LockManager::InMemory(lock) => {
                Ok(WriteGuard::InMemory(lock.write_lock(lock_key).await))
            }
        }
    }
}
