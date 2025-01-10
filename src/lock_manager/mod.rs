use crate::configuration::LockingConfig;
use crate::{configuration, registry};
use tracing::{debug, error, info, instrument};

mod memory;
mod redis;

#[derive(Debug, Clone)]
pub enum LockManager {
    Redis(redis::LockManager),
    InMemory(memory::LockManager),
}

pub enum ReadGuard {
    Redis(redis::LockGuard),
    InMemory(memory::ReadLockGuard),
}

pub enum WriteGuard {
    Redis(redis::LockGuard),
    InMemory(memory::WriteLockGuard),
}

impl LockManager {
    pub fn new(config: LockingConfig) -> Result<Self, configuration::Error> {
        if let Some(redis_config) = config.redis {
            info!("Using Redis lock manager");
            let redis_lock =
                redis::LockManager::new(&redis_config.url, redis_config.ttl).map_err(|err| {
                    error!("Unable to create Redis lock: {}", err);
                    configuration::Error::LockManagerInit("Unable to create Redis lock".to_string())
                })?;
            Ok(LockManager::Redis(redis_lock))
        } else {
            info!("Using in-memory lock manager");
            Ok(LockManager::InMemory(memory::LockManager::new()))
        }
    }

    #[instrument(skip(self))]
    pub async fn read_lock(&self, lock_key: String) -> Result<ReadGuard, registry::Error> {
        match self {
            LockManager::Redis(lock) => {
                let guard = lock.read_lock(lock_key).await.map(ReadGuard::Redis)?;
                if let ReadGuard::Redis(_redis_guard) = &guard {
                    debug!("Acquired read lock for key");
                }
                Ok(guard)
            }
            LockManager::InMemory(lock) => {
                let guard = ReadGuard::InMemory(lock.read_lock(lock_key).await);
                if let ReadGuard::InMemory(_in_memory_guard) = &guard {
                    debug!("Acquired read lock for key");
                }
                Ok(guard)
            }
        }
    }

    #[instrument(skip(self))]
    pub async fn write_lock(&self, lock_key: String) -> Result<WriteGuard, registry::Error> {
        match self {
            LockManager::Redis(lock) => {
                let guard = lock.write_lock(lock_key).await.map(WriteGuard::Redis)?;
                if let WriteGuard::Redis(_redis_guard) = &guard {
                    debug!("Acquired write lock for key");
                }

                Ok(guard)
            }
            LockManager::InMemory(lock) => {
                let guard = WriteGuard::InMemory(lock.write_lock(lock_key).await);
                if let WriteGuard::InMemory(_in_memory_guard) = &guard {
                    debug!("Acquired write lock for key");
                }

                Ok(guard)
            }
        }
    }
}
