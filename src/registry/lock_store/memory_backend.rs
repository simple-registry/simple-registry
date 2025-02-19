use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex as AsyncMutex, RwLock};

#[derive(Debug, Default, Clone)]
pub struct MemoryBackend {
    locks: Arc<AsyncMutex<HashMap<String, Weak<RwLock<()>>>>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            locks: Arc::new(AsyncMutex::new(HashMap::new())),
        }
    }

    pub async fn acquire_read_lock(&self, key: &str) -> MemoryReadLockGuard {
        let lock = self.get_lock_for_key(key).await;
        lock.read_owned().await
    }

    pub async fn acquire_write_lock(&self, key: &str) -> MemoryWriteLockGuard {
        let lock = self.get_lock_for_key(key).await;
        lock.write_owned().await
    }

    async fn clean_unreferenced_locks(&self) {
        let mut locks = self.locks.lock().await;
        locks.retain(|_, weak_lock| weak_lock.upgrade().is_some());
    }

    async fn get_lock_for_key(&self, key: &str) -> Arc<RwLock<()>> {
        self.clean_unreferenced_locks().await;
        let mut locks = self.locks.lock().await;
        if let Some(weak_lock) = locks.get(key) {
            if let Some(lock) = weak_lock.upgrade() {
                return lock;
            }
            locks.remove(key);
        }
        let lock = Arc::new(RwLock::new(()));
        locks.insert(key.to_owned(), Arc::downgrade(&lock));
        lock
    }

    #[cfg(test)]
    pub async fn get_lock_count(&self) -> usize {
        self.clean_unreferenced_locks().await;
        self.locks.lock().await.len()
    }
}

pub type MemoryReadLockGuard = tokio::sync::OwnedRwLockReadGuard<()>;
pub type MemoryWriteLockGuard = tokio::sync::OwnedRwLockWriteGuard<()>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_acquire_read_lock() {
        let memory_backend = MemoryBackend::new();

        let lock_1 = memory_backend.acquire_read_lock("test").await;
        let lock_2 = memory_backend.acquire_read_lock("test").await;
        assert_eq!(memory_backend.get_lock_count().await, 1);

        drop(lock_1);
        assert_eq!(memory_backend.get_lock_count().await, 1);

        drop(lock_2);
        assert_eq!(memory_backend.get_lock_count().await, 0);
    }

    #[tokio::test]
    async fn test_acquire_write_lock() {
        let memory_backend = MemoryBackend::new();

        let lock = memory_backend.acquire_write_lock("test").await;
        assert_eq!(memory_backend.get_lock_count().await, 1);

        drop(lock);
        assert_eq!(memory_backend.get_lock_count().await, 0);
    }
}
