#[cfg(test)]
mod tests;

use crate::registry::metadata_store::{lock::LockBackend, Error};
use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::Mutex;

#[derive(Debug, Default, Clone)]
pub struct MemoryBackend {
    locks: Arc<Mutex<HashMap<String, Weak<Mutex<()>>>>>,
    counter: Arc<AtomicUsize>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            locks: Arc::new(Mutex::new(HashMap::new())),
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    pub async fn get_lock_count(&self) -> usize {
        let mut locks = self.locks.lock().await;
        locks.retain(|_, weak| weak.upgrade().is_some());
        locks.len()
    }
}

#[async_trait]
impl LockBackend for MemoryBackend {
    type Guard = Box<dyn Send>;

    async fn acquire(&self, key: &str) -> Result<Self::Guard, Error> {
        let count = self.counter.fetch_add(1, Ordering::Relaxed);

        let mut locks = self.locks.lock().await;
        if count % 10000 == 0 {
            locks.retain(|_, weak| weak.upgrade().is_some());
        }

        let lock = if let Some(weak) = locks.get(key) {
            if let Some(lock) = weak.upgrade() {
                lock
            } else {
                locks.remove(key);
                let lock = Arc::new(Mutex::new(()));
                locks.insert(key.to_owned(), Arc::downgrade(&lock));
                lock
            }
        } else {
            let lock = Arc::new(Mutex::new(()));
            locks.insert(key.to_owned(), Arc::downgrade(&lock));
            lock
        };

        drop(locks);

        let guard = lock.lock_owned().await;
        Ok(Box::new(guard) as Box<dyn Send>)
    }
}
