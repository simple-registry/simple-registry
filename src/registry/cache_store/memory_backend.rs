use crate::registry::cache_store::Error;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{interval, Instant};

#[derive(Debug)]
pub struct MemoryBackend {
    store: Arc<RwLock<HashMap<String, (String, Instant)>>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        let backend = MemoryBackend {
            store: Arc::new(RwLock::new(HashMap::new())),
        };
        backend.start_cleanup_task();
        backend
    }

    fn start_cleanup_task(&self) {
        let store = Arc::clone(&self.store);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let mut store = store.write().await;
                let now = Instant::now();
                store.retain(|_, &mut (_, expiry)| expiry > now);
            }
        });
    }

    async fn cleanup_expired_values(&self) {
        let mut store = self.store.write().await;
        let now = Instant::now();
        store.retain(|_, &mut (_, expiry)| expiry > now);
    }

    pub async fn store(&self, key: &str, value: &str, expires_in: u64) -> Result<(), Error> {
        self.cleanup_expired_values().await;
        let mut store = self.store.write().await;
        store.insert(
            key.to_string(),
            (
                value.to_string(),
                Instant::now() + Duration::from_secs(expires_in),
            ),
        );
        Ok(())
    }

    pub async fn retrieve(&self, key: &str) -> Result<String, Error> {
        self.cleanup_expired_values().await;
        let store = self.store.read().await;
        if let Some((value, expiry)) = store.get(key) {
            if *expiry > Instant::now() {
                return Ok(value.clone());
            }
        }

        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let cache = MemoryBackend::new();

        // Store and retrieve value
        let res = cache.store("key", "value", 1).await;
        assert!(res.is_ok());
        assert_eq!(cache.retrieve("key").await, Ok("value".to_string()));

        // Expired value
        tokio::time::sleep(Duration::from_millis(1050)).await;
        assert_eq!(cache.retrieve("key").await, Err(Error::NotFound));
    }
}
