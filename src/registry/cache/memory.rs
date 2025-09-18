use crate::registry::cache::{Cache, Error};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::info;

#[derive(Debug)]
pub struct Backend {
    store: Arc<RwLock<HashMap<String, (String, Instant)>>>,
    counter: Arc<AtomicUsize>,
}

impl Backend {
    pub fn new() -> Self {
        info!("Using in-memory cache store");
        Backend {
            store: Arc::new(RwLock::new(HashMap::new())),
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl Cache for Backend {
    async fn store(&self, key: &str, value: &str, expires_in: u64) -> Result<(), Error> {
        let count = self.counter.fetch_add(1, Ordering::Relaxed);

        let mut store = self.store.write().await;

        if count % 1000 == 0 {
            let now = Instant::now();
            store.retain(|_, &mut (_, expiry)| expiry > now);
        }

        store.insert(
            key.to_string(),
            (
                value.to_string(),
                Instant::now() + Duration::from_secs(expires_in),
            ),
        );
        Ok(())
    }

    async fn retrieve(&self, key: &str) -> Result<String, Error> {
        let count = self.counter.fetch_add(1, Ordering::Relaxed);

        if count % 1000 == 0 {
            let mut store = self.store.write().await;
            let now = Instant::now();
            store.retain(|_, &mut (_, expiry)| expiry > now);

            if let Some((value, expiry)) = store.get(key) {
                if *expiry > Instant::now() {
                    return Ok(value.clone());
                }
            }
        } else {
            let store = self.store.read().await;
            if let Some((value, expiry)) = store.get(key) {
                if *expiry > Instant::now() {
                    return Ok(value.clone());
                }
            }
        }

        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let cache = Backend::new();

        let res = cache.store("key", "value", 1).await;
        assert!(res.is_ok());
        assert_eq!(cache.retrieve("key").await, Ok("value".to_string()));

        tokio::time::sleep(Duration::from_millis(1050)).await;
        assert_eq!(cache.retrieve("key").await, Err(Error::NotFound));
    }

    #[tokio::test]
    async fn test_cleanup_on_counter() {
        let cache = Backend::new();

        for i in 0..500 {
            cache
                .store(&format!("short_{i}"), "value", 1)
                .await
                .unwrap();
        }

        for i in 0..5 {
            cache
                .store(&format!("long_{i}"), "value", 100)
                .await
                .unwrap();
        }

        tokio::time::sleep(Duration::from_millis(1100)).await;

        for i in 0..495 {
            let _ = cache.retrieve(&format!("nonexistent_{i}")).await;
        }

        assert_eq!(cache.retrieve("long_0").await, Ok("value".to_string()));
        assert_eq!(cache.retrieve("short_0").await, Err(Error::NotFound));
    }
}
