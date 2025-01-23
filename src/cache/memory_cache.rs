use crate::cache::Cache;
use crate::registry::Error;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{interval, Instant};

#[derive(Debug)]
pub struct MemoryCache {
    store: Arc<RwLock<HashMap<String, (String, Instant)>>>,
}

impl MemoryCache {
    pub fn new() -> Self {
        let cache = MemoryCache {
            store: Arc::new(RwLock::new(HashMap::new())),
        };
        cache.start_cleanup_task();
        cache
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

    async fn cleanup_expired_tokens(&self) {
        let mut store = self.store.write().await;
        let now = Instant::now();
        store.retain(|_, &mut (_, expiry)| expiry > now);
    }
}

#[async_trait]
impl Cache for MemoryCache {
    async fn store_token(&self, key: &str, token: &str, expires_in: u64) -> Result<(), Error> {
        self.cleanup_expired_tokens().await;
        let mut store = self.store.write().await;
        store.insert(
            key.to_string(),
            (
                token.to_string(),
                Instant::now() + Duration::from_secs(expires_in),
            ),
        );
        Ok(())
    }

    async fn retrieve_token(&self, key: &str) -> Result<Option<String>, Error> {
        self.cleanup_expired_tokens().await;
        let store = self.store.read().await;
        if let Some((token, expiry)) = store.get(key) {
            if *expiry > Instant::now() {
                return Ok(Some(token.clone()));
            }
        }
        Ok(None)
    }
}
