use crate::cache::memory_cache::MemoryCache;
use crate::cache::redis_cache::RedisCache;
use crate::registry::Error;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

mod memory_cache;
mod redis_cache;

use crate::configuration;
use crate::configuration::CacheConfig;

#[async_trait]
pub trait Cache: Debug + Send + Sync {
    async fn store_token(&self, key: &str, token: &str, expires_in: u64) -> Result<(), Error>;
    async fn retrieve_token(&self, key: &str) -> Result<Option<String>, Error>;
}

pub fn build_cache_engine(
    cache_config: CacheConfig,
) -> Result<Arc<dyn Cache>, configuration::Error> {
    match cache_config.redis {
        Some(redis_config) => Ok(Arc::new(RedisCache::new(&redis_config.url)?)),
        None => Ok(Arc::new(MemoryCache::new())),
    }
}
