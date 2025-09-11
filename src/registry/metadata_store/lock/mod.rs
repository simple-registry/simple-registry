use crate::registry::metadata_store::Error;
use async_trait::async_trait;
use std::fmt::Debug;

pub mod memory;
pub mod redis;

pub use memory::MemoryBackend;
pub use redis::RedisBackend;

/// Trait for lock backend implementations
#[async_trait]
pub trait LockBackend: Send + Sync + Debug {
    type Guard: Send;

    /// Acquire an exclusive lock for the given key
    async fn acquire(&self, key: &str) -> Result<Self::Guard, Error>;
}
