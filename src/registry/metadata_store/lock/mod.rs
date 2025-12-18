use std::fmt::Debug;

use async_trait::async_trait;

use crate::registry::metadata_store::Error;

pub mod memory;
pub mod redis;

pub use memory::MemoryBackend;
pub use redis::RedisBackend;

#[async_trait]
pub trait LockBackend: Send + Sync + Debug {
    type Guard: Send;

    async fn acquire(&self, keys: &[String]) -> Result<Self::Guard, Error>;
}
