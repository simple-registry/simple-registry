use async_trait::async_trait;
use std::fmt::Debug;

mod config;
mod error;
pub(crate) mod memory;
pub(crate) mod redis;

pub use config::CacheStoreConfig;
pub use error::Error;

/// Trait for cache implementations that can store and retrieve values with a given TTL
#[async_trait]
pub trait Cache: Debug + Send + Sync {
    /// Store a value with a given TTL in the cache
    ///
    /// # Arguments
    ///
    /// * `key` - The key to store the value under
    /// * `value` - The value to store
    /// * `expires_in` - The time in seconds until the value expires
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the value was stored successfully
    /// * `Err(Error)` if the value could not be stored
    async fn store(&self, key: &str, value: &str, expires_in: u64) -> Result<(), Error>;

    /// Retrieve a value from the cache
    ///
    /// # Arguments
    ///
    /// * `key` - The key to retrieve the value for
    ///
    /// # Returns
    ///
    /// * `Ok(String)` if the value was found in the cache
    /// * `Err(Error)` if the value was not found in the cache or could not be retrieved
    async fn retrieve(&self, key: &str) -> Result<String, Error>;
}
