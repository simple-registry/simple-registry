use async_trait::async_trait;
use std::any::Any;
use std::fmt::Debug;
mod config;
mod error;
mod memory;
mod redis;
mod serializing_cache;

pub use config::Config;
pub use error::Error;
pub use serializing_cache::{retrieve, store};

/// Trait for cache implementations that can store and retrieve values with a given TTL
#[async_trait]
pub trait Cache: Any + Debug + Send + Sync {
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
    async fn store_value(&self, key: &str, value: &str, expires_in: u64) -> Result<(), Error>;

    /// Retrieve a value from the cache
    ///
    /// # Arguments
    ///
    /// * `key` - The key to retrieve the value for
    ///
    /// # Returns
    ///
    /// * `Ok(Some(String))` if the value was found in the cache
    /// * `Ok(None)` if the value was not found in the cache
    /// * `Err(Error)` if the value could not be retrieved
    async fn retrieve_value(&self, key: &str) -> Result<Option<String>, Error>;
}
