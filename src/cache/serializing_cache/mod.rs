use crate::cache::{Cache, Error};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::{debug, warn};

#[cfg(test)]
mod tests;

pub trait SerializingCache {
    async fn retrieve<T>(&self, key: &str) -> Result<Option<T>, Error>
    where
        T: DeserializeOwned;

    async fn store<T>(&self, key: &str, value: &T, ttl: u64) -> Result<(), Error>
    where
        T: Serialize;
}

impl SerializingCache for dyn Cache {
    async fn retrieve<T>(&self, key: &str) -> Result<Option<T>, Error>
    where
        T: DeserializeOwned,
    {
        let cached = match self.retrieve_value(key).await {
            Ok(s) => s,
            Err(err) => {
                warn!("Failed to retrieve value from cache for key {key}: {err}");
                let msg = format!("Failed to retrieve value from cache: {err}");
                return Err(Error::Execution(msg));
            }
        };

        let Some(cached) = cached else {
            return Ok(None);
        };

        match serde_json::from_str::<T>(&cached) {
            Ok(value) => {
                debug!("Using cached value for key: {key}");
                Ok(Some(value))
            }
            Err(e) => {
                warn!("Failed to deserialize cached value for key {key}: {e}");
                let msg = format!("Failed to deserialize cached value: {e}");
                Err(Error::Execution(msg))
            }
        }
    }

    async fn store<T>(&self, key: &str, value: &T, ttl: u64) -> Result<(), Error>
    where
        T: Serialize,
    {
        let serialized = match serde_json::to_string(value) {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to serialize value for caching for key {key}: {e}");
                let msg = format!("Failed to serialize value for caching: {e}");
                return Err(Error::Execution(msg));
            }
        };

        if let Err(err) = self.store_value(key, &serialized, ttl).await {
            warn!("Failed to store value in cache for key {}: {}", key, err);
            let msg = format!("Failed to store value in cache: {err}");
            return Err(Error::Execution(msg));
        }

        Ok(())
    }
}
