use crate::cache::{Cache, Error};
use async_trait::async_trait;
use redis::AsyncCommands;
use serde::Deserialize;
use tracing::info;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct BackendConfig {
    pub url: String,
    pub key_prefix: String,
}

#[derive(Debug)]
pub struct Backend {
    client: redis::Client,
    key_prefix: String,
}

impl Backend {
    pub fn new(config: &BackendConfig) -> Result<Self, Error> {
        info!("Using Redis cache store");
        let client = redis::Client::open(config.url.as_str())?;
        Ok(Backend {
            client,
            key_prefix: config.key_prefix.clone(),
        })
    }

    async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection, Error> {
        Ok(self.client.get_multiplexed_async_connection().await?)
    }
}

#[async_trait]
impl Cache for Backend {
    async fn store_value(&self, key: &str, value: &str, expires_in: u64) -> Result<(), Error> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}{key}", self.key_prefix);
        Ok(conn.set_ex(key, value, expires_in).await?)
    }

    async fn retrieve_value(&self, key: &str) -> Result<Option<String>, Error> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}{key}", self.key_prefix);
        let value: Option<String> = conn.get(key).await?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time;

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let config = BackendConfig {
            url: "redis://localhost:6379/0".to_string(),
            key_prefix: "test_acquire_write_lock".to_owned(),
        };
        let cache = Backend::new(&config).unwrap();

        cache.store_value("key", "token", 1).await.unwrap();
        assert_eq!(
            cache.retrieve_value("key").await,
            Ok(Some("token".to_string()))
        );

        time::sleep(Duration::from_millis(1050)).await;
        assert_eq!(cache.retrieve_value("key").await, Ok(None));
    }
}
