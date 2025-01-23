use crate::registry::cache_store::Error;
use redis::AsyncCommands;

#[derive(Debug)]
pub struct RedisBackend {
    client: redis::Client,
}

impl RedisBackend {
    pub fn new(redis_url: &str) -> Result<Self, Error> {
        let client = redis::Client::open(redis_url)?;
        Ok(RedisBackend { client })
    }

    async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection, Error> {
        Ok(self.client.get_multiplexed_async_connection().await?)
    }

    pub async fn store(&self, key: &str, value: &str, expires_in: u64) -> Result<(), Error> {
        let mut conn = self.get_connection().await?;
        Ok(conn.set_ex(key, value, expires_in).await?)
    }

    pub async fn retrieve(&self, key: &str) -> Result<String, Error> {
        let mut conn = self.get_connection().await?;

        let value: Option<String> = conn.get(key).await?;
        value.ok_or(Error::NotFound)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::configuration::RedisCacheConfig;
    use std::time::Duration;

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let config = RedisCacheConfig {
            url: "redis://localhost:6379/0".to_string(),
        };
        let cache = RedisBackend::new(&config.url).unwrap();

        // Store and retrieve token
        cache.store("key", "token", 1).await.unwrap();
        assert_eq!(cache.retrieve("key").await, Ok("token".to_string()));

        // Expired token
        tokio::time::sleep(Duration::from_millis(1050)).await;
        assert_eq!(cache.retrieve("key").await, Err(Error::NotFound));
    }
}
