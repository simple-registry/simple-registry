use crate::cache::Cache;
use crate::configuration;
use crate::registry::Error;
use async_trait::async_trait;
use redis::AsyncCommands;

#[derive(Debug)]
pub struct RedisCache {
    client: redis::Client,
}

impl RedisCache {
    pub fn new(redis_url: &str) -> Result<Self, configuration::Error> {
        let client = redis::Client::open(redis_url)?;
        Ok(RedisCache { client })
    }

    async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection, Error> {
        Ok(self.client.get_multiplexed_async_connection().await?)
    }
}

#[async_trait]
impl Cache for RedisCache {
    async fn store_token(&self, key: &str, token: &str, expires_in: u64) -> Result<(), Error> {
        let mut conn = self.get_connection().await?;
        Ok(conn.set_ex(key, token, expires_in).await?)
    }

    async fn retrieve_token(&self, key: &str) -> Result<Option<String>, Error> {
        let mut conn = self.get_connection().await?;
        Ok(conn.get(key).await?)
    }
}
