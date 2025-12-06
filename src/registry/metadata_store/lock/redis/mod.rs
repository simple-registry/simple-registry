#[cfg(test)]
mod tests;

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use redis::Client;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::debug;

use crate::registry::metadata_store::lock::LockBackend;
use crate::registry::metadata_store::Error;

#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
pub struct LockConfig {
    pub url: String,
    pub ttl: usize,
    #[serde(default)]
    pub key_prefix: String,
    #[serde(default = "LockConfig::default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "LockConfig::default_retry_delay_ms")]
    pub retry_delay_ms: u64,
}

impl LockConfig {
    fn default_max_retries() -> u32 {
        100
    }

    fn default_retry_delay_ms() -> u64 {
        10
    }
}

impl Default for LockConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            ttl: 30,
            key_prefix: String::new(),
            max_retries: Self::default_max_retries(),
            retry_delay_ms: Self::default_retry_delay_ms(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RedisBackend {
    client: Arc<Client>,
    ttl: usize,
    key_prefix: String,
    max_retries: u32,
    retry_delay_ms: u64,
}

impl RedisBackend {
    pub fn new(config: &LockConfig) -> redis::RedisResult<Self> {
        let client = Arc::new(Client::open(config.url.clone())?);
        Ok(RedisBackend {
            client,
            ttl: config.ttl,
            key_prefix: config.key_prefix.clone(),
            max_retries: config.max_retries,
            retry_delay_ms: config.retry_delay_ms,
        })
    }
}

struct RedisLock {
    refresh_handle: JoinHandle<()>,
    stop_notify: Arc<Notify>,
    client: Arc<Client>,
    key: String,
}

impl Drop for RedisLock {
    fn drop(&mut self) {
        self.stop_notify.notify_one();
        self.refresh_handle.abort();

        if let Ok(mut conn) = self.client.get_connection() {
            let _: redis::RedisResult<()> = redis::cmd("DEL").arg(&self.key).query(&mut conn);
        }
    }
}

#[async_trait]
impl LockBackend for RedisBackend {
    type Guard = Box<dyn Send>;

    async fn acquire(&self, key: &str) -> Result<Self::Guard, Error> {
        let lock_key = format!("{}{}", self.key_prefix, key);
        let mut retries = self.max_retries;
        let retry_delay = Duration::from_millis(self.retry_delay_ms);

        loop {
            let mut conn = self.client.get_multiplexed_async_connection().await?;

            // Try to acquire lock with SET NX EX
            let acquired: bool = redis::cmd("SET")
                .arg(&lock_key)
                .arg(1)
                .arg("NX")
                .arg("EX")
                .arg(self.ttl)
                .query_async(&mut conn)
                .await?;

            if acquired {
                let stop_notify = Arc::new(Notify::new());
                let client = self.client.clone();
                let key = lock_key.clone();
                let ttl = self.ttl;
                let refresh_interval = Duration::from_secs((ttl / 2) as u64);
                let stop_notify_clone = stop_notify.clone();

                let refresh_handle = tokio::spawn(async move {
                    let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
                        return;
                    };

                    loop {
                        tokio::select! {
                            () = sleep(refresh_interval) => {
                                let _: redis::RedisResult<()> = redis::cmd("EXPIRE")
                                    .arg(&key)
                                    .arg(ttl)
                                    .query_async(&mut conn)
                                    .await;
                            }
                            () = stop_notify_clone.notified() => {
                                // Stop signal received
                                break;
                            }
                        }
                    }
                });

                let lock = Box::new(RedisLock {
                    refresh_handle,
                    stop_notify,
                    client: self.client.clone(),
                    key: lock_key,
                });

                return Ok(lock as Box<dyn Send>);
            }

            if retries == 0 {
                return Err(Error::Lock(format!(
                    "Failed to acquire lock for key: {key}"
                )));
            }

            retries -= 1;
            debug!("Lock busy, retrying... ({} attempts left)", retries);
            tokio::time::sleep(retry_delay).await;
        }
    }
}
