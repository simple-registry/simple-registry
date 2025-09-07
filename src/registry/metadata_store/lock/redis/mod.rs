#[cfg(test)]
mod tests;

use crate::registry::metadata_store::lock::LockBackend;
use crate::registry::metadata_store::Error;
use async_trait::async_trait;
use redis::Client;
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;
use tracing::debug;

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
        10000
    }

    fn default_retry_delay_ms() -> u64 {
        100
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
    pub fn new(config: LockConfig) -> redis::RedisResult<Self> {
        let client = Arc::new(Client::open(config.url)?);
        Ok(RedisBackend {
            client,
            ttl: config.ttl,
            key_prefix: config.key_prefix,
            max_retries: config.max_retries,
            retry_delay_ms: config.retry_delay_ms,
        })
    }
}

struct RedisLock {
    client: Arc<Client>,
    key: String,
    refresh_handle: Mutex<Option<JoinHandle<()>>>,
    stop_signal: Arc<AtomicBool>,
}

impl RedisLock {
    fn release(&self) {
        if let Ok(mut handle) = self.refresh_handle.lock() {
            if let Some(h) = handle.take() {
                self.stop_signal.store(true, Ordering::Relaxed);
                let _ = h.join();
            }
        }

        if let Ok(mut conn) = self.client.get_connection() {
            let _: redis::RedisResult<()> = redis::cmd("DEL").arg(&self.key).query(&mut conn);
        }
    }
}

impl Drop for RedisLock {
    fn drop(&mut self) {
        self.release();
    }
}

#[async_trait]
impl LockBackend for RedisBackend {
    type Guard = Box<dyn Send>;

    async fn acquire_lock(&self, key: &str) -> Result<Self::Guard, Error> {
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
                // Start refresh task
                let stop_signal = Arc::new(AtomicBool::new(false));
                let client = self.client.clone();
                let key_clone = lock_key.clone();
                let ttl = self.ttl;
                let stop_signal_clone = stop_signal.clone();

                let refresh_handle = spawn(move || {
                    let Ok(mut conn) = client.get_connection() else {
                        return;
                    };

                    let refresh_interval = Duration::from_secs((ttl / 2) as u64);

                    while !stop_signal_clone.load(Ordering::Relaxed) {
                        sleep(refresh_interval);
                        if stop_signal_clone.load(Ordering::Relaxed) {
                            break;
                        }
                        let _: redis::RedisResult<()> = redis::cmd("EXPIRE")
                            .arg(&key_clone)
                            .arg(ttl)
                            .query(&mut conn);
                    }
                });

                let lock = Box::new(RedisLock {
                    client: self.client.clone(),
                    key: lock_key,
                    refresh_handle: Mutex::new(Some(refresh_handle)),
                    stop_signal,
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
