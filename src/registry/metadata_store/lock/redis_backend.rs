use super::Error;
use redis::Client;
use std::fmt::Debug;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;
use tracing::{debug, error, warn};

#[derive(Debug, Clone)]
pub struct RedisBackend {
    client: Arc<Client>,
    ttl: usize,
    key_prefix: String,
}

const ACQUIRE_LOCK_SCRIPT: &str = r"
    if redis.call('exists', KEYS[1]) == 1 then
        return 0
    else
        redis.call('set', KEYS[1], 1, 'EX', ARGV[1])
        return 1
    end
";

impl RedisBackend {
    pub fn new(redis_url: &str, ttl: usize, key_prefix: String) -> redis::RedisResult<Self> {
        let client = Arc::new(Client::open(redis_url)?);
        Ok(RedisBackend {
            client,
            ttl,
            key_prefix,
        })
    }

    pub async fn acquire_lock(&self, key: &str) -> Result<RedisLockGuard, Error> {
        let lock = self.acquire_lock_with_retry(key).await?;
        Ok(RedisLockGuard { lock })
    }

    async fn acquire_lock_with_retry(&self, key: &str) -> Result<Arc<RedisRwLockInner>, Error> {
        let mut remaining_attempts = 10000; // XXX: customizable attempts count
        let poll_delay = Duration::from_millis(100); // XXX: customizable polling delay

        loop {
            match self.try_acquire_lock(key).await {
                Ok(lock) => return Ok(lock),
                Err(err) => {
                    if remaining_attempts == 0 {
                        error!("Failed to acquire lock, aborting");
                        return Err(err);
                    }
                    debug!("Failed to acquire lock, retrying");
                    remaining_attempts -= 1;
                }
            }

            tokio::time::sleep(poll_delay).await;
        }
    }

    async fn try_acquire_lock(&self, key: &str) -> Result<Arc<RedisRwLockInner>, Error> {
        let lock_key = format!("{}{key}", self.key_prefix);

        let stop_signal = Arc::new(AtomicBool::new(false));
        let lock = Arc::new(RedisRwLockInner {
            client: self.client.clone(),
            lock_key: lock_key.clone(),
            refresh_handle: Mutex::new(None),
            stop_signal: stop_signal.clone(),
        });

        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let script = redis::Script::new(ACQUIRE_LOCK_SCRIPT);

        let result: i32 = script
            .prepare_invoke()
            .key(lock_key.clone())
            .arg(self.ttl.to_string())
            .invoke_async(&mut conn)
            .await?;

        if result == 1 {
            let refresh_handle =
                Self::start_refresh_task(self.client.clone(), lock_key, self.ttl, stop_signal);

            let Ok(mut refresh_lock) = lock.refresh_handle.lock() else {
                return Err(Error::BackendError(
                    "Failed to acquire lock for the refresh-handle".to_owned(),
                ));
            };

            *refresh_lock = Some(refresh_handle);
            drop(refresh_lock);
            Ok(lock)
        } else {
            Err(Error::BackendError(format!(
                "Failed to acquire lock: {result}"
            )))
        }
    }

    fn start_refresh_task(
        client: Arc<Client>,
        key: String,
        ttl: usize,
        stop_signal: Arc<AtomicBool>,
    ) -> JoinHandle<Result<(), Error>> {
        spawn(move || -> Result<(), Error> {
            let mut conn = client.get_connection()?;

            let sleep_duration = Duration::from_millis(10);
            let refresh_interval = Duration::from_secs((ttl * 1000 / 2) as u64);
            let mut elapsed = Duration::ZERO;

            while !stop_signal.load(std::sync::atomic::Ordering::Relaxed) {
                if elapsed > refresh_interval {
                    let _: () = redis::cmd("EXPIRE").arg(&key).arg(ttl).query(&mut conn)?;
                    elapsed = Duration::ZERO;
                }

                sleep(sleep_duration);
                elapsed += sleep_duration;
            }

            Ok(())
        })
    }
}

struct RedisRwLockInner {
    client: Arc<Client>,
    lock_key: String,
    refresh_handle: Mutex<Option<JoinHandle<Result<(), Error>>>>,
    stop_signal: Arc<AtomicBool>,
}

impl RedisRwLockInner {
    fn release_lock(&self) {
        let Ok(mut lock) = self.refresh_handle.lock() else {
            warn!("Failed to release lock, letting it expire");
            return;
        };

        if let Some(handle) = lock.take() {
            self.stop_signal
                .store(true, std::sync::atomic::Ordering::Relaxed);
            if handle.join().is_err() {
                warn!("Failed to join refresh task");
            }
        }

        let Ok(mut conn) = self.client.get_connection() else {
            warn!("Failed to release lock, letting it expire");
            return;
        };

        let _: redis::RedisResult<()> = redis::cmd("DEL").arg(&self.lock_key).query(&mut conn);
    }
}

pub struct RedisLockGuard {
    lock: Arc<RedisRwLockInner>,
}

impl Drop for RedisLockGuard {
    fn drop(&mut self) {
        self.lock.release_lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::RedisLockStoreConfig;

    #[tokio::test]
    async fn test_acquire_lock() {
        let config = RedisLockStoreConfig {
            url: "redis://localhost:6379/2".to_owned(),
            ttl: 1,
            key_prefix: "test_acquire_lock".to_owned(),
        };

        let redis_backend = RedisBackend::new(&config.url, config.ttl, config.key_prefix)
            .expect("Failed to create RedisBackend");

        // Check we can't acquire another lock while there is already one held

        let lock = redis_backend.acquire_lock("test_acquire_lock").await;
        if let Err(err) = lock {
            panic!("Failed to acquire lock: {err}");
        }
        assert!(lock.is_ok());

        let other_lock = redis_backend.try_acquire_lock("test_acquire_lock").await;
        assert!(other_lock.is_err());
        drop(lock);

        let lock = redis_backend.acquire_lock("test_acquire_lock").await;
        assert!(lock.is_ok());
        drop(lock);
    }
}
