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
}

struct RedisRwLockInner {
    client: Arc<Client>,
    key: String,
    refresh_handle: Mutex<Option<JoinHandle<Result<(), Error>>>>,
    stop_signal: Arc<AtomicBool>,
    is_writer: bool,
}

const ACQUIRE_READ_LOCK_SCRIPT: &str = r"
    if redis.call('exists', KEYS[1]) == 1 then
        return 0
    else
        redis.call('incr', KEYS[2])
        redis.call('expire', KEYS[2], ARGV[1])
        return 1
    end
";

const ACQUIRE_WRITE_LOCK_SCRIPT: &str = r"
    if redis.call('exists', KEYS[1]) == 1 then
        return 0
    elseif redis.call('exists', KEYS[2]) == 1 then
        return 0
    else
        redis.call('set', KEYS[1], 1, 'EX', ARGV[1])
        return 1
    end
";

const RELEASE_READ_LOCK_SCRIPT: &str = r"
    if redis.call('decr', KEYS[1]) <= 0 then
        redis.call('del', KEYS[1])
    end
    return 1
";

impl RedisBackend {
    pub fn new(redis_url: &str, ttl: usize) -> redis::RedisResult<Self> {
        let client = Arc::new(Client::open(redis_url)?);
        Ok(RedisBackend { client, ttl })
    }

    pub async fn acquire_read_lock(&self, key: &str) -> Result<RedisLockGuard, Error> {
        let lock = self.acquire_lock_with_retry(key, false).await?;
        Ok(RedisLockGuard { lock })
    }

    pub async fn acquire_write_lock(&self, key: &str) -> Result<RedisLockGuard, Error> {
        let lock = self.acquire_lock_with_retry(key, true).await?;
        Ok(RedisLockGuard { lock })
    }

    async fn acquire_lock_with_retry(
        &self,
        key: &str,
        is_writer: bool,
    ) -> Result<Arc<RedisRwLockInner>, Error> {
        let mut remaining_attempts = 10000; // XXX: customizable attempts count
        let poll_delay = Duration::from_millis(100); // XXX: customizable polling delay

        loop {
            match self.try_acquire_lock(key, is_writer).await {
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

    fn readers_key(key: &str) -> String {
        format!("{key}:readers")
    }

    fn writer_key(key: &str) -> String {
        format!("{key}:writer")
    }

    async fn try_acquire_lock(
        &self,
        key: &str,
        is_writer: bool,
    ) -> Result<Arc<RedisRwLockInner>, Error> {
        let stop_signal = Arc::new(AtomicBool::new(false));
        let lock = Arc::new(RedisRwLockInner {
            client: self.client.clone(),
            key: key.to_owned(),
            refresh_handle: Mutex::new(None),
            stop_signal: stop_signal.clone(),
            is_writer,
        });

        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let script = if is_writer {
            redis::Script::new(ACQUIRE_WRITE_LOCK_SCRIPT)
        } else {
            redis::Script::new(ACQUIRE_READ_LOCK_SCRIPT)
        };

        // issue: sometimes result is not == 1.
        let result: i32 = script
            .prepare_invoke()
            .key(Self::writer_key(key))
            .key(Self::readers_key(key))
            .arg(self.ttl.to_string())
            .invoke_async(&mut conn)
            .await?;

        if result == 1 {
            let refresh_key = if is_writer {
                Self::writer_key(key)
            } else {
                Self::readers_key(key)
            };

            let refresh_handle =
                Self::start_refresh_task(self.client.clone(), refresh_key, self.ttl, stop_signal);

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

        if self.is_writer {
            let write_lock_key = RedisBackend::writer_key(&self.key);
            let _: redis::RedisResult<()> = redis::cmd("DEL").arg(&write_lock_key).query(&mut conn);
        } else {
            let read_lock_key = RedisBackend::readers_key(&self.key);
            let _ = redis::Script::new(RELEASE_READ_LOCK_SCRIPT)
                .key(read_lock_key)
                .invoke::<i32>(&mut conn);
        }
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
mod test {
    use super::*;
    use crate::configuration::RedisLockStoreConfig;

    #[tokio::test]
    async fn test_acquire_read_lock() {
        let config = RedisLockStoreConfig {
            url: "redis://localhost:6379/1".to_owned(),
            ttl: 1,
        };

        let redis_backend =
            RedisBackend::new(&config.url, config.ttl).expect("Failed to create RedisBackend");

        // Check we can acquire multiple read locks
        let lock_1 = redis_backend
            .acquire_read_lock("test_acquire_read_lock")
            .await;
        assert!(lock_1.is_ok());

        let lock_2 = redis_backend
            .acquire_read_lock("test_acquire_read_lock")
            .await;
        assert!(lock_2.is_ok());

        // But we can't acquire a write lock while read locks are held
        let lock = redis_backend
            .try_acquire_lock("test_acquire_read_lock", true)
            .await;
        assert!(lock.is_err());
        drop(lock_1);
        drop(lock_2);

        // Now we should be able to acquire a write lock
        let lock = redis_backend
            .acquire_write_lock("test_acquire_read_lock")
            .await;
        assert_eq!(lock.is_ok(), true);
        drop(lock);
    }

    #[tokio::test]
    async fn test_acquire_write_lock() {
        let config = RedisLockStoreConfig {
            url: "redis://localhost:6379/2".to_owned(),
            ttl: 1,
        };

        let redis_backend =
            RedisBackend::new(&config.url, config.ttl).expect("Failed to create RedisBackend");

        // Check we can't acquire read or write locks while a write lock is held

        let lock = redis_backend
            .acquire_write_lock("test_acquire_write_lock")
            .await;
        if let Err(err) = lock {
            panic!("Failed to acquire write lock: {err}");
        }
        assert!(lock.is_ok());

        let read_lock = redis_backend
            .try_acquire_lock("test_acquire_write_lock", false)
            .await;
        assert!(read_lock.is_err());

        let write_lock = redis_backend
            .try_acquire_lock("test_acquire_write_lock", true)
            .await;
        assert!(write_lock.is_err());
        drop(lock);

        // Now we should be able to acquire a read lock
        let lock = redis_backend
            .acquire_read_lock("test_acquire_write_lock")
            .await;
        assert!(lock.is_ok());
        drop(lock);

        // ... or a write lock
        let lock = redis_backend
            .acquire_write_lock("test_acquire_write_lock")
            .await;
        assert!(lock.is_ok());
        drop(lock);
    }
}
