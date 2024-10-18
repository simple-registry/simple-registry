use crate::error::RegistryError;
use redis::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::error;

#[derive(Debug)]
pub struct RedisRwLock {
    client: Client,
    ttl: usize,
}

struct RedisRwLockInner {
    client: Client,
    key: String,
    refresh_handle: Mutex<Option<JoinHandle<()>>>,
    is_writer: bool,
}

const ACQUIRE_READ_LOCK_SCRIPT: &str = r#"
    if redis.call('exists', KEYS[1]) == 1 then
        return 0
    else
        redis.call('incr', KEYS[2])
        redis.call('expire', KEYS[2], ARGV[1])
        return 1
    end
"#;

const ACQUIRE_WRITE_LOCK_SCRIPT: &str = r#"
    if redis.call('exists', KEYS[1]) == 1 then
        return 0
    elseif redis.call('exists', KEYS[2]) == 1 then
        return 0
    else
        redis.call('set', KEYS[1], 1, 'EX', ARGV[1])
        return 1
    end
"#;

const RELEASE_READ_LOCK_SCRIPT: &str = r#"
    if redis.call('decr', KEYS[1]) <= 0 then
        redis.call('del', KEYS[1])
    end
    return 1
"#;

impl RedisRwLock {
    pub fn new(redis_url: &str, ttl: usize) -> redis::RedisResult<Self> {
        let client = Client::open(redis_url)?;
        Ok(RedisRwLock { client, ttl })
    }

    pub async fn read_lock(&self, key: String) -> Result<RedisLockGuard, RegistryError> {
        let lock = self
            .acquire_lock_with_retry(key, false)
            .await
            .map_err(|err| {
                error!("Failed to acquire read lock: {}", err);
                RegistryError::InternalServerError(Some("Failed to acquire read lock".to_string()))
            })?;
        Ok(RedisLockGuard { lock })
    }

    pub async fn write_lock(&self, key: String) -> Result<RedisLockGuard, RegistryError> {
        let lock = self
            .acquire_lock_with_retry(key, true)
            .await
            .map_err(|err| {
                error!("Failed to acquire write lock: {}", err);
                RegistryError::InternalServerError(Some("Failed to acquire write lock".to_string()))
            })?;
        Ok(RedisLockGuard { lock })
    }

    async fn acquire_lock_with_retry(
        &self,
        key: String,
        is_writer: bool,
    ) -> redis::RedisResult<Arc<RedisRwLockInner>> {
        let max_attempts = 10;
        for attempt in 0..max_attempts {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }

            match self.try_acquire_lock(&key, is_writer).await {
                Ok(lock) => return Ok(lock),
                Err(err) if attempt == max_attempts - 1 => return Err(err),
                Err(_) => continue,
            }
        }

        Err(redis::RedisError::from((
            redis::ErrorKind::TryAgain,
            "Failed to acquire lock after retries",
        )))
    }

    fn readers_key(&self, key: &str) -> String {
        format!("{}:readers", key)
    }

    fn writer_key(&self, key: &str) -> String {
        format!("{}:writer", key)
    }

    async fn try_acquire_lock(
        &self,
        key: &str,
        is_writer: bool,
    ) -> redis::RedisResult<Arc<RedisRwLockInner>> {
        let lock = Arc::new(RedisRwLockInner {
            client: self.client.clone(),
            key: key.to_string(),
            refresh_handle: Mutex::new(None),
            is_writer,
        });

        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let script = match is_writer {
            false => redis::Script::new(ACQUIRE_READ_LOCK_SCRIPT),
            true => redis::Script::new(ACQUIRE_WRITE_LOCK_SCRIPT),
        };

        let result: i32 = script
            .prepare_invoke()
            .key(self.writer_key(key))
            .key(self.readers_key(key))
            .arg(self.ttl.to_string())
            .invoke_async(&mut conn)
            .await?;

        if result == 1 {
            let refresh_key = if is_writer {
                self.writer_key(key)
            } else {
                self.readers_key(key)
            };

            let refresh_handle =
                Self::start_refresh_task(self.client.clone(), refresh_key, self.ttl);

            *lock.refresh_handle.lock().await = Some(refresh_handle);

            Ok(lock)
        } else {
            Err(redis::RedisError::from((
                redis::ErrorKind::TryAgain,
                "Failed to acquire lock",
            )))
        }
    }

    fn start_refresh_task(client: Client, key: String, ttl: usize) -> JoinHandle<()> {
        tokio::spawn(async move {
            let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
                return;
            };

            let refresh_interval = Duration::from_secs((ttl / 2) as u64);
            let mut interval = time::interval(refresh_interval);

            loop {
                interval.tick().await;

                let result: redis::RedisResult<()> = redis::cmd("EXPIRE")
                    .arg(&key)
                    .arg(ttl)
                    .query_async(&mut conn)
                    .await;

                if result.is_err() {
                    break;
                }
            }
        })
    }
}

impl RedisRwLockInner {
    async fn release_lock(&self) {
        if let Some(handle) = self.refresh_handle.lock().await.take() {
            handle.abort();
        }

        let Ok(mut conn) = self.client.get_multiplexed_async_connection().await else {
            return;
        };

        match self.is_writer {
            false => {
                let read_lock_key = format!("{}:readers", self.key);
                let _ = redis::Script::new(RELEASE_READ_LOCK_SCRIPT)
                    .key(read_lock_key)
                    .invoke_async::<i32>(&mut conn)
                    .await;
            }
            true => {
                let write_lock_key = format!("{}:writer", self.key);
                let _: redis::RedisResult<()> = redis::cmd("DEL")
                    .arg(&write_lock_key)
                    .query_async(&mut conn)
                    .await;
            }
        }
    }
}

/// Guard returned by `read_lock` and `write_lock`, releases the lock when dropped.
pub struct RedisLockGuard {
    lock: Arc<RedisRwLockInner>,
}

impl Drop for RedisLockGuard {
    fn drop(&mut self) {
        let lock = self.lock.clone();
        tokio::spawn(async move {
            lock.release_lock().await;
        });
    }
}
