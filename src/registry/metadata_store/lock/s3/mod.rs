#[cfg(test)]
mod tests;

use crate::command::server::sha256_hash;
use crate::registry::data_store;
use crate::registry::metadata_store::lock::LockBackend;
use crate::registry::metadata_store::Error;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use rand::random;
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, warn};

#[derive(Debug, Default, Clone, Deserialize, PartialEq)]
pub struct LockConfig {
    pub access_key_id: String,
    pub secret_key: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub key_prefix: String,
    #[serde(default = "LockConfig::default_ttl")]
    pub ttl: u64,
    #[serde(default = "LockConfig::default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "LockConfig::default_retry_delay_ms")]
    pub retry_delay_ms: u64,
}

impl LockConfig {
    fn default_ttl() -> u64 {
        30
    }

    fn default_max_retries() -> u32 {
        100
    }

    fn default_retry_delay_ms() -> u64 {
        10
    }
}

impl From<LockConfig> for data_store::s3::BackendConfig {
    fn from(config: LockConfig) -> Self {
        Self {
            access_key_id: config.access_key_id,
            secret_key: config.secret_key,
            endpoint: config.endpoint,
            bucket: config.bucket,
            region: config.region,
            key_prefix: config.key_prefix,
            ..Default::default()
        }
    }
}

#[derive(Deserialize, Serialize)]
struct LockStatus {
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct S3Backend {
    pub store: data_store::s3::Backend,
    ttl: u64,
    max_retries: u32,
    retry_delay_ms: u64,
}

impl Debug for S3Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Backend")
            .field("ttl", &self.ttl)
            .field("max_retries", &self.max_retries)
            .field("retry_delay_ms", &self.retry_delay_ms)
            .finish_non_exhaustive()
    }
}

impl S3Backend {
    pub fn new(config: &LockConfig) -> Result<Self, Error> {
        let store = data_store::s3::Backend::new(&data_store::s3::BackendConfig {
            access_key_id: config.access_key_id.clone(),
            secret_key: config.secret_key.clone(),
            endpoint: config.endpoint.clone(),
            bucket: config.bucket.clone(),
            region: config.region.clone(),
            key_prefix: config.key_prefix.clone(),
            multipart_copy_threshold:
                data_store::s3::BackendConfig::default_multipart_copy_threshold(),
            multipart_copy_chunk_size:
                data_store::s3::BackendConfig::default_multipart_copy_chunk_size(),
            multipart_copy_jobs: data_store::s3::BackendConfig::default_multipart_copy_jobs(),
            multipart_part_size: data_store::s3::BackendConfig::default_multipart_part_size(),
        })?;

        Ok(Self {
            store,
            ttl: config.ttl,
            max_retries: config.max_retries,
            retry_delay_ms: config.retry_delay_ms,
        })
    }

    async fn try_acquire(&self, key: &str) -> Result<Option<String>, Error> {
        let key = sha256_hash(key);

        let lock = LockStatus {
            expires_at: Utc::now()
                + chrono::Duration::seconds(i64::try_from(self.ttl).unwrap_or(i64::MAX)),
        };
        let lock_data = serde_json::to_vec(&lock)
            .map_err(|e| Error::StorageBackend(format!("Failed to serialize lock status: {e}")))?;

        let lock_data = Bytes::from(lock_data);

        match self
            .store
            .put_object_conditional(&key, lock_data.clone(), None)
            .await
        {
            Ok(Some(res)) => {
                debug!("Successfully acquired lock for key: {key}");
                Ok(res.e_tag)
            }
            Ok(None) => {
                if let Ok(res) = self.store.get_object(&key, None).await {
                    let Some(body) = res.body.collect().await.ok() else {
                        return Ok(None);
                    };
                    let body = body.to_vec();

                    let expired = serde_json::from_slice::<LockStatus>(&body)
                        .map(|l| Utc::now() > l.expires_at)
                        .unwrap_or(false); // If we can't parse the lock, assume it's expired

                    if expired {
                        debug!("Lock for key: {key} has expired, attempting to acquire");

                        match self
                            .store
                            .put_object_conditional(&key, lock_data.clone(), res.e_tag.as_deref())
                            .await
                        {
                            Ok(Some(res)) => {
                                debug!("Successfully acquired expired lock for key: {key}");
                                return Ok(res.e_tag);
                            }
                            Ok(None) => {
                                // Another process acquired the lock before us
                                warn!("Lock for key: {key} was acquired by another process");
                                return Ok(None);
                            }
                            Err(e) => {
                                warn!("Failed to acquire expired lock for key: {key} - {e}");
                                return Ok(None);
                            }
                        }
                    }
                }

                //warn!("Lock acquisition returned None for key: {key} - object already exists");

                Ok(None)
            }
            Err(e) => {
                warn!("Failed to acquire lock for key {key}: {e}");
                Ok(None)
            }
        }
    }

    async fn refresh_lock(&self, key: &str, e_tag: &str) -> Result<Option<String>, Error> {
        let key = sha256_hash(key);

        let lock = LockStatus {
            expires_at: Utc::now()
                + chrono::Duration::seconds(i64::try_from(self.ttl).unwrap_or(i64::MAX)),
        };
        let lock_data = serde_json::to_vec(&lock)
            .map_err(|e| Error::StorageBackend(format!("Failed to serialize lock status: {e}")))?;

        match self
            .store
            .put_object_conditional(&key, Bytes::from(lock_data), Some(e_tag))
            .await
        {
            Ok(Some(res)) => {
                debug!("Successfully refreshed lock for key: {key}");
                Ok(res.e_tag)
            }
            Ok(None) => {
                warn!("Failed to refresh lock for key: {key} - ETag mismatch");
                Ok(None)
            }
            Err(e) => Err(Error::StorageBackend(format!(
                "Failed to refresh lock: {e}"
            ))),
        }
    }

    async fn release_lock(&self, key: &str, e_tag: &str) -> Result<(), Error> {
        let key = sha256_hash(key);

        match self.store.delete_conditional(&key, e_tag).await {
            Ok(Some(_res)) => {
                debug!("Successfully released lock for key: {key}");
                Ok(())
            }
            Ok(None) => {
                // Hope-driven ops
                Ok(())
            }
            Err(e) => Err(Error::StorageBackend(format!(
                "Failed to release lock: {e}"
            ))),
        }
    }
}

struct S3Lock {
    refresh_handle: JoinHandle<()>,
    stop_notify: Arc<Notify>,
    inner: Option<S3LockInner>,
}

struct S3LockInner {
    backend: Arc<S3Backend>,
    key: String,
    e_tag: Arc<ArcSwap<String>>,
}

impl Drop for S3Lock {
    fn drop(&mut self) {
        self.stop_notify.notify_one();
        self.refresh_handle.abort();

        let Some(inner) = self.inner.take() else {
            return;
        };

        tokio::spawn(async move {
            let e_tag = inner.e_tag.load().as_ref().clone();
            if let Err(e) = inner.backend.release_lock(&inner.key, &e_tag).await {
                warn!("Failed to release lock on drop: {e}");
            }
        });
    }
}

#[async_trait]
impl LockBackend for S3Backend {
    type Guard = Box<dyn Send>;

    async fn acquire(&self, key: &str) -> Result<Self::Guard, Error> {
        let mut retries = self.max_retries;
        let mut retry_delay = Duration::from_millis(self.retry_delay_ms);

        loop {
            match self.try_acquire(key).await {
                Ok(Some(e_tag)) => {
                    let stop_notify = Arc::new(Notify::new());
                    let backend = Arc::new(self.clone());
                    let key_clone = key.to_string();
                    let ttl = self.ttl;
                    let refresh_interval = Duration::from_secs(ttl / 2);
                    let stop_notify_clone = stop_notify.clone();
                    let e_tag_swap = Arc::new(ArcSwap::new(Arc::new(e_tag.clone())));
                    let e_tag_swap_clone = e_tag_swap.clone();

                    let lock_inner = Some(S3LockInner {
                        backend: Arc::new(self.clone()),
                        key: key.to_string(),
                        e_tag: e_tag_swap,
                    });

                    let refresh_handle = tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                () = sleep(refresh_interval) => {
                                    let current_etag = e_tag_swap_clone.load().as_ref().clone();
                                    match backend.refresh_lock(&key_clone, &current_etag).await {
                                        Ok(Some(new_etag)) => {
                                            e_tag_swap_clone.store(Arc::new(new_etag));
                                        }
                                        Ok(None) => {
                                            warn!("Failed to refresh lock: ETag mismatch");
                                        }
                                        Err(e) => {
                                            warn!("Failed to refresh lock: {e}");
                                        }
                                    }
                                }
                                () = stop_notify_clone.notified() => {
                                    break;
                                }
                            }
                        }
                    });

                    let lock = Box::new(S3Lock {
                        refresh_handle,
                        stop_notify,
                        inner: lock_inner,
                    });

                    return Ok(lock as Box<dyn Send>);
                }
                Ok(None) => {
                    if retries == 0 {
                        return Err(Error::Lock(format!(
                            "Failed to acquire lock for key: {key}"
                        )));
                    }

                    retries -= 1;
                    debug!("Lock busy, retrying... ({retries} attempts left)");

                    // Add jitter to avoid thundering herd
                    let jitter = random::<u64>()
                        % u64::try_from(retry_delay.as_millis()).unwrap_or(u64::MAX);
                    retry_delay = min(retry_delay * 2, Duration::from_secs(5));

                    sleep(retry_delay + Duration::from_millis(jitter)).await;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
}
