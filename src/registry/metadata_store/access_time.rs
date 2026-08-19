//! Access-time recording: every path that stamps a link's `accessed_at`
//! lives here.
//!
//! With a debounce configured, stamps are buffered in [`AccessTimeWriter`] and
//! flushed periodically; otherwise each read stamps inline. Access times are
//! advisory, so every stamp is a plain overwrite and a lost race is dropped.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use chrono::Utc;
use futures_util::stream::{self, StreamExt};
use tokio::{spawn, sync::Mutex, time::sleep};
use tracing::{instrument, warn};

use angos_oci::Namespace;
use angos_storage::{Error as StorageError, ObjectStore};

use crate::registry::{
    Error,
    metadata_store::{LinkKind, LinkMetadata, MetadataStore},
    path_builder,
};

// Build-time wiring

/// Access-time wiring decided at build time. A configured debounce gets the
/// buffering writer plus its background flush task; otherwise stamps are
/// applied inline and no writer is spun up.
pub fn build_writer(
    store: &Arc<dyn ObjectStore>,
    debounce_secs: u64,
) -> (Option<AccessTimeWriter>, Option<Arc<FlushHandle>>) {
    if debounce_secs == 0 {
        return (None, None);
    }

    let writer = AccessTimeWriter::new();
    let shutdown = Arc::new(AtomicBool::new(false));
    spawn_flush_task(
        store.clone(),
        writer.clone(),
        shutdown.clone(),
        Duration::from_secs(debounce_secs),
    );

    (Some(writer), Some(Arc::new(FlushHandle::new(shutdown))))
}

fn spawn_flush_task(
    store: Arc<dyn ObjectStore>,
    writer: AccessTimeWriter,
    shutdown: Arc<AtomicBool>,
    interval: Duration,
) {
    spawn(async move {
        loop {
            sleep(interval).await;
            writer.flush(&store).await;
            if shutdown.load(Ordering::Acquire) {
                return;
            }
        }
    });
}

// Access-time write debouncing (lock-coordinated deployments)

#[derive(Clone)]
pub struct AccessTimeWriter {
    pub pending: Arc<Mutex<HashMap<String, (Namespace, LinkKind)>>>,
}

impl AccessTimeWriter {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn record(&self, namespace: &Namespace, link: &LinkKind) {
        let key = advisory_atime_path(namespace, link)
            .unwrap_or_else(|| path_builder::link_path(link, namespace));
        self.pending
            .lock()
            .await
            .insert(key, (namespace.clone(), link.clone()));
    }

    pub async fn flush(&self, store: &Arc<dyn ObjectStore>) {
        let entries: Vec<(Namespace, LinkKind)> = {
            let mut pending = self.pending.lock().await;
            pending.drain().map(|(_, v)| v).collect()
        };

        stream::iter(entries)
            .for_each_concurrent(10, |(namespace, link)| async move {
                // A tag's or revision's atime is its own overwritten key: the
                // newest arriving timestamp is the correct value, no
                // transaction and no read.
                let result = match advisory_atime_path(&namespace, &link) {
                    Some(key) => store
                        .put(&key, Bytes::from(Utc::now().to_rfc3339()))
                        .await
                        .map_err(Error::from),
                    None => flush_one_access_time(store, &namespace, &link).await,
                };
                if let Err(e) = result {
                    warn!("Failed to flush access time for {namespace}:{link}: {e}");
                }
            })
            .await;
    }
}

pub struct FlushHandle {
    shutdown: Arc<AtomicBool>,
}

impl FlushHandle {
    pub fn new(shutdown: Arc<AtomicBool>) -> Self {
        Self { shutdown }
    }
}

impl Drop for FlushHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

// Recording reads

impl MetadataStore {
    /// Like [`MetadataStore::read_link`] but records the link's access time.
    /// A configured debounce defers the stamp via the writer; otherwise the
    /// stamp is applied inline through the store's advisory update. The manifest
    /// pull path uses this when pull-time tracking is enabled.
    #[instrument(skip(self))]
    pub async fn read_link_recording_access(
        &self,
        namespace: &Namespace,
        link: &LinkKind,
    ) -> Result<LinkMetadata, Error> {
        let Some(writer) = &self.access_time_writer else {
            let link_data = self.stamp_link_access_time(namespace, link).await?;
            self.cache_put(namespace, link, &link_data).await;
            return Ok(link_data);
        };
        let link_data = self.read_link(namespace, link).await?;
        writer.record(namespace, link).await;
        Ok(link_data)
    }

    pub async fn flush_access_times(&self) {
        if let Some(writer) = &self.access_time_writer {
            writer.flush(self.object_store()).await;
        }
    }

    /// Stamp the access time inline. A tag or revision stamps its own atime
    /// key with a plain overwrite; every other kind rewrites its link body
    /// with a fresh `accessed_at`. Access times are advisory, so a concurrent
    /// writer's lost update is acceptable.
    async fn stamp_link_access_time(
        &self,
        namespace: &Namespace,
        link: &LinkKind,
    ) -> Result<LinkMetadata, Error> {
        match link {
            LinkKind::Tag(tag) => {
                let mut metadata = self.read_link_reference(namespace, link).await?;
                self.write_tag_access_time(namespace, tag).await?;
                metadata.accessed_at = Some(Utc::now());
                return Ok(metadata);
            }
            LinkKind::Digest(digest) => {
                let mut metadata = self.read_link_reference(namespace, link).await?;
                self.write_revision_access_time(namespace, digest).await?;
                metadata.accessed_at = Some(Utc::now());
                return Ok(metadata);
            }
            _ => {}
        }
        let link_path = path_builder::link_path(link, namespace);
        let body = self.object_store().get(&link_path).await?;
        let link_data = serde_json::from_slice::<LinkMetadata>(&body)?.accessed();
        let serialized = Bytes::from(serde_json::to_vec(&link_data)?);
        self.object_store().put(&link_path, serialized).await?;
        Ok(link_data)
    }
}

/// The kind's dedicated advisory atime key, when its primary state is
/// write-once and must not be stamped in place.
fn advisory_atime_path(namespace: &Namespace, link: &LinkKind) -> Option<String> {
    match link {
        LinkKind::Tag(tag) => Some(path_builder::tag_atime_path(namespace, tag)),
        LinkKind::Digest(digest) => Some(path_builder::revision_atime_path(namespace, digest)),
        _ => None,
    }
}

/// Flush a single access-time update as a plain read-modify-write. Access
/// times are advisory, so a concurrent writer's lost update is acceptable
/// and a vanished link is nothing to stamp.
async fn flush_one_access_time(
    store: &Arc<dyn ObjectStore>,
    namespace: &Namespace,
    link: &LinkKind,
) -> Result<(), Error> {
    let link_path = path_builder::link_path(link, namespace);
    let body = match store.get(&link_path).await {
        Ok(body) => body,
        Err(StorageError::NotFound) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let link_data = serde_json::from_slice::<LinkMetadata>(&body)?.accessed();
    let serialized = Bytes::from(serde_json::to_vec(&link_data)?);
    store.put(&link_path, serialized).await.map_err(Error::from)
}
