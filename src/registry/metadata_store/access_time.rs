//! Access-time recording: every path that stamps a link's `accessed_at`
//! lives here.
//!
//! A tag's or revision's access times are append-only entries under its atime
//! entry directory, named like tag entries (inverted-millis ordinal plus a
//! per-client suffix) so a listing yields newest first and same-millisecond
//! stamps from distinct clients coexist. The entries double as a rolling
//! audit log: each body records who pulled and when, every stamped pull is
//! one plain put, and scrub collects superseded entries past the audit
//! window.

use std::{str::from_utf8, sync::Arc};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use angos_oci::Namespace;
use angos_storage::{Error as StorageError, ObjectStore};

use crate::registry::{
    Error,
    metadata_store::{LinkKind, LinkMetadata, MetadataStore},
    path_builder,
};

/// The stored body of one access entry: who pulled and when.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessEntry {
    pub client: String,
    pub at: DateTime<Utc>,
}

/// Append one access entry to `dir`: a fresh ordinal plus the client's
/// suffix, the body recording the client and the stamp time.
pub async fn put_access_entry(
    store: &Arc<dyn ObjectStore>,
    dir: &str,
    client: &str,
) -> Result<(), Error> {
    let at = Utc::now();
    let name = path_builder::atime_entry_name(
        path_builder::tag_ord(Some(at)),
        &path_builder::atime_client_suffix(client),
    );
    let body = serde_json::to_vec(&AccessEntry {
        client: client.to_string(),
        at,
    })?;
    store
        .put(&format!("{dir}/{name}"), Bytes::from(body))
        .await
        .map_err(Error::from)
}

impl MetadataStore {
    /// Like [`MetadataStore::read_link`] but records the link's access time
    /// under `client`'s identity: one appended entry per stamped pull. The
    /// manifest pull path uses this when pull-time tracking is enabled.
    #[instrument(skip(self))]
    pub async fn read_link_recording_access(
        &self,
        namespace: &Namespace,
        link: &LinkKind,
        client: &str,
    ) -> Result<LinkMetadata, Error> {
        let link_data = self.stamp_link_access_time(namespace, link, client).await?;
        self.cache_put(namespace, link, &link_data).await;
        Ok(link_data)
    }

    /// Stamp the access time. A tag or revision appends an entry to its own
    /// atime directory; every other kind rewrites its link body with a fresh
    /// `accessed_at`. Access times are advisory, so a concurrent writer's
    /// lost update is acceptable.
    async fn stamp_link_access_time(
        &self,
        namespace: &Namespace,
        link: &LinkKind,
        client: &str,
    ) -> Result<LinkMetadata, Error> {
        match link {
            LinkKind::Tag(tag) => {
                let mut metadata = self.read_link_reference(namespace, link).await?;
                self.write_tag_access_time(namespace, tag, client).await?;
                metadata.accessed_at = Some(Utc::now());
                return Ok(metadata);
            }
            LinkKind::Digest(digest) => {
                let mut metadata = self.read_link_reference(namespace, link).await?;
                self.write_revision_access_time(namespace, digest, client)
                    .await?;
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

    /// The target's last access: the newest entry of `dir` (its ordinal
    /// encodes the stamp time), falling back to the legacy single key.
    pub async fn newest_access_time(
        &self,
        dir: &str,
        legacy_key: &str,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        let page = self.object_store().list(dir, 1, None).await?;
        if let Some(name) = page.items.first()
            && let Some(ord) = path_builder::parse_atime_entry(name)
            && let Some(at) = path_builder::tag_ord_ts(ord)
        {
            return Ok(Some(at));
        }
        match self.object_store().get(legacy_key).await {
            Ok(raw) => Ok(from_utf8(&raw)
                .ok()
                .and_then(|text| DateTime::parse_from_rfc3339(text.trim()).ok())
                .map(Into::into)),
            Err(StorageError::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
