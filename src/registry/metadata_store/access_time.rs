//! Every path that stamps a link's `accessed_at`.
//!
//! A tag's or revision's access times are append-only entries named like tag
//! entries (inverted-millis ordinal plus a per-client suffix), so a listing
//! yields newest first and same-millisecond stamps from distinct clients
//! coexist. Each body records who pulled and when, making the directory a
//! rolling audit log scrub trims past the audit window.

use std::{str::from_utf8, sync::Arc};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use angos_oci::{Digest, Namespace};
use angos_storage::{Error as StorageError, ObjectStore};

use crate::registry::{
    Error,
    metadata_store::{
        LinkKind, LinkMetadata, MetadataStore,
        link::tag::{tag_ord, tag_ord_ts},
    },
    path_builder,
};

/// The stored body of one access entry: who pulled and when.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessEntry {
    pub client: String,
    pub at: DateTime<Utc>,
}

/// Longest client identity an access entry records; identities come from
/// token claims, which have no length bound of their own.
const MAX_CLIENT_CHARS: usize = 256;

/// One access entry: `<ord>.<suffix>`, where `<ord>` is the inverted-millis
/// ordinal of [`tag_ord`] (entries list newest first) and `<suffix>` breaks
/// same-millisecond collisions between clients.
pub fn atime_entry_name(ord: u64, suffix: &str) -> String {
    format!("{ord:016x}.{suffix}")
}

/// The entry-name collision breaker for one client identity: the first 8 hex
/// of its sha256.
pub fn atime_client_suffix(client: &str) -> String {
    Digest::sha256_of_bytes(client.as_bytes()).hash()[..8].to_string()
}

/// Decode one entry filename of an atime entry directory back into its
/// ordinal. `None` = not a shape this version writes.
pub fn parse_atime_entry(name: &str) -> Option<u64> {
    let (ord, suffix) = name.split_once('.')?;
    if ord.len() != 16 || suffix.len() != 8 || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(ord, 16).ok()
}

/// Append one access entry to `dir`, its body recording the client and the
/// stamp time.
pub async fn put_access_entry(
    store: &Arc<dyn ObjectStore>,
    dir: &str,
    client: &str,
) -> Result<(), Error> {
    let client = match client.char_indices().nth(MAX_CLIENT_CHARS) {
        Some((cut, _)) => &client[..cut],
        None => client,
    };
    let at = Utc::now();
    let name = atime_entry_name(tag_ord(Some(at)), &atime_client_suffix(client));
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
    /// Like [`MetadataStore::read_link`] but appends one access entry under
    /// `client`'s identity.
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

    /// A tag or revision appends an entry to its atime directory; every other
    /// kind rewrites its link body. Access times are advisory, so the
    /// rewrite's lost update under a concurrent writer is acceptable.
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
        let Some(link_path) = path_builder::link_path(link, namespace) else {
            return Err(Error::NotFound);
        };
        let body = self.object_store().get(&link_path).await?;
        let link_data = serde_json::from_slice::<LinkMetadata>(&body)?.accessed();
        let serialized = Bytes::from(serde_json::to_vec(&link_data)?);
        self.object_store().put(&link_path, serialized).await?;
        Ok(link_data)
    }

    /// The target's last access, from the newest entry of `dir` (its ordinal
    /// encodes the stamp time) or the legacy single key.
    pub async fn newest_access_time(
        &self,
        dir: &str,
        legacy_key: &str,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        let page = self.object_store().list(dir, 1, None).await?;
        if let Some(name) = page.items.first()
            && let Some(ord) = parse_atime_entry(name)
            && let Some(at) = tag_ord_ts(ord)
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
