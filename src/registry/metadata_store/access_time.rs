//! Every path that stamps a link's `accessed_at`.
//!
//! A tag's or revision's access times are append-only entries named like tag
//! entries (inverted-millis ordinal plus a per-client suffix), so a listing
//! yields newest first and same-millisecond stamps from distinct clients
//! coexist. Each body records who pulled and when, making the directory a
//! rolling audit log scrub trims past the audit window.

use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use angos_oci::{Digest, Namespace};
use angos_storage::ObjectStore;

use crate::registry::{
    Error,
    metadata_store::{
        LinkKind, LinkMetadata, MetadataStore,
        link::tag::{tag_ord, tag_ord_ts},
    },
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
        let mut link_data = self.read_link_reference(namespace, link).await?;
        self.record_link_access(namespace, link, client).await?;
        link_data.accessed_at = Some(Utc::now());
        self.cache_put(namespace, link, &link_data).await;
        Ok(link_data)
    }

    /// Append one access entry for `link` under `client`'s identity. Only tags
    /// and revisions are pull-tracked, so every other kind records nothing.
    pub async fn record_link_access(
        &self,
        namespace: &Namespace,
        link: &LinkKind,
        client: &str,
    ) -> Result<(), Error> {
        match link {
            LinkKind::Tag(tag) => self.write_tag_access_time(namespace, tag, client).await,
            LinkKind::Digest(digest) => {
                self.write_revision_access_time(namespace, digest, client)
                    .await
            }
            _ => Ok(()),
        }
    }

    /// The target's last access: the newest entry of `dir`, whose ordinal
    /// encodes the stamp time. Entries list newest first, so one key answers.
    pub async fn newest_access_time(&self, dir: &str) -> Result<Option<DateTime<Utc>>, Error> {
        let page = self.object_store().list(dir, 1, None).await?;
        Ok(page
            .items
            .first()
            .and_then(|name| parse_atime_entry(name))
            .and_then(tag_ord_ts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_names_round_trip_and_sort_newest_first() {
        let older = DateTime::from_timestamp_millis(1_000_000).unwrap();
        let newer = DateTime::from_timestamp_millis(2_000_000).unwrap();
        let suffix = atime_client_suffix("alice");

        let older_name = atime_entry_name(tag_ord(Some(older)), &suffix);
        let newer_name = atime_entry_name(tag_ord(Some(newer)), &suffix);
        assert!(
            newer_name < older_name,
            "a newer entry must sort before an older one"
        );
        assert_eq!(parse_atime_entry(&newer_name), Some(tag_ord(Some(newer))));
        assert_eq!(
            tag_ord_ts(parse_atime_entry(&newer_name).unwrap()),
            Some(newer)
        );
    }

    /// Two clients stamping in the same millisecond must land on distinct
    /// entries, or one pull silently overwrites the other's audit record.
    #[test]
    fn same_millisecond_stamps_from_distinct_clients_do_not_collide() {
        let at = DateTime::from_timestamp_millis(1_000_000).unwrap();
        let alice = atime_client_suffix("alice");
        let bob = atime_client_suffix("bob");
        assert_eq!(alice.len(), 8);
        assert_ne!(alice, bob);
        assert_ne!(
            atime_entry_name(tag_ord(Some(at)), &alice),
            atime_entry_name(tag_ord(Some(at)), &bob)
        );
    }

    #[test]
    fn foreign_entry_names_do_not_parse() {
        for name in [
            "",
            "0123.abcd1234",
            &format!("{:016x}.short", 1_u64),
            &format!("{:016x}.zzzzzzzz", 1_u64),
            &format!("{:016x}", 1_u64),
        ] {
            assert_eq!(parse_atime_entry(name), None, "name {name:?}");
        }
    }
}
