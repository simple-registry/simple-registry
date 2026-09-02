//! Tag state as ordered write-once entries.
//!
//! A tag is the set of entries under its [`NamespaceKeys::tag_entry_dir`], each
//! named `<ord>.<kind>.<algo>.<hash>` with an inverted-timestamp `<ord>` so a
//! listing yields newest first. Writers only append, so last-writer-wins is a
//! property of the key names and concurrent writers never contend; a tag with
//! no entries does not exist.

use std::{collections::BTreeMap, str::FromStr};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use angos_oci::{Algorithm, Digest, MediaType, Namespace, Tag};
use angos_storage::Error as StorageError;

use crate::registry::keys::NamespaceKeys;
use crate::registry::metadata_store::{access_time::put_access_entry, mutation::Mutation};
use crate::registry::{
    Error,
    metadata_store::{LinkMetadata, MetadataStore},
};

/// The stored body of one tag entry, carrying the descriptor fields the key
/// name cannot. Resolution reads key names alone and never fetches it.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TagEntryBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<MediaType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// The inverted-timestamp ordinal of `ts`: entries sort newest first.
/// `u64::MAX` is reserved for a missing timestamp: it sorts last, never wins
/// resolution, and stays distinct from a real epoch timestamp.
pub fn tag_ord(ts: Option<DateTime<Utc>>) -> u64 {
    match ts {
        None => u64::MAX,
        Some(ts) => u64::MAX - 1 - ts.timestamp_millis().max(0).unsigned_abs(),
    }
}

/// The author timestamp `ord` encodes; `None` for the never-wins ordinal.
pub fn tag_ord_ts(ord: u64) -> Option<DateTime<Utc>> {
    if ord == u64::MAX {
        return None;
    }
    DateTime::from_timestamp_millis(i64::try_from(u64::MAX - 1 - ord).ok()?)
}

/// Decode one entry filename of [`NamespaceKeys::tag_entry_dir`] back into
/// `(ord, deletion, digest)`. `None` = not a shape this version writes.
pub fn parse_tag_entry(name: &str) -> Option<(u64, bool, Digest)> {
    let mut parts = name.splitn(4, '.');
    let (Some(ord), Some(kind), Some(algorithm), Some(hash)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if ord.len() != 16 {
        return None;
    }
    let ord = u64::from_str_radix(ord, 16).ok()?;
    let deletion = match kind {
        "set" => false,
        "del" => true,
        _ => return None,
    };
    let digest = Digest::with_algorithm(Algorithm::from_str(algorithm).ok()?, hash).ok()?;
    Some((ord, deletion, digest))
}

/// Annotation keys under the distribution spec's reserved prefix never
/// persist into a tag entry.
const RESERVED_ANNOTATION_PREFIX: &str = "org.opencontainers.distribution";

/// The pushed annotations minus the reserved-prefix keys, `None` when nothing
/// survives.
fn persisted_annotations(
    annotations: Option<BTreeMap<String, String>>,
) -> Option<BTreeMap<String, String>> {
    let filtered: BTreeMap<String, String> = annotations?
        .into_iter()
        .filter(|(key, _)| !key.starts_with(RESERVED_ANNOTATION_PREFIX))
        .collect();
    (!filtered.is_empty()).then_some(filtered)
}

/// The resolved winner of a tag's newest entry group; its fields rebuild the
/// entry key via [`NamespaceKeys::tag_entry_path`].
struct TagWinner {
    ord: u64,
    deletion: bool,
    digest: Digest,
}

/// The key carries the authored timestamp (truncated to the millisecond the
/// ordinal encodes) and the target; the body carries the descriptor fields.
pub fn tag_set_mutation(
    namespace: &Namespace,
    tag: &Tag,
    created_at: DateTime<Utc>,
    target: &Digest,
    media_type: Option<MediaType>,
    size: Option<u64>,
    annotations: Option<BTreeMap<String, String>>,
) -> Result<Mutation, serde_json::Error> {
    let key = namespace.tag_entry_path(tag, tag_ord(Some(created_at)), false, target);
    let body = serde_json::to_vec(&TagEntryBody {
        media_type,
        size,
        annotations: persisted_annotations(annotations),
    })?;
    Ok(Mutation::Put {
        key,
        body: Bytes::from(body),
    })
}

/// The tombstone names the digest the tag held immediately before deletion and
/// copies the superseded winner's descriptor `body`, which tag history needs.
pub fn tag_del_mutation(
    namespace: &Namespace,
    tag: &Tag,
    created_at: DateTime<Utc>,
    prior_target: &Digest,
    body: &TagEntryBody,
) -> Result<Mutation, serde_json::Error> {
    let key = namespace.tag_entry_path(tag, tag_ord(Some(created_at)), true, prior_target);
    let body = serde_json::to_vec(body)?;
    Ok(Mutation::Put {
        key,
        body: Bytes::from(body),
    })
}

impl MetadataStore {
    /// Resolve `tag` to link-shaped metadata: the complete newest entry group
    /// decides, the highest digest winning a same-millisecond tie and a
    /// deletion never beating an equal-timestamped push of the same digest. A
    /// tombstone winner reads as `NotFound`, and `media_type` is always `None`
    /// because the winner comes from key names alone.
    pub async fn resolve_tag(
        &self,
        namespace: &Namespace,
        tag: &Tag,
    ) -> Result<LinkMetadata, Error> {
        match self.resolve_tag_winner(namespace, tag).await? {
            Some(winner) if winner.deletion => Err(Error::NotFound),
            Some(winner) => Ok(LinkMetadata {
                target: winner.digest,
                created_at: tag_ord_ts(winner.ord),
                media_type: None,
                descriptor: None,
            }),
            None => Err(Error::NotFound),
        }
    }

    /// Targeted read of the resolved winner's stored entry body, which only
    /// the tombstone needs. An entry deleted since the winner resolved falls
    /// back to the metadata's own media type.
    pub async fn read_tag_winner_body(
        &self,
        namespace: &Namespace,
        tag: &Tag,
        metadata: &LinkMetadata,
    ) -> Result<TagEntryBody, Error> {
        let entry_path =
            namespace.tag_entry_path(tag, tag_ord(metadata.created_at), false, &metadata.target);
        match self.object_store().get(&entry_path).await {
            Ok(body) => Ok(serde_json::from_slice(&body).unwrap_or_default()),
            Err(StorageError::NotFound) => Ok(TagEntryBody {
                media_type: metadata.media_type.clone(),
                ..TagEntryBody::default()
            }),
            Err(e) => Err(e.into()),
        }
    }

    /// The winner of the tag's complete lowest-ordinal entry group, or `None`
    /// when the tag has no entries. Pages until the ordinal changes, so a
    /// same-millisecond pair straddling a page boundary is never split.
    async fn resolve_tag_winner(
        &self,
        namespace: &Namespace,
        tag: &Tag,
    ) -> Result<Option<TagWinner>, Error> {
        let dir = namespace.tag_entry_dir(tag);
        let mut group: Vec<TagWinner> = Vec::new();
        let mut token = None;
        'pages: loop {
            let page = self.object_store().list(&dir, 1000, token).await?;
            for name in &page.items {
                let Some((ord, deletion, digest)) = parse_tag_entry(name) else {
                    continue;
                };
                match group.first() {
                    Some(first) if ord != first.ord => break 'pages,
                    _ => group.push(TagWinner {
                        ord,
                        deletion,
                        digest,
                    }),
                }
            }
            token = page.next_token;
            if token.is_none() {
                break;
            }
        }
        // Highest digest first; a `set` beats a `del` of the same digest.
        group.sort_by(|a, b| {
            b.digest
                .cmp(&a.digest)
                .then_with(|| a.deletion.cmp(&b.deletion))
        });
        Ok(group.into_iter().next())
    }

    /// Test-only write of one `set` entry, as a sibling replica's write would
    /// land it.
    #[cfg(test)]
    pub async fn write_tag_state(
        &self,
        namespace: &Namespace,
        tag: &Tag,
        metadata: &LinkMetadata,
    ) -> Result<(), Error> {
        let key =
            namespace.tag_entry_path(tag, tag_ord(metadata.created_at), false, &metadata.target);
        let body = serde_json::to_vec(&TagEntryBody {
            media_type: metadata.media_type.clone(),
            ..TagEntryBody::default()
        })?;
        self.object_store()
            .put(&key, Bytes::from(body))
            .await
            .map_err(Error::from)
    }

    /// The tag's advisory last-pull timestamp: its newest access entry.
    pub async fn read_tag_access_time(
        &self,
        namespace: &Namespace,
        tag: &Tag,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        self.newest_access_time(&namespace.tag_atime_entry_dir(tag))
            .await
    }

    /// Append one access entry naming `client` to the tag's atime directory,
    /// a plain put with no read.
    pub async fn write_tag_access_time(
        &self,
        namespace: &Namespace,
        tag: &Tag,
        client: &str,
    ) -> Result<(), Error> {
        put_access_entry(
            self.object_store(),
            &namespace.tag_atime_entry_dir(tag),
            client,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn the_ordinal_round_trips_and_reserves_the_never_wins_value() {
        let at = DateTime::from_timestamp_millis(1_700_000_000_123).unwrap();
        assert_eq!(tag_ord_ts(tag_ord(Some(at))), Some(at));
        assert_eq!(tag_ord_ts(tag_ord(None)), None, "the never-wins ordinal");
        assert_eq!(tag_ord(None), u64::MAX);
        assert!(
            tag_ord(None) > tag_ord(Some(DateTime::from_timestamp_millis(0).unwrap())),
            "a missing timestamp must sort after a real epoch one"
        );
        // Sub-millisecond precision is not encoded, so two stamps in the same
        // millisecond share an ordinal and only the digest separates them.
        let same_ms = DateTime::from_timestamp_micros(1_700_000_000_123_400).unwrap();
        assert_eq!(tag_ord(Some(same_ms)), tag_ord(Some(at)));
    }

    #[test]
    fn entry_names_round_trip_through_the_parser() {
        let namespace = Namespace::new("org/app").unwrap();
        let tag = Tag::new("v1.0").unwrap();
        let digest = Digest::sha256(HASH_A).unwrap();
        let at = DateTime::from_timestamp_millis(1_700_000_000_123).unwrap();

        for deletion in [false, true] {
            let key = namespace.tag_entry_path(&tag, tag_ord(Some(at)), deletion, &digest);
            let (_, name) = key.rsplit_once('/').unwrap();
            assert_eq!(
                parse_tag_entry(name),
                Some((tag_ord(Some(at)), deletion, digest.clone())),
                "entry {name:?} must round-trip"
            );
        }

        // Same millisecond, different digests: distinct keys, both parseable.
        let other = Digest::sha256(HASH_B).unwrap();
        assert_ne!(
            namespace.tag_entry_path(&tag, tag_ord(Some(at)), false, &digest),
            namespace.tag_entry_path(&tag, tag_ord(Some(at)), false, &other)
        );
    }

    #[test]
    fn foreign_entry_names_do_not_parse() {
        for name in [
            "",
            &format!("{:016x}.set.sha256", 1_u64),
            &format!("{:08x}.set.sha256.{HASH_A}", 1_u64),
            &format!("{:016x}.mov.sha256.{HASH_A}", 1_u64),
            &format!("{:016x}.set.sha3.{HASH_A}", 1_u64),
            &format!("{:016x}.set.sha256.{}", 1_u64, "z".repeat(64)),
            &format!("{:016x}.set.sha256.{HASH_A}.extra", 1_u64),
        ] {
            assert_eq!(parse_tag_entry(name), None, "name {name:?}");
        }
    }
}
