//! Tag state as ordered write-once entries.
//!
//! A tag is the set of entries under its [`path_builder::tag_entry_dir`],
//! each named `<ord>.<kind>.<algo>.<hash>` with an inverted-timestamp `<ord>`
//! so a listing yields newest first. Writers only append; last-writer-wins is
//! a property of the key names, so concurrent writers and replicas never
//! contend. A tag with no entries falls back to the legacy `current/link`,
//! which scrub converts; a tombstone entry shadows any legacy link.

use std::collections::{BTreeMap, HashSet};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use angos_oci::{Digest, MediaType, Namespace, Tag};
use angos_storage::Error as StorageError;

use crate::registry::metadata_store::{access_time::put_access_entry, mutation::Mutation};

use crate::registry::{
    Error,
    metadata_store::{LinkMetadata, MetadataStore},
    path_builder,
};

/// The stored body of one tag entry: the descriptor fields a future tag
/// history needs (distribution-spec PR 606). The hot path resolves from key
/// names alone; the body carries what the key cannot.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TagEntryBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<MediaType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// Annotation keys under the distribution spec's reserved prefix never
/// persist into a tag entry.
const RESERVED_ANNOTATION_PREFIX: &str = "org.opencontainers.distribution";

/// The manifest annotations a `set` entry stores: the pushed set minus the
/// reserved-prefix keys, `None` when nothing survives.
fn persisted_annotations(
    annotations: Option<BTreeMap<String, String>>,
) -> Option<BTreeMap<String, String>> {
    let filtered: BTreeMap<String, String> = annotations?
        .into_iter()
        .filter(|(key, _)| !key.starts_with(RESERVED_ANNOTATION_PREFIX))
        .collect();
    (!filtered.is_empty()).then_some(filtered)
}

/// The resolved winner of a tag's newest entry group. Its fields rebuild the
/// entry key via [`path_builder::tag_entry_path`].
struct TagWinner {
    ord: u64,
    deletion: bool,
    digest: Digest,
}

/// The mutation appending one `set` entry. The entry key carries the authored
/// timestamp (truncated to the millisecond the ordinal encodes) and target;
/// the body carries the manifest's descriptor fields, reserved-prefix
/// annotations filtered out.
pub fn tag_set_mutation(
    namespace: &Namespace,
    tag: &Tag,
    created_at: DateTime<Utc>,
    target: &Digest,
    media_type: Option<MediaType>,
    size: Option<u64>,
    annotations: Option<BTreeMap<String, String>>,
) -> Result<Mutation, serde_json::Error> {
    let key = path_builder::tag_entry_path(
        namespace,
        tag,
        path_builder::tag_ord(Some(created_at)),
        false,
        target,
    );
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

/// The mutation appending one `del` tombstone. It names the digest the tag
/// held immediately before deletion and copies the superseded winner's
/// descriptor `body`, which tag history requires.
pub fn tag_del_mutation(
    namespace: &Namespace,
    tag: &Tag,
    created_at: DateTime<Utc>,
    prior_target: &Digest,
    body: &TagEntryBody,
) -> Result<Mutation, serde_json::Error> {
    let key = path_builder::tag_entry_path(
        namespace,
        tag,
        path_builder::tag_ord(Some(created_at)),
        true,
        prior_target,
    );
    let body = serde_json::to_vec(body)?;
    Ok(Mutation::Put {
        key,
        body: Bytes::from(body),
    })
}

impl MetadataStore {
    /// Resolve `tag` to link-shaped metadata. The complete newest entry group
    /// decides (highest digest wins the same-millisecond tie, and a deletion
    /// does not beat an equal-timestamped push of the same digest); a
    /// tombstone winner reads as `NotFound` and shadows any legacy link; a
    /// tag with no entries falls back to the legacy `current/link`. The
    /// winner comes from key names alone, so `media_type` is `None`: serving
    /// paths take it from the revision record they read anyway, and only
    /// [`Self::read_tag_winner_body`] pays for the entry body.
    pub async fn resolve_tag(
        &self,
        namespace: &Namespace,
        tag: &Tag,
    ) -> Result<LinkMetadata, Error> {
        match self.resolve_tag_winner(namespace, tag).await? {
            Some(winner) if winner.deletion => Err(Error::NotFound),
            Some(winner) => Ok(LinkMetadata {
                target: winner.digest,
                created_at: path_builder::tag_ord_ts(winner.ord),
                accessed_at: None,
                referenced_by: HashSet::new(),
                media_type: None,
                descriptor: None,
            }),
            None => self.read_legacy_tag_link(namespace, tag).await,
        }
    }

    /// Targeted read of the resolved winner's stored entry body, for the one
    /// consumer that needs it (the tombstone copies its descriptor fields). A
    /// tag answered by the legacy link has no entry; its recorded media type
    /// stands in.
    pub async fn read_tag_winner_body(
        &self,
        namespace: &Namespace,
        tag: &Tag,
        metadata: &LinkMetadata,
    ) -> Result<TagEntryBody, Error> {
        let entry_path = path_builder::tag_entry_path(
            namespace,
            tag,
            path_builder::tag_ord(metadata.created_at),
            false,
            &metadata.target,
        );
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
        let dir = path_builder::tag_entry_dir(namespace, tag);
        let mut group: Vec<TagWinner> = Vec::new();
        let mut token = None;
        'pages: loop {
            let page = self.object_store().list(&dir, 1000, token).await?;
            for name in &page.items {
                let Some((ord, deletion, digest)) = path_builder::parse_tag_entry(name) else {
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

    /// Test-only backend write of tag state: one `set` entry carrying
    /// `metadata`'s target, timestamp, and media type, as a sibling replica's
    /// write would land it.
    #[cfg(test)]
    pub async fn write_tag_state(
        &self,
        namespace: &Namespace,
        tag: &Tag,
        metadata: &LinkMetadata,
    ) -> Result<(), Error> {
        let key = path_builder::tag_entry_path(
            namespace,
            tag,
            path_builder::tag_ord(metadata.created_at),
            false,
            &metadata.target,
        );
        let body = serde_json::to_vec(&TagEntryBody {
            media_type: metadata.media_type.clone(),
            ..TagEntryBody::default()
        })?;
        self.object_store()
            .put(&key, Bytes::from(body))
            .await
            .map_err(Error::from)
    }

    /// Raw read of the legacy `current/link`, the fallback for a tag with no
    /// entries.
    async fn read_legacy_tag_link(
        &self,
        namespace: &Namespace,
        tag: &Tag,
    ) -> Result<LinkMetadata, Error> {
        let link_path = format!(
            "{}/current/link",
            path_builder::manifest_tag_dir(namespace, tag.as_ref())
        );
        match self.object_store().get(&link_path).await {
            Ok(data) => serde_json::from_slice(&data).map_err(|e| Error::Internal(e.to_string())),
            Err(StorageError::NotFound) => Err(Error::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// The tag's advisory last-pull timestamp: its newest access entry, or
    /// the legacy sibling atime key when no entries exist.
    pub async fn read_tag_access_time(
        &self,
        namespace: &Namespace,
        tag: &Tag,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        self.newest_access_time(
            &path_builder::tag_atime_entry_dir(namespace, tag),
            &path_builder::tag_atime_path(namespace, tag),
        )
        .await
    }

    /// Append one access entry to the tag's atime directory, recording
    /// `client` and the current time. A plain put with no transaction and no
    /// read.
    pub async fn write_tag_access_time(
        &self,
        namespace: &Namespace,
        tag: &Tag,
        client: &str,
    ) -> Result<(), Error> {
        put_access_entry(
            self.object_store(),
            &path_builder::tag_atime_entry_dir(namespace, tag),
            client,
        )
        .await
    }

    /// Convert one legacy `current/link` into a `set` entry stamped with the
    /// link's recorded `created_at`, then delete the link once it is older
    /// than the grace period (an old-binary writer may still rewrite a young
    /// one in place; a skipped delete waits for the next run). Entry first
    /// and both halves idempotent, so an interruption or an absent link
    /// loses nothing.
    pub async fn convert_legacy_tag_link(
        &self,
        namespace: &Namespace,
        tag: &Tag,
    ) -> Result<(), Error> {
        let metadata = match self.read_legacy_tag_link(namespace, tag).await {
            Ok(metadata) => metadata,
            Err(Error::NotFound) => return Ok(()),
            Err(e) => return Err(e),
        };
        let entry_key = path_builder::tag_entry_path(
            namespace,
            tag,
            path_builder::tag_ord(metadata.created_at),
            false,
            &metadata.target,
        );
        let body = serde_json::to_vec(&TagEntryBody {
            media_type: metadata.media_type,
            ..TagEntryBody::default()
        })?;
        self.object_store()
            .put(&entry_key, Bytes::from(body))
            .await?;
        let link_path = format!(
            "{}/current/link",
            path_builder::manifest_tag_dir(namespace, tag.as_ref())
        );
        match self.object_store().head(&link_path).await {
            Ok(meta) => {
                // A missing timestamp reads as young: never delete a file an
                // old-shape writer may just have rewritten.
                let age = meta
                    .last_modified
                    .map_or(0, |m| Utc::now().signed_duration_since(m).num_seconds());
                if age >= i64::try_from(self.gc_grace_secs).unwrap_or(i64::MAX) {
                    self.object_store().delete(&link_path).await?;
                }
            }
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        self.cache_invalidate(namespace, &super::LinkKind::Tag(tag.clone()))
            .await;
        Ok(())
    }
}
