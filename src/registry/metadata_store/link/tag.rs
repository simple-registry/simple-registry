//! Tag state as ordered write-once entries.
//!
//! A tag is the set of entries under its [`path_builder::tag_entry_dir`],
//! each named `<ord>.<kind>.<algo>.<hash>` with an inverted-timestamp `<ord>`
//! so a listing yields newest first. Writers only append; last-writer-wins is
//! a property of the key names, so concurrent writers and replicas never
//! contend. A tag with no entries falls back to the legacy `current/link`,
//! which scrub converts; a tombstone entry shadows any legacy link.

use std::collections::HashSet;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use angos_oci::{Digest, MediaType, Namespace, Tag};
use angos_storage::Error as StorageError;

use crate::registry::metadata_store::mutation::Mutation;

use crate::registry::{
    Error,
    metadata_store::{LinkMetadata, MetadataStore},
    path_builder,
};

/// The stored body of one tag entry. The hot path resolves from key names
/// alone; the body carries what the key cannot.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TagEntryBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<MediaType>,
}

/// The resolved winner of a tag's newest entry group.
struct TagWinner {
    ord: u64,
    deletion: bool,
    digest: Digest,
    entry: String,
}

/// The mutation appending one `set` entry. The entry key carries the authored
/// timestamp (truncated to the millisecond the ordinal encodes) and target;
/// the body carries the media type.
pub fn tag_set_mutation(
    namespace: &Namespace,
    tag: &Tag,
    created_at: DateTime<Utc>,
    target: &Digest,
    media_type: Option<MediaType>,
) -> Result<Mutation, serde_json::Error> {
    let key = path_builder::tag_entry_path(
        namespace,
        tag,
        path_builder::tag_ord(Some(created_at)),
        false,
        target,
    );
    let body = serde_json::to_vec(&TagEntryBody { media_type })?;
    Ok(Mutation::Put {
        key,
        body: Bytes::from(body),
    })
}

/// The mutation appending one `del` tombstone. It names the digest the tag
/// held immediately before deletion, which tag history requires.
pub fn tag_del_mutation(
    namespace: &Namespace,
    tag: &Tag,
    created_at: DateTime<Utc>,
    prior_target: &Digest,
    media_type: Option<MediaType>,
) -> Result<Mutation, serde_json::Error> {
    let key = path_builder::tag_entry_path(
        namespace,
        tag,
        path_builder::tag_ord(Some(created_at)),
        true,
        prior_target,
    );
    let body = serde_json::to_vec(&TagEntryBody { media_type })?;
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
    /// tag with no entries falls back to the legacy `current/link`.
    pub async fn resolve_tag(
        &self,
        namespace: &Namespace,
        tag: &Tag,
    ) -> Result<LinkMetadata, Error> {
        match self.resolve_tag_winner(namespace, tag).await? {
            Some(winner) if winner.deletion => Err(Error::NotFound),
            Some(winner) => {
                let entry_path = format!(
                    "{}/{}",
                    path_builder::tag_entry_dir(namespace, tag),
                    winner.entry
                );
                let media_type = match self.object_store().get(&entry_path).await {
                    Ok(body) => serde_json::from_slice::<TagEntryBody>(&body)
                        .ok()
                        .and_then(|body| body.media_type),
                    Err(StorageError::NotFound) => None,
                    Err(e) => return Err(e.into()),
                };
                Ok(LinkMetadata {
                    target: winner.digest,
                    created_at: path_builder::tag_ord_ts(winner.ord),
                    accessed_at: None,
                    referenced_by: HashSet::new(),
                    media_type,
                    descriptor: None,
                })
            }
            None => self.read_legacy_tag_link(namespace, tag).await,
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
                        entry: name.clone(),
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

    /// The tag's advisory last-pull timestamp, from its sibling atime key.
    pub async fn read_tag_access_time(
        &self,
        namespace: &Namespace,
        tag: &Tag,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        let key = path_builder::tag_atime_path(namespace, tag);
        match self.object_store().get(&key).await {
            Ok(raw) => Ok(std::str::from_utf8(&raw)
                .ok()
                .and_then(|text| DateTime::parse_from_rfc3339(text.trim()).ok())
                .map(Into::into)),
            Err(StorageError::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Overwrite the tag's atime key with the current time. Advisory: the
    /// newest arriving timestamp is the correct value, so this is a plain put
    /// with no transaction and no read.
    pub async fn write_tag_access_time(
        &self,
        namespace: &Namespace,
        tag: &Tag,
    ) -> Result<(), Error> {
        let key = path_builder::tag_atime_path(namespace, tag);
        self.object_store()
            .put(&key, Bytes::from(Utc::now().to_rfc3339()))
            .await
            .map_err(Error::from)
    }

    /// Convert one legacy `current/link` into a `set` entry stamped with the
    /// link's recorded `created_at`, then delete the link once it is older
    /// than the grace period (an old-binary writer may still rewrite a young
    /// one in place; a skipped delete waits for the next run). Entry first,
    /// so an interruption loses nothing; both halves are idempotent. An
    /// absent link is a no-op (a racer or an earlier run already converted
    /// it).
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
