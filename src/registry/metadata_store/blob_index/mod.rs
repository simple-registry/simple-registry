//! Cross-namespace blob reference tracking.
//!
//! One write-once, empty reference key per (namespace, link) under
//! [`DigestKeys::blob_ref_dir`] records that a namespace references a blob.
//! Legacy per-namespace JSON shards still merge into every read until scrub
//! finishes converting them ([`shard`]).

use std::collections::{HashMap, HashSet};
use std::pin::pin;
use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use futures_util::{Stream, TryStreamExt};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use angos_oci::{Digest, Namespace};
use angos_storage::{Error as StorageError, ObjectStore, paginated};

use crate::registry::keys::DigestKeys;
use crate::registry::{
    Error,
    metadata_store::{LinkKind, LinksTx, MetadataStore, mutation::Mutation},
    path_builder,
};

pub mod shard;

use self::shard::{
    SHARD_READ_CONCURRENCY, decode_blob_index_shard_namespace, non_empty_links_or_not_found,
    read_shard,
};

/// Keys fetched per page when listing a blob's reference directory.
const REF_LIST_PAGE: u16 = 1000;

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlobIndex {
    pub namespace: HashMap<Namespace, HashSet<LinkKind>>,
}

#[derive(Debug, Clone)]
pub enum BlobIndexOperation {
    Insert(LinkKind),
    Remove(LinkKind),
}

/// The mutation one blob-index operation compiles to. Reference keys are
/// write-once and empty, so nothing is read first.
pub fn ref_mutation(
    namespace: &Namespace,
    digest: &Digest,
    operation: &BlobIndexOperation,
) -> Mutation {
    match operation {
        BlobIndexOperation::Insert(link) => Mutation::Put {
            key: digest.blob_ref_path(namespace, link),
            body: Bytes::new(),
        },
        BlobIndexOperation::Remove(link) => Mutation::Delete {
            key: digest.blob_ref_path(namespace, link),
        },
    }
}

/// `namespace`'s reference entries for `digest`: the `!own` leaf plus the
/// `!r/` subtree.
async fn namespace_ref_entries(
    store: &Arc<dyn ObjectStore>,
    namespace: &Namespace,
    digest: &Digest,
) -> Result<HashSet<LinkKind>, Error> {
    let mut links = HashSet::new();
    let own = digest.blob_ref_own_path(namespace);
    match store.head(&own).await {
        Ok(_) => {
            links.insert(LinkKind::Blob(digest.clone()));
        }
        Err(StorageError::NotFound) => {}
        Err(e) => return Err(e.into()),
    }
    let dir = digest.blob_ref_namespace_dir(namespace);
    let mut token = None;
    loop {
        let page = store.list(&dir, REF_LIST_PAGE, token).await?;
        links.extend(
            page.items
                .iter()
                .filter_map(|entry| digest.parse_blob_ref_entry(entry)),
        );
        token = page.next_token;
        if token.is_none() {
            break;
        }
    }
    Ok(links)
}

/// `namespace`'s reference keys merged with its legacy shard. A corrupt
/// shard fails the read rather than parsing as empty, because reclaim
/// decisions built on this must fail closed.
pub async fn namespace_entries_merged(
    store: &Arc<dyn ObjectStore>,
    namespace: &Namespace,
    digest: &Digest,
) -> Result<HashSet<LinkKind>, Error> {
    let mut links = namespace_ref_entries(store, namespace, digest).await?;
    let shard_path = path_builder::blob_index_shard_path(digest, namespace);
    if let Some(legacy) = read_shard(store, &shard_path).await.map_err(Error::from)? {
        links.extend(legacy);
    }
    Ok(links)
}

impl MetadataStore {
    /// Write or remove the reference key for `digest` in `namespace`.
    /// Idempotent: the key's existence is the whole record.
    #[instrument(skip(self))]
    pub async fn update_blob_index(
        &self,
        namespace: &Namespace,
        digest: &Digest,
        operation: BlobIndexOperation,
    ) -> Result<(), Error> {
        match ref_mutation(namespace, digest, &operation) {
            Mutation::Put { key, body } => self.object_store().put(&key, body).await,
            Mutation::Delete { key } => self.object_store().delete(&key).await,
        }
        .map_err(Error::from)
    }

    /// Whether `namespace` holds the `_own` grant for `digest`, without the
    /// reference listing [`Self::read_blob_index_namespace`] does.
    pub async fn has_own_grant(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<bool, Error> {
        let own = digest.blob_ref_own_path(namespace);
        match self.object_store().head(&own).await {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Revoke `namespace`'s ownership of `digest`, the only reference removal
    /// a writer ever performs. The bytes are the collector's to reclaim once
    /// every reference is stale.
    pub async fn revoke_blob_ownership(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<(), Error> {
        let tx = LinksTx::RevokeBlobOwnership {
            blob: digest,
            ops: vec![BlobIndexOperation::Remove(LinkKind::Blob(digest.clone()))],
        };
        self.execute_links_tx(namespace, &[], tx).await.map(|_| ())
    }

    /// Stream each present shard under `refs_dir` as its relative filename
    /// plus raw body. A shard deleted between listing and read is dropped;
    /// parsing is the caller's, so each picks its own empty-shard policy.
    fn stream_shards<'a>(
        &'a self,
        refs_dir: &'a str,
    ) -> impl Stream<Item = Result<(String, Vec<u8>), Error>> + 'a {
        paginated(move |token| async move {
            let page = self
                .object_store()
                .list_children(refs_dir, 1000, token, None)
                .await?;
            Ok((page.objects, page.next_token))
        })
        .map_ok(move |obj| async move {
            let shard_path = format!("{refs_dir}/{obj}");
            match self.object_store().get(&shard_path).await {
                Ok(data) => Ok(Some((obj, data))),
                Err(StorageError::NotFound) => Ok(None),
                Err(e) => Err(Error::from(e)),
            }
        })
        .try_buffer_unordered(SHARD_READ_CONCURRENCY)
        .try_filter_map(|shard| async move { Ok(shard) })
    }

    #[instrument(skip(self))]
    pub async fn read_blob_index(&self, digest: &Digest) -> Result<BlobIndex, Error> {
        let mut index = BlobIndex::default();
        let dir = digest.blob_ref_dir();
        let mut token = None;
        loop {
            let page = self.object_store().list(&dir, REF_LIST_PAGE, token).await?;
            for key in &page.items {
                let Some((raw, link)) = digest.parse_blob_ref(key) else {
                    continue;
                };
                let Ok(namespace) = Namespace::new(&raw) else {
                    continue;
                };
                index.namespace.entry(namespace).or_default().insert(link);
            }
            token = page.next_token;
            if token.is_none() {
                break;
            }
        }

        let refs_dir = path_builder::blob_index_refs_dir(digest);
        let mut shards = pin!(self.stream_shards(&refs_dir));
        while let Some((obj, data)) = shards.try_next().await? {
            let (Ok(links), Ok(namespace)) = (
                serde_json::from_slice::<HashSet<LinkKind>>(&data),
                Namespace::new(&decode_blob_index_shard_namespace(&obj)),
            ) else {
                continue;
            };
            if !links.is_empty() {
                index.namespace.entry(namespace).or_default().extend(links);
            }
        }

        if index.namespace.is_empty() {
            return Err(Error::NotFound);
        }
        Ok(index)
    }

    #[instrument(skip(self))]
    pub async fn read_blob_index_namespace(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<HashSet<LinkKind>, Error> {
        let links = namespace_entries_merged(self.object_store(), namespace, digest).await?;
        non_empty_links_or_not_found(links)
    }

    /// Whether the link behind a reference entry still backs it: a tag,
    /// revision, or referrer while it resolves to `blob`, a per-referrer
    /// entry while the referring manifest's revision resolves, every other
    /// (legacy tracked) kind while a manifest in its recorded referrer set
    /// resolves. Reads bypass the cache so it cannot mask a live reference.
    pub async fn reference_backed(
        &self,
        namespace: &Namespace,
        link: &LinkKind,
        blob: &Digest,
    ) -> Result<bool, Error> {
        match link {
            LinkKind::Tag(_) | LinkKind::Digest(_) | LinkKind::Referrer { .. } => {
                match self.read_link_reference(namespace, link).await {
                    Ok(metadata) => Ok(&metadata.target == blob),
                    Err(Error::NotFound) => Ok(false),
                    Err(e) => Err(e),
                }
            }
            LinkKind::ReferencedBy(referrer) => {
                let revision = LinkKind::Digest(referrer.clone());
                match self.read_link_reference(namespace, &revision).await {
                    Ok(_) => Ok(true),
                    Err(Error::NotFound) => Ok(false),
                    Err(e) => Err(e),
                }
            }
            _ => {
                // Legacy tracked entries: the link file alone is not
                // liveness, because a manifest delete leaves it in place.
                let metadata = match self.read_link_reference(namespace, link).await {
                    Ok(metadata) => metadata,
                    Err(Error::NotFound) => return Ok(false),
                    Err(e) => return Err(e),
                };
                for referrer in &metadata.referenced_by {
                    match self
                        .read_link_reference(namespace, &LinkKind::Digest(referrer.clone()))
                        .await
                    {
                        Ok(_) => return Ok(true),
                        Err(Error::NotFound) => {}
                        Err(e) => return Err(e),
                    }
                }
                Ok(false)
            }
        }
    }

    /// Collector-side liveness over the reference index: `_own` pins
    /// unconditionally, an unconverted legacy shard pins, and any other key
    /// pins while it is younger than the grace period or its backing link
    /// resolves. The blob-data age gate is the caller's, since the bytes live
    /// in the blob store.
    pub async fn blob_references_live(&self, digest: &Digest) -> Result<bool, Error> {
        let dir = digest.blob_ref_dir();
        let mut token = None;
        loop {
            let page = self.object_store().list(&dir, 1000, token).await?;
            for key in &page.items {
                let Some((raw, link)) = digest.parse_blob_ref(key) else {
                    continue;
                };
                if matches!(link, LinkKind::Blob(_)) {
                    return Ok(true);
                }
                let full_key = format!("{dir}/{key}");
                match self.object_store().head(&full_key).await {
                    Ok(meta) => {
                        // No timestamp to gate on, so never guess in favour
                        // of deletion.
                        let Some(modified) = meta.last_modified else {
                            return Ok(true);
                        };
                        let age = Utc::now().signed_duration_since(modified);
                        if age.num_seconds() < i64::try_from(self.gc_grace_secs).unwrap_or(i64::MAX)
                        {
                            return Ok(true);
                        }
                    }
                    Err(StorageError::NotFound) => continue,
                    Err(e) => return Err(e.into()),
                }
                let Ok(namespace) = Namespace::new(&raw) else {
                    // A key angos cannot address is left to quarantine, and
                    // pins until then.
                    return Ok(true);
                };
                if self.reference_backed(&namespace, &link, digest).await? {
                    return Ok(true);
                }
            }
            token = page.next_token;
            if token.is_none() {
                break;
            }
        }
        // Any non-empty legacy shard pins the blob until scrub converts it.
        let refs_dir = path_builder::blob_index_refs_dir(digest);
        let mut shards = pin!(self.stream_shards(&refs_dir));
        while let Some((_, data)) = shards.try_next().await? {
            match serde_json::from_slice::<HashSet<LinkKind>>(&data) {
                Ok(links) if links.is_empty() => {}
                // A corrupt shard pins: fail closed.
                _ => return Ok(true),
            }
        }
        Ok(false)
    }

    /// Delete every reference key and legacy shard of a reclaimed blob. Only
    /// the collector calls this, and only after the marker protocol has
    /// fenced the blob-data delete.
    pub async fn delete_blob_references(&self, digest: &Digest) -> Result<(), Error> {
        for prefix in [
            digest.blob_ref_dir(),
            path_builder::blob_index_refs_dir(digest),
        ] {
            self.object_store().delete_prefix(&prefix).await?;
        }
        Ok(())
    }
}
