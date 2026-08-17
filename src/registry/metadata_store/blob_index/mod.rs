//! The blob-index domain: cross-namespace blob reference tracking.
//!
//! One write-once, empty reference key per (namespace, link) under
//! [`path_builder::blob_ref_dir`] records that a namespace references a blob.
//! Writers only touch these keys; the legacy per-namespace JSON shards under
//! `v2/blobs/.../refs/` are still merged into every read as a fallback until
//! scrub finishes converting them ([`shard`]).

use std::collections::{HashMap, HashSet};
use std::pin::pin;

use bytes::Bytes;
use chrono::Utc;
use futures_util::{Stream, TryStreamExt};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use angos_oci::{Digest, Namespace};
use angos_storage::paginated;
use angos_tx_engine::{StorageError, store::Store, transaction::Mutation};

use crate::registry::{
    Error,
    metadata_store::{LinkKind, LinksTx, MetadataStore},
    path_builder,
};

pub mod shard;

use self::shard::{
    SHARD_READ_CONCURRENCY, decode_blob_index_shard_namespace, non_empty_links_or_not_found,
    read_shard,
};

/// Keys fetched per page when listing a blob's reference directory.
const REF_LIST_PAGE: u16 = 1000;

// Domain types

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
/// write-once and empty, so an insert is an unconditional put and a removal
/// an unconditional delete; nothing is read first.
pub fn ref_mutation(
    namespace: &Namespace,
    digest: &Digest,
    operation: &BlobIndexOperation,
) -> Mutation {
    match operation {
        BlobIndexOperation::Insert(link) => Mutation::Put {
            key: path_builder::blob_ref_path(digest, namespace, link),
            body: Bytes::new(),
            expected: None,
        },
        BlobIndexOperation::Remove(link) => Mutation::Delete {
            key: path_builder::blob_ref_path(digest, namespace, link),
            expected: None,
        },
    }
}

/// `namespace`'s reference entries for `digest` under the new key shape: the
/// `!own` leaf plus the `!r/` subtree.
pub async fn namespace_ref_entries(
    store: &Store,
    namespace: &Namespace,
    digest: &Digest,
) -> Result<HashSet<LinkKind>, Error> {
    let mut links = HashSet::new();
    let own = path_builder::blob_ref_own_path(digest, namespace);
    match store.object_store().head(&own).await {
        Ok(_) => {
            links.insert(LinkKind::Blob(digest.clone()));
        }
        Err(StorageError::NotFound) => {}
        Err(e) => return Err(e.into()),
    }
    let dir = path_builder::blob_ref_namespace_dir(digest, namespace);
    let mut token = None;
    loop {
        let page = store
            .object_store()
            .list(&dir, REF_LIST_PAGE, token)
            .await?;
        links.extend(
            page.items
                .iter()
                .filter_map(|entry| path_builder::parse_blob_ref_entry(digest, entry)),
        );
        token = page.next_token;
        if token.is_none() {
            break;
        }
    }
    Ok(links)
}

/// `namespace`'s merged entries: the new reference keys plus its legacy
/// shard. A corrupt shard fails the read rather than parsing as empty, since
/// reclaim decisions built on this must fail closed.
pub async fn namespace_entries_merged(
    store: &Store,
    namespace: &Namespace,
    digest: &Digest,
) -> Result<HashSet<LinkKind>, Error> {
    let mut links = namespace_ref_entries(store, namespace, digest).await?;
    let shard_path = path_builder::blob_index_shard_path(digest, namespace);
    if let Some((_, legacy)) = read_shard(store, &shard_path).await.map_err(Error::from)? {
        links.extend(legacy);
    }
    Ok(links)
}

// Store-backed methods

impl MetadataStore {
    /// Write the reference key for `digest` in `namespace` (insert), or
    /// remove it. Idempotent: the key's existence is the whole record.
    #[instrument(skip(self))]
    pub async fn update_blob_index(
        &self,
        namespace: &Namespace,
        digest: &Digest,
        operation: BlobIndexOperation,
    ) -> Result<(), Error> {
        match ref_mutation(namespace, digest, &operation) {
            Mutation::Put { key, body, .. } => self.store().object_store().put(&key, body).await,
            Mutation::Delete { key, .. } => self.store().object_store().delete(&key).await,
            // `ref_mutation` only produces puts and deletes.
            _ => Ok(()),
        }
        .map_err(Error::from)
    }

    /// Revoke `namespace`'s ownership of `digest`: one delete of the `_own`
    /// key, the only reference removal a writer ever performs. The bytes are
    /// the collector's to reclaim once every reference is stale.
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

    /// Stream each present shard under `refs_dir` as its relative filename plus
    /// raw body: shard names page off the listing while up to
    /// [`SHARD_READ_CONCURRENCY`] bodies read concurrently. A shard deleted
    /// between listing and read is dropped; parsing is left to the caller so
    /// each derives its own decode and empty-shard policy.
    fn stream_shards<'a>(
        &'a self,
        refs_dir: &'a str,
    ) -> impl Stream<Item = Result<(String, Vec<u8>), Error>> + 'a {
        paginated(move |token| async move {
            let page = self
                .store()
                .object_store()
                .list_children(refs_dir, 1000, token, None)
                .await?;
            Ok((page.objects, page.next_token))
        })
        .map_ok(move |obj| async move {
            let shard_path = format!("{refs_dir}/{obj}");
            match self.store().object_store().get(&shard_path).await {
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
        let dir = path_builder::blob_ref_dir(digest);
        let mut token = None;
        loop {
            let page = self
                .store()
                .object_store()
                .list(&dir, REF_LIST_PAGE, token)
                .await?;
            for key in &page.items {
                // Foreign key shapes and invalid namespaces are skipped, the
                // way undecodable shard names always were.
                let Some((raw, link)) = path_builder::parse_blob_ref(digest, key) else {
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
        let links = namespace_entries_merged(self.store(), namespace, digest).await?;
        non_empty_links_or_not_found(links)
    }

    /// Whether the link behind a reference entry still backs it: a tag,
    /// revision, or referrer while it resolves to `blob`, every other kind
    /// while its link file exists. Reads are raw, so a cache cannot mask a
    /// live reference.
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
            _ => {
                let link_key = path_builder::link_path(link, namespace);
                match self.store().object_store().head(&link_key).await {
                    Ok(_) => Ok(true),
                    Err(StorageError::NotFound) => Ok(false),
                    Err(e) => Err(e.into()),
                }
            }
        }
    }

    /// Collector-side liveness over the reference index: `_own` pins
    /// unconditionally, an unconverted legacy shard pins, and any other key
    /// pins while it is younger than the grace period or its backing link
    /// still resolves. The blob-data age gate is the caller's, since the
    /// bytes live in the blob store.
    pub async fn blob_references_live(&self, digest: &Digest) -> Result<bool, Error> {
        let dir = path_builder::blob_ref_dir(digest);
        let mut token = None;
        loop {
            let page = self.store().object_store().list(&dir, 1000, token).await?;
            for key in &page.items {
                let Some((raw, link)) = path_builder::parse_blob_ref(digest, key) else {
                    continue;
                };
                if matches!(link, LinkKind::Blob(_)) {
                    return Ok(true);
                }
                let full_key = format!("{dir}/{key}");
                match self.store().object_store().head(&full_key).await {
                    Ok(meta) => {
                        // No timestamp to gate on: live, never guess in
                        // favour of deletion.
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
    /// the collector calls this, after the marker protocol has fenced the
    /// blob-data delete.
    pub async fn delete_blob_references(&self, digest: &Digest) -> Result<(), Error> {
        for prefix in [
            path_builder::blob_ref_dir(digest),
            path_builder::blob_index_refs_dir(digest),
        ] {
            self.store().object_store().delete_prefix(&prefix).await?;
        }
        Ok(())
    }
}
