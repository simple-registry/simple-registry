//! Legacy blob-index shard support. Nothing writes shards any more: readers
//! merge them in as a fallback and scrub converts each one into reference
//! keys, so everything here is read-side and disappears with the last shard.

use std::collections::HashSet;

use bytes::Bytes;

use angos_oci::{Digest, Namespace};
use angos_tx_engine::{StorageError, store::Store};

use crate::registry::{
    Error,
    metadata_store::{BlobIndexOperation, LinkKind},
    path_builder,
};

pub const SHARD_READ_CONCURRENCY: usize = 10;

pub fn decode_blob_index_shard_namespace(file_name: &str) -> String {
    file_name
        .strip_suffix(".json")
        .unwrap_or(file_name)
        .replace("%2F", "/")
        .replace("%25", "%")
}

pub fn apply_blob_index_operations(
    links: &mut HashSet<LinkKind>,
    operations: &[BlobIndexOperation],
) {
    for operation in operations {
        match operation {
            BlobIndexOperation::Insert(link) => {
                links.insert(link.clone());
            }
            BlobIndexOperation::Remove(link) => {
                links.remove(link);
            }
        }
    }
}

pub fn non_empty_links_or_not_found(links: HashSet<LinkKind>) -> Result<HashSet<LinkKind>, Error> {
    if links.is_empty() {
        Err(Error::NotFound)
    } else {
        Ok(links)
    }
}

/// Read one per-namespace shard: its raw bytes plus parsed links, or `None`
/// when absent. A present shard that fails to parse is an error, never an
/// empty set: the reclaim decisions built on this read must fail closed.
pub async fn read_shard(
    store: &Store,
    shard_path: &str,
) -> Result<Option<(Bytes, HashSet<LinkKind>)>, StorageError> {
    match store.object_store().get(shard_path).await {
        Ok(data) => {
            let links: HashSet<LinkKind> = serde_json::from_slice(&data).map_err(|e| {
                StorageError::Backend(format!("corrupt blob-index shard {shard_path}: {e}"))
            })?;
            Ok(Some((Bytes::from(data), links)))
        }
        Err(StorageError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Return `true` when any namespace other than `our_namespace` has a live
/// legacy shard entry in the refs directory. A shard holding an empty link
/// set is not a reference, matching [`MetadataStore::has_blob_references`]:
/// the old write path deleted a shard when its set emptied, so an empty one
/// is a leftover or corrupt artifact and must not pin the blob forever.
///
/// [`MetadataStore::has_blob_references`]: crate::registry::metadata_store::MetadataStore::has_blob_references
pub async fn any_other_namespace_shard_references_blob(
    store: &Store,
    our_namespace: &Namespace,
    digest: &Digest,
) -> Result<bool, Error> {
    let refs_prefix = path_builder::blob_index_refs_dir(digest);
    let mut continuation = None;
    loop {
        let page = store
            .object_store()
            .list(&refs_prefix, 100, continuation)
            .await
            .map_err(Error::from)?;
        for key in &page.items {
            let ns = decode_blob_index_shard_namespace(key);
            if ns == our_namespace.as_ref() {
                continue;
            }
            // Address the shard the way it was written whenever its filename
            // still decodes to a namespace; a name that no longer parses is
            // joined verbatim so a legacy shard is still read, not skipped.
            let shard_path = Namespace::new(&ns).map_or_else(
                |_| format!("{refs_prefix}/{key}"),
                |namespace| path_builder::blob_index_shard_path(digest, &namespace),
            );
            // A shard deleted between the listing and this read is gone, so it
            // holds nothing; a corrupt one errors rather than reading as empty.
            if read_shard(store, &shard_path)
                .await
                .map_err(Error::from)?
                .is_some_and(|(_, links)| !links.is_empty())
            {
                return Ok(true);
            }
        }
        continuation = page.next_token;
        if continuation.is_none() {
            break;
        }
    }
    Ok(false)
}
