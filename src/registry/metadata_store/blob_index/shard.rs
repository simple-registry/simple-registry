//! Legacy blob-index shard support. Nothing writes shards any more: readers
//! merge them in as a fallback and scrub converts each one into reference
//! keys, so everything here is read-side and disappears with the last shard.

use std::{collections::HashSet, sync::Arc};

use bytes::Bytes;

use angos_storage::{Error as StorageError, ObjectStore};

use crate::registry::{Error, metadata_store::LinkKind};

pub const SHARD_READ_CONCURRENCY: usize = 10;

pub fn decode_blob_index_shard_namespace(file_name: &str) -> String {
    file_name
        .strip_suffix(".json")
        .unwrap_or(file_name)
        .replace("%2F", "/")
        .replace("%25", "%")
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
    store: &Arc<dyn ObjectStore>,
    shard_path: &str,
) -> Result<Option<(Bytes, HashSet<LinkKind>)>, StorageError> {
    match store.get(shard_path).await {
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
