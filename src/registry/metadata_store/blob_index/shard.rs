//! Blob-index shard operations in two layers: a pure in-memory layer
//! (`apply_blob_index_operations` and friends, no I/O) and a store
//! read-modify-write layer that turns applied [`BlobIndexOperation`]s into
//! transaction reads + mutations. Both the link-transaction planner and the
//! standalone shard writers in [`super`] build on these.

use std::collections::HashSet;

use bytes::Bytes;
use serde_json::Value;

use angos_oci::{Digest, Namespace};
use angos_tx_engine::{
    StorageError,
    store::Store,
    transaction::{Mutation, TransactionBuilder},
};

use crate::registry::{
    Error,
    metadata_store::{BlobIndexOperation, LinkKind},
    path_builder,
};

// Pure shard operations (in-memory; no I/O)

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

// Store read-modify-write

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

/// Fold `ops` into the disjoint `(add, remove)` link sets a [`Mutation::MergeSet`]
/// carries, applying last-op-wins per link so the result matches an ordered
/// [`apply_blob_index_operations`] over the same ops.
fn ops_to_merge_delta(
    ops: &[BlobIndexOperation],
) -> Result<(Vec<Value>, Vec<Value>), serde_json::Error> {
    let mut add: Vec<LinkKind> = Vec::new();
    let mut remove: Vec<LinkKind> = Vec::new();
    for op in ops {
        match op {
            BlobIndexOperation::Insert(link) => {
                remove.retain(|existing| existing != link);
                if !add.contains(link) {
                    add.push(link.clone());
                }
            }
            BlobIndexOperation::Remove(link) => {
                add.retain(|existing| existing != link);
                if !remove.contains(link) {
                    remove.push(link.clone());
                }
            }
        }
    }
    let add = add
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    let remove = remove
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    Ok((add, remove))
}

/// Append the shard mutation for `ops` to `builder` as an idempotent
/// [`Mutation::MergeSet`], or leave `builder` untouched when `ops` net to
/// nothing.
///
/// Pass `existing` only when a decision in this transaction was taken on those
/// bytes: it joins the shard to the read set, so a racing write fails prepare
/// and the decision is re-taken rather than committed on stale evidence. A merge
/// on its own needs no read. It carries a delta, not a body, so a racing write
/// costs it one re-read inside [`Mutation::MergeSet`] instead of aborting the
/// whole transaction, and two pushes sharing a base layer stop colliding on the
/// layers they have in common.
pub fn append_shard_ops(
    shard_path: String,
    existing: Option<Bytes>,
    ops: &[BlobIndexOperation],
    builder: TransactionBuilder,
) -> Result<TransactionBuilder, serde_json::Error> {
    let (add, remove) = ops_to_merge_delta(ops)?;
    if add.is_empty() && remove.is_empty() {
        return Ok(builder);
    }
    let builder = match existing {
        Some(raw) => builder.read(shard_path.clone(), raw),
        None => builder,
    };
    Ok(builder.mutation(Mutation::MergeSet {
        key: shard_path,
        add,
        remove,
    }))
}

/// Append the merge mutation for `digest`/`namespace`'s shard to `builder`,
/// reading nothing: the delta stands on its own.
pub fn append_shard_merge(
    namespace: &Namespace,
    digest: &Digest,
    ops: &[BlobIndexOperation],
    builder: TransactionBuilder,
) -> Result<TransactionBuilder, Error> {
    let shard_path = path_builder::blob_index_shard_path(digest, namespace);
    append_shard_ops(shard_path, None, ops, builder).map_err(Error::from)
}

/// Return `true` when any namespace other than `our_namespace` has a live
/// shard entry in the refs directory. A shard holding an empty link set is not
/// a reference, matching [`MetadataStore::has_blob_references`]: emptying a
/// shard deletes it, so an empty one is a legacy or corrupt artifact and must
/// not pin the blob forever.
pub async fn any_other_namespace_references_blob(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::metadata_store::LinkKind;
    use angos_oci::Tag;

    fn digest() -> Digest {
        Digest::try_from(format!("sha256:{}", "a".repeat(64)).as_str()).expect("digest")
    }

    fn namespace() -> Namespace {
        Namespace::new("repo").expect("namespace")
    }

    fn insert_op() -> [BlobIndexOperation; 1] {
        [BlobIndexOperation::Insert(LinkKind::Tag(
            Tag::new("v1").expect("tag"),
        ))]
    }

    /// A merge stands on its own delta, so it must not join the shard to the
    /// read set. Reading it there made two pushes conflict over every base layer
    /// their images share, and cost a round trip per layer to do it.
    #[test]
    fn a_bare_merge_reads_nothing() {
        let tx = append_shard_merge(
            &namespace(),
            &digest(),
            &insert_op(),
            TransactionBuilder::new(),
        )
        .expect("merge")
        .build();

        assert!(
            tx.reads.is_empty(),
            "a merge must not join its shard to the read set, got {:?}",
            tx.reads
        );
        assert_eq!(tx.mutations.len(), 1);
        assert!(matches!(tx.mutations[0], Mutation::MergeSet { .. }));
    }

    /// A decision taken on the shard bytes still has to be validated at commit,
    /// so passing them keeps the read that a racing write fails.
    #[test]
    fn a_decision_backed_merge_keeps_its_read() {
        let shard_path = path_builder::blob_index_shard_path(&digest(), &namespace());
        let tx = append_shard_ops(
            shard_path.clone(),
            Some(Bytes::from_static(br#"["tag:v0"]"#)),
            &insert_op(),
            TransactionBuilder::new(),
        )
        .expect("merge")
        .build();

        assert_eq!(
            tx.reads.iter().map(|read| &read.key).collect::<Vec<_>>(),
            vec![&shard_path],
            "the bytes a decision was taken on must be read-set validated"
        );
    }
}
