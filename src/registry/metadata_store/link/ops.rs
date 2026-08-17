//! The consolidated link-write planner.
//!
//! [`MetadataStore::execute_links_tx`] is the single planner behind every
//! public write method (`update_links`, `delete_links`, `store_manifest`,
//! `delete_manifest`, `revoke_blob_ownership`): each passes a [`LinksTx`]
//! kind, and the planner turns it into ordered waves of unconditional
//! single-object writes. The wave boundaries are load-bearing: reference keys
//! land before the collector check, the revision record (the commit point)
//! lands before anything that makes it reachable, and a crash between waves
//! leaves only over-approximated references or a tagless revision, both
//! legal. Single-link primitives live in [`super::storage`].

use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::future::join_all;
use tracing::warn;

use angos_oci::{Descriptor, Digest, MediaType, Namespace};
use angos_tx_engine::{StorageError, error::Error as TxError, store::Store, transaction::Mutation};

use crate::registry::{
    Error,
    metadata_store::{
        BlobIndexOperation, LinkKind, LinkMetadata, LinkOperation, MetadataStore, ReferencePolicy,
        blob_index::{namespace_entries_merged, ref_mutation},
        link::record::{referrer_set_mutation, revision_set_mutation},
        link::tag::{tag_del_mutation, tag_set_mutation},
    },
    path_builder,
};

// Consolidated transaction planner

/// The kind of link transaction the planner runs: one variant per public entry
/// point, each carrying exactly the blob-data / blob-index side effects and
/// timestamps that operation needs. Modelling it as an enum (not a struct of
/// optional fields) makes invalid combinations unrepresentable.
pub enum LinksTx<'a> {
    /// Plain link create/delete batch (`update_links`): no blob-data or
    /// blob-index side effects and no replication timestamps.
    UpdateLinks,
    /// Link delete batch carrying a replicated delete's `source_ts` for the
    /// last-writer-wins gate (`delete_links`); `None` is a plain local delete.
    /// Unlike [`Self::DeleteManifest`] it does no blob-data reclamation.
    DeleteLinks { source_ts: Option<DateTime<Utc>> },
    /// `store_manifest`: the link writes for a manifest push. The manifest
    /// blob-data is written separately to the blob store by the registry before
    /// this runs. `created_at` stamps new link metadata; a replicated write
    /// passes the author's `source_ts` for LWW. `reference_policy` governs
    /// newly-referenced digests the namespace does not own: Strict rejects the
    /// push, Permissive drops the unowned link, Trusted grants blindly. The
    /// caller's `blob-data:{digest}` lock keeps the ownership read from racing
    /// a concurrent reclaim.
    StoreManifest {
        created_at: Option<DateTime<Utc>>,
        reference_policy: ReferencePolicy,
    },
    /// `delete_manifest`: removes the links and reports via `reclaim_blob`
    /// whether the blob became unreferenced (the namespace's entries empty out
    /// and no other namespace references it), leaving the blob-data reclaim to
    /// the caller.
    /// `source_ts` gates each deleted tag via LWW; the caller's
    /// `blob-data:{digest}` lock keeps the unreferenced-check from racing a
    /// concurrent grant.
    DeleteManifest { source_ts: Option<DateTime<Utc>> },
    /// `revoke_blob_ownership`: removes `namespace`'s ownership entry and
    /// reports via `reclaim_blob` whether the blob became unreferenced. The
    /// caller holds the `blob-data:{digest}` lock across the call and reclaims
    /// the blob-data from the blob store.
    RevokeBlobOwnership {
        blob: &'a Digest,
        ops: Vec<BlobIndexOperation>,
    },
}

impl<'a> LinksTx<'a> {
    /// Direct blob-index ops applied alongside the link-derived ops.
    fn blob_index_ops(&self) -> Option<(&'a Digest, &[BlobIndexOperation])> {
        match self {
            LinksTx::RevokeBlobOwnership { blob, ops } => Some((*blob, ops.as_slice())),
            _ => None,
        }
    }

    /// Creation timestamp stamped on newly-written link metadata (`None` =
    /// stamp the current time).
    fn created_at(&self) -> Option<DateTime<Utc>> {
        match self {
            LinksTx::StoreManifest { created_at, .. } => *created_at,
            _ => None,
        }
    }

    /// Reference policy of a manifest push; `None` for other transaction kinds.
    fn reference_policy(&self) -> Option<ReferencePolicy> {
        match self {
            LinksTx::StoreManifest {
                reference_policy, ..
            } => Some(*reference_policy),
            _ => None,
        }
    }

    /// Author timestamp of a replicated delete, gating each deleted tag via LWW.
    fn delete_source_ts(&self) -> Option<DateTime<Utc>> {
        match self {
            LinksTx::DeleteLinks { source_ts } | LinksTx::DeleteManifest { source_ts, .. } => {
                *source_ts
            }
            _ => None,
        }
    }

    /// Whether this transaction touches blob-data or the blob-index beyond its
    /// link operations, so the empty-no-op short-circuit must not fire.
    fn has_blob_side_effects(&self) -> bool {
        !matches!(self, LinksTx::UpdateLinks | LinksTx::DeleteLinks { .. })
    }
}

/// Data captured from a successful link-transaction attempt, used for
/// post-apply cache/cleanup steps outside the engine lock.
#[derive(Default)]
struct LinksTxCaptured {
    /// Link writes that were committed (both tracked and non-tracked creates,
    /// plus tracked deletes where references remain).
    written_links: Vec<(LinkKind, LinkMetadata)>,
    /// Links that were fully removed.
    deleted_links: Vec<LinkKind>,
    /// Prior target per `Create` op's link (`None` = absent), as read by the
    /// committed attempt.
    prior_targets: Vec<(LinkKind, Option<Digest>)>,
    /// `Some(message)` when the attempt's last-writer-wins guard rejected the
    /// write; the attempt committed an empty transaction and the caller maps
    /// this to [`Error::ReplicationSuperseded`].
    superseded: Option<String>,
    /// `Some(digest)` when a strict push referenced a digest the namespace
    /// held no entry for at plan time; the plan is empty and the caller maps
    /// this to [`Error::ManifestBlobUnknown`].
    missing_reference: Option<Digest>,
}

/// Prior link state captured by a committed link transaction. The retry loop
/// re-reads each `Create` op's link on every attempt and the commit validates
/// those exact bytes, so this is the state the commit was actually validated
/// against, never a stale pre-write read.
#[derive(Default)]
pub struct LinksCommit {
    /// Prior target per `Create` op's link; `None` = the link did not exist.
    pub prior_targets: Vec<(LinkKind, Option<Digest>)>,
}

impl LinksCommit {
    /// Whether the commit changed `link`: it was absent or pointed at a
    /// different digest before. Fails open (`true`) when the transaction had
    /// no `Create` op for `link`, so a genuine write is never suppressed.
    #[must_use]
    pub fn changed(&self, link: &LinkKind, target: &Digest) -> bool {
        self.prior_targets
            .iter()
            .find(|(l, _)| l == link)
            .is_none_or(|(_, prior)| prior.as_ref() != Some(target))
    }
}

/// One operation's snapshot from the single per-attempt read pass. Field
/// types mirror the borrows of the originating [`LinkOperation`], so the planning
/// phases can pass these around without re-reading.
enum OpSnapshot<'a> {
    /// A create with the link's current target (`None` = the link does not
    /// exist).
    Create {
        link: &'a LinkKind,
        target: &'a Digest,
        old_target: Option<Digest>,
        referrer: &'a Option<Digest>,
        media_type: &'a Option<MediaType>,
        descriptor: &'a Option<Box<Descriptor>>,
    },
    /// A delete with the link's currently-stored metadata (`None` = already
    /// absent). Boxed because `LinkMetadata` dwarfs the common `Create` variant.
    Delete {
        link: &'a LinkKind,
        metadata: Option<Box<LinkMetadata>>,
        referrer: &'a Option<Digest>,
    },
}

/// The single per-attempt read pass over every operation's link.
struct LinksSnapshot<'a> {
    ops: Vec<OpSnapshot<'a>>,
    /// Current metadata per present `Create` link, consumed by the mutation
    /// builders when merging tracked-link referrers.
    link_cache: HashMap<LinkKind, LinkMetadata>,
}

/// Whether the pushing namespace already holds any reference entry for each
/// newly-referenced digest of a policy-checked push, read before planning.
type ReferenceOwnership = HashMap<Digest, bool>;

/// The compiled waves of one link write.
#[derive(Default)]
struct WavePlan {
    /// Wave A: reference keys.
    refs: Vec<Mutation>,
    /// Wave C: revision records, tracked links, tag tombstones, referrer
    /// removals.
    records: Vec<Mutation>,
    /// Wave D: tag entries, referrer records, revision-record deletions.
    finals: Vec<Mutation>,
    /// The digests wave A references, checked against collector runs.
    gc_digests: Vec<Digest>,
}

/// The planned waves: `refs` land first (wave A), `records` after the
/// collector check (wave C), `finals` last (wave D). A push puts its revision
/// record in `records` and its tag entry and referrer record in `finals`, so
/// a reader that resolves a tag sees a complete manifest; a delete tombstones
/// tags in `records` and removes the revision record in `finals`, so the tags
/// are gone before the revision is.
struct LinkMutations {
    records: Vec<Mutation>,
    finals: Vec<Mutation>,
    pending_blob_ops: HashMap<Digest, Vec<BlobIndexOperation>>,
    written_links: Vec<(LinkKind, LinkMetadata)>,
    deleted_links: Vec<LinkKind>,
    /// `Some(digest)` when a strict push referenced an unowned digest; the
    /// plan is empty and the caller reports a missing reference.
    missing_reference: Option<Digest>,
}

impl LinkMutations {
    /// Queue a blob-index op for `digest`, compiled into wave A.
    fn push_blob_op(&mut self, digest: &Digest, op: BlobIndexOperation) {
        self.pending_blob_ops
            .entry(digest.clone())
            .or_default()
            .push(op);
    }

    /// `Put` `metadata` for `link` and record it among the written links.
    fn put_link(
        &mut self,
        namespace: &Namespace,
        link: &LinkKind,
        metadata: LinkMetadata,
    ) -> Result<(), TxError> {
        let body = serde_json::to_vec(&metadata)
            .map(Bytes::from)
            .map_err(TxError::Serde)?;
        self.records.push(Mutation::Put {
            key: path_builder::link_path(link, namespace),
            body,
            expected: None,
        });
        self.written_links.push((link.clone(), metadata));
        Ok(())
    }

    /// `Delete` `link` and record it among the deleted links. A revision or
    /// referrer also deletes its record key, so the legacy fallback cannot
    /// resurrect it; a revision goes last (`finals`), after the tombstones
    /// and referrer removals that reference it. The blob-index entry is left
    /// for the collector: a writer that removed it could unpin a blob a
    /// concurrent push is committing.
    fn delete_link(&mut self, namespace: &Namespace, link: &LinkKind, _target: &Digest) {
        let wave = if matches!(link, LinkKind::Digest(_)) {
            &mut self.finals
        } else {
            &mut self.records
        };
        wave.push(Mutation::Delete {
            key: path_builder::link_path(link, namespace),
            expected: None,
        });
        let record_key = match link {
            LinkKind::Digest(digest) => Some(path_builder::revision_record_path(namespace, digest)),
            LinkKind::Referrer { subject, referrer } => Some(path_builder::referrer_record_path(
                namespace, subject, referrer,
            )),
            _ => None,
        };
        if let Some(key) = record_key {
            let wave = if matches!(link, LinkKind::Digest(_)) {
                &mut self.finals
            } else {
                &mut self.records
            };
            wave.push(Mutation::Delete {
                key,
                expected: None,
            });
        }
        self.deleted_links.push(link.clone());
    }
}

impl MetadataStore {
    /// Engine-backed implementation of `update_links`.
    ///
    /// Thin wrapper over [`Self::execute_links_tx`].
    pub async fn update_links(
        &self,
        namespace: &Namespace,
        operations: &[LinkOperation],
    ) -> Result<(), Error> {
        if operations.is_empty() {
            return Ok(());
        }
        self.execute_links_tx(namespace, operations, LinksTx::UpdateLinks)
            .await
            .map(|_| ())
    }

    /// Delete links (e.g. a tag) carrying a replicated delete's `source_ts` for
    /// the last-writer-wins gate. Unlike [`Self::delete_manifest`] it does no
    /// blob-data reclamation. A `None` `source_ts` is a plain unconditional
    /// delete (a genuine client request).
    pub async fn delete_links(
        &self,
        namespace: &Namespace,
        operations: &[LinkOperation],
        source_ts: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        if operations.is_empty() {
            return Ok(());
        }
        self.execute_links_tx(namespace, operations, LinksTx::DeleteLinks { source_ts })
            .await
            .map(|_| ())
    }

    /// Plan the write once, then apply it as ordered waves of unconditional
    /// single-object writes, and perform post-apply cleanup. Every public
    /// entry point shares this body, differing only in the `tx` kind. No
    /// retry loop: every write is idempotent, so a failed wave surfaces to
    /// the client and a replay is harmless.
    pub async fn execute_links_tx(
        &self,
        namespace: &Namespace,
        operations: &[LinkOperation],
        tx: LinksTx<'_>,
    ) -> Result<LinksCommit, Error> {
        let (plan, result) = self
            .plan_links(namespace, operations, &tx)
            .await
            .map_err(Error::from)?;

        if let Some(message) = result.superseded {
            return Err(Error::ReplicationSuperseded(message));
        }

        if let Some(digest) = result.missing_reference {
            warn!("Strict manifest push references {digest} with no blob-index entry; rejecting");
            return Err(Error::ManifestBlobUnknown);
        }

        // Wave A: reference keys, before anything that could commit them.
        self.apply_writes(&plan.refs).await?;
        // Wave B: the collector check. An unexpired run covering one of the
        // referenced blobs means a reclaim may be mid-flight; back off.
        if !plan.gc_digests.is_empty() {
            self.gc_backoff(&plan.gc_digests).await?;
        }
        // Waves C and D, in order.
        self.apply_writes(&plan.records).await?;
        self.apply_writes(&plan.finals).await?;

        // Post-apply cache maintenance. On FS the backend prunes the emptied
        // parent directories on delete; no directory sweep runs here, because
        // an unvalidated prefix delete could erase a link a concurrent push
        // just re-created.
        for (link, metadata) in &result.written_links {
            self.cache_put(namespace, link, metadata).await;
        }
        for link in &result.deleted_links {
            self.cache_invalidate(namespace, link).await;
        }
        if !result.written_links.is_empty() {
            self.ensure_catalog_index(namespace).await;
        }

        Ok(LinksCommit {
            prior_targets: result.prior_targets,
        })
    }

    /// Apply one wave: every write fans out concurrently, and the wave
    /// completes only when all of them have.
    async fn apply_writes(&self, writes: &[Mutation]) -> Result<(), Error> {
        let results = join_all(writes.iter().map(|write| async move {
            match write {
                Mutation::Put { key, body, .. } => {
                    self.store().object_store().put(key, body.clone()).await
                }
                Mutation::Delete { key, .. } => self.store().object_store().delete(key).await,
                // The planner only produces puts and deletes.
                _ => Ok(()),
            }
        }))
        .await;
        for result in results {
            result?;
        }
        Ok(())
    }

    /// The writer half of the reclamation marker protocol: wait out a
    /// covering collector run briefly, then give up and let the client
    /// retry. Both sides aborting is safe.
    async fn gc_backoff(&self, digests: &[Digest]) -> Result<(), Error> {
        let digests: Vec<&Digest> = digests.iter().collect();
        if self.gc_clear(&digests).await? {
            return Ok(());
        }
        Err(Error::Internal(
            "blob reclamation in progress for a referenced blob; retry".to_string(),
        ))
    }

    /// The single planning pass: snapshot the touched links, gate on no-op /
    /// LWW / reference ownership, and compile the ordered waves.
    async fn plan_links(
        &self,
        namespace: &Namespace,
        operations: &[LinkOperation],
        tx: &LinksTx<'_>,
    ) -> Result<(WavePlan, LinksTxCaptured), TxError> {
        // Snapshot: one read pass over every operation's link.
        let snapshot = self.snapshot_links(namespace, operations).await?;

        // Empty no-op short-circuit: no creates, every delete target
        // already missing, and no extras to apply.
        if is_empty_noop(&snapshot.ops, tx) {
            return Ok((WavePlan::default(), LinksTxCaptured::default()));
        }

        // LWW gate: reject replicated writes/deletes superseded locally. A
        // racing writer that lands between this read and the waves loses or
        // wins by key name, never by protocol.
        if let Some(message) = lww_superseded(&snapshot, tx) {
            return Ok((
                WavePlan::default(),
                LinksTxCaptured {
                    superseded: Some(message),
                    ..LinksTxCaptured::default()
                },
            ));
        }

        let LinksSnapshot {
            ops,
            mut link_cache,
        } = snapshot;

        // Ownership pre-read: one reference lookup per newly-referenced digest
        // of a policy-checked push.
        let store = self.store_arc();
        let ownership = preread_reference_ownership(store.as_ref(), namespace, &ops, tx).await?;

        // Plan: build the link mutations over the snapshot state.
        let LinkMutations {
            records,
            finals,
            mut pending_blob_ops,
            written_links,
            deleted_links,
            missing_reference,
        } = build_link_mutations(namespace, &ops, &mut link_cache, tx, &ownership)?;

        if let Some(digest) = missing_reference {
            return Ok((
                WavePlan::default(),
                LinksTxCaptured {
                    missing_reference: Some(digest),
                    ..LinksTxCaptured::default()
                },
            ));
        }

        // Direct blob-index ops (`revoke_blob_ownership`'s `_own` removal).
        if let Some((digest, ops)) = tx.blob_index_ops() {
            pending_blob_ops
                .entry(digest.clone())
                .or_default()
                .extend(ops.iter().cloned());
        }
        let (refs, gc_digests) = build_ref_wave(namespace, &pending_blob_ops);

        Ok((
            WavePlan {
                refs,
                records,
                finals,
                gc_digests,
            },
            LinksTxCaptured {
                written_links,
                deleted_links,
                prior_targets: capture_prior_targets(&ops),
                superseded: None,
                missing_reference: None,
            },
        ))
    }

    /// The snapshot pass: read each operation's link once, in parallel,
    /// capturing the raw bytes (for the transaction read set) and the parsed
    /// metadata (for planning) together. A non-`NotFound` read error fails the
    /// attempt rather than being planned around as an absent link.
    ///
    /// Repeated operations are collapsed first: a manifest may legally list the
    /// same digest twice, and planning that link twice would erase the referrers
    /// the first mutation merged in and leave a second write to the same key
    /// whose read precondition the first one already invalidated.
    async fn snapshot_links<'a>(
        &self,
        namespace: &Namespace,
        operations: &'a [LinkOperation],
    ) -> Result<LinksSnapshot<'a>, TxError> {
        let mut seen_ops = HashSet::new();
        let operations: Vec<&LinkOperation> = operations
            .iter()
            .filter(|op| match op {
                LinkOperation::Create {
                    link,
                    target,
                    referrer,
                    ..
                } => seen_ops.insert((link, Some(target), referrer)),
                LinkOperation::Delete { link, referrer } => seen_ops.insert((link, None, referrer)),
            })
            .collect();

        let results = join_all(operations.iter().map(|op| async move {
            let link = match op {
                LinkOperation::Create { link, .. } | LinkOperation::Delete { link, .. } => link,
            };
            // Tags, revisions, and referrers resolve from their write-once
            // shapes: there is no single mutable object whose bytes could
            // join the read set, and none is needed, because concurrent
            // writers of these kinds write disjoint or identical keys.
            let resolved = match link {
                LinkKind::Tag(tag) => Some(self.resolve_tag(namespace, tag).await),
                LinkKind::Digest(digest) => Some(self.resolve_revision(namespace, digest).await),
                LinkKind::Referrer { subject, referrer } => {
                    Some(self.resolve_referrer(namespace, subject, referrer).await)
                }
                _ => None,
            };
            if let Some(result) = resolved {
                let metadata = match result {
                    Ok(metadata) => Some(metadata),
                    Err(Error::NotFound) => None,
                    Err(e) => return Err(TxError::Storage(StorageError::Backend(e.to_string()))),
                };
                return Ok((op, metadata));
            }
            let link_path = path_builder::link_path(link, namespace);
            let found = self.read_link_raw(&link_path).await?;
            let metadata = found.map(|(_, metadata)| metadata);
            Ok::<_, TxError>((op, metadata))
        }))
        .await;

        let mut snapshot = LinksSnapshot {
            ops: Vec::with_capacity(operations.len()),
            link_cache: HashMap::new(),
        };
        for result in results {
            let (op, metadata) = result?;
            snapshot.ops.push(match op {
                LinkOperation::Create {
                    link,
                    target,
                    referrer,
                    media_type,
                    descriptor,
                } => {
                    let old_target = metadata.as_ref().map(|m| m.target.clone());
                    if let Some(metadata) = metadata {
                        snapshot.link_cache.insert(link.clone(), metadata);
                    }
                    OpSnapshot::Create {
                        link,
                        target,
                        old_target,
                        referrer,
                        media_type,
                        descriptor,
                    }
                }
                LinkOperation::Delete { link, referrer } => OpSnapshot::Delete {
                    link,
                    metadata: metadata.map(Box::new),
                    referrer,
                },
            });
        }
        Ok(snapshot)
    }

    /// Read a link's exact stored bytes and parsed metadata, or `None` when
    /// absent. The snapshot pass needs the raw bytes for the read-set
    /// fingerprint alongside the parsed metadata.
    async fn read_link_raw(
        &self,
        link_path: &str,
    ) -> Result<Option<(Bytes, LinkMetadata)>, TxError> {
        match self.store().object_store().get(link_path).await {
            Ok(data) => {
                let bytes = Bytes::from(data.clone());
                let metadata: LinkMetadata = serde_json::from_slice(&data)
                    .map_err(|e| TxError::Storage(StorageError::Backend(e.to_string())))?;
                Ok(Some((bytes, metadata)))
            }
            Err(StorageError::NotFound) => Ok(None),
            Err(e) => Err(TxError::Storage(e)),
        }
    }
}

/// The last-writer-wins gate for replicated writes and deletes: returns
/// `Some(message)` when a local tag is newer than the replicated source, so
/// the attempt commits an empty transaction and the caller maps it to
/// [`Error::ReplicationSuperseded`]. The comparison runs against the same
/// snapshot the read set validates, so a racing tag write aborts the commit
/// rather than gating LWW on stale state.
fn lww_superseded(snapshot: &LinksSnapshot<'_>, tx: &LinksTx<'_>) -> Option<String> {
    // A stored tag timestamp carries millisecond precision (the entry
    // ordinal), so the incoming side is compared at the same precision or an
    // exact-equality tie would silently read as strictly newer.
    let entry_ms =
        |ts: DateTime<Utc>| path_builder::tag_ord_ts(path_builder::tag_ord(Some(ts))).unwrap_or(ts);
    for op in &snapshot.ops {
        match op {
            OpSnapshot::Create { link, target, .. } => {
                if !matches!(link, LinkKind::Tag(_)) {
                    continue;
                }
                if let (Some(source_ts), Some(metadata)) = (
                    tx.created_at().map(entry_ms),
                    snapshot.link_cache.get(*link),
                ) && let Some(created_at) = metadata.supersedes(source_ts, Some(target))
                {
                    return Some(format!(
                        "local {link} (created {created_at}) is newer \
                         than the replicated source ({source_ts})"
                    ));
                }
            }
            OpSnapshot::Delete {
                link,
                metadata: Some(metadata),
                ..
            } => {
                if !matches!(link, LinkKind::Tag(_)) {
                    continue;
                }
                if let Some(source_ts) = tx.delete_source_ts().map(entry_ms)
                    && let Some(created_at) = metadata.supersedes(source_ts, None)
                {
                    return Some(format!(
                        "local {link} (created {created_at}) is newer \
                         than the replicated delete ({source_ts})"
                    ));
                }
            }
            OpSnapshot::Delete { .. } => {}
        }
    }
    None
}

/// Empty no-op short-circuit predicate: no creates, no blob side effects, and
/// every delete target already missing.
fn is_empty_noop(ops: &[OpSnapshot<'_>], tx: &LinksTx<'_>) -> bool {
    let had_creates = ops.iter().any(|op| matches!(op, OpSnapshot::Create { .. }));
    let all_deletes_absent = ops.iter().all(|op| match op {
        OpSnapshot::Create { .. } => true,
        OpSnapshot::Delete { metadata, .. } => metadata.is_none(),
    });
    !had_creates && !tx.has_blob_side_effects() && all_deletes_absent
}

/// The planning step: turn the snapshot's creates and deletes into transaction
/// mutations, accumulating the blob-index ops and the written / deleted link
/// sets. Seeds the builder with the snapshot reads and direct blob-index ops,
/// then threads a [`LinkMutations`] accumulator through the create/delete
/// processors.
fn build_link_mutations(
    namespace: &Namespace,
    ops: &[OpSnapshot<'_>],
    link_cache: &mut HashMap<LinkKind, LinkMetadata>,
    tx: &LinksTx<'_>,
    ownership: &ReferenceOwnership,
) -> Result<LinkMutations, TxError> {
    let acc = LinkMutations {
        records: Vec::new(),
        finals: Vec::new(),
        pending_blob_ops: HashMap::new(),
        written_links: Vec::new(),
        deleted_links: Vec::new(),
        missing_reference: None,
    };
    let acc = build_create_mutations(namespace, ops, link_cache, tx, ownership, acc)?;
    if acc.missing_reference.is_some() {
        return Ok(acc);
    }
    let acc = build_delete_mutations(namespace, ops, tx, acc)?;
    Ok(acc)
}

/// The create half of mutation planning: append a link `Put` per `Create` op,
/// recording the inserted / moved blob-index entries and the written link
/// metadata.
fn build_create_mutations(
    namespace: &Namespace,
    ops: &[OpSnapshot<'_>],
    link_cache: &mut HashMap<LinkKind, LinkMetadata>,
    tx: &LinksTx<'_>,
    ownership: &ReferenceOwnership,
    mut acc: LinkMutations,
) -> Result<LinkMutations, TxError> {
    for op in ops {
        let OpSnapshot::Create {
            link,
            target,
            old_target,
            referrer,
            media_type,
            descriptor,
        } = op
        else {
            continue;
        };

        if link.is_tracked() && referrer.is_some() {
            // Ownership gate: a newly-referenced digest must already hold a
            // reference entry. Strict rejects the push, Permissive drops the
            // link so the namespace gains no access it did not have.
            if old_target.is_none() && ownership.get(*target) == Some(&false) {
                if tx.reference_policy() == Some(ReferencePolicy::Strict) {
                    acc.missing_reference = Some((*target).clone());
                    return Ok(acc);
                }
                continue;
            }

            // Tracked link: merge referrer into existing or new metadata.
            let mut metadata = link_cache.remove(*link).unwrap_or_else(|| {
                LinkMetadata::from_digest_at(
                    (*target).clone(),
                    tx.created_at().unwrap_or_else(Utc::now),
                )
                .with_media_type((*media_type).clone())
                .with_descriptor(descriptor.as_ref().map(|b| b.as_ref().clone()))
            });

            if let Some(manifest_digest) = referrer {
                metadata.add_referrer((*manifest_digest).clone());
            }

            if old_target.is_none() {
                acc.push_blob_op(target, BlobIndexOperation::Insert((*link).clone()));
            }
            acc.put_link(namespace, link, metadata)?;
        } else {
            // Non-tracked link.
            let same_target = old_target.as_ref() == Some(*target);
            if !same_target {
                acc.push_blob_op(target, BlobIndexOperation::Insert((*link).clone()));
                if let Some(old) = old_target
                    && *old != **target
                {
                    acc.push_blob_op(old, BlobIndexOperation::Remove((*link).clone()));
                }
            }

            // A same-digest re-push keeps the existing `created_at`: the binding
            // is unchanged so dispatch is suppressed, and bumping the timestamp
            // would let an interleaved peer write lose locally yet win on peers.
            // A real binding change stamps the new write time.
            let created_at = if same_target {
                link_cache.get(*link).and_then(|m| m.created_at)
            } else {
                None
            }
            .or(tx.created_at())
            .unwrap_or_else(Utc::now);
            match link {
                LinkKind::Tag(tag) => {
                    // The entry key is the write: the same digest in the same
                    // millisecond is the same key, so a re-push is naturally
                    // idempotent and concurrent writers never contend.
                    let mutation =
                        tag_set_mutation(namespace, tag, created_at, target, (*media_type).clone())
                            .map_err(TxError::Serde)?;
                    acc.finals.push(mutation);
                    let created_at =
                        path_builder::tag_ord_ts(path_builder::tag_ord(Some(created_at)))
                            .unwrap_or(created_at);
                    let metadata = LinkMetadata::from_digest_at((*target).clone(), created_at)
                        .with_media_type((*media_type).clone());
                    acc.written_links.push(((*link).clone(), metadata));
                }
                LinkKind::Digest(digest) => {
                    let mutation = revision_set_mutation(
                        namespace,
                        digest,
                        Some(created_at),
                        (*media_type).clone(),
                    )
                    .map_err(TxError::Serde)?;
                    acc.records.push(mutation);
                    let metadata = LinkMetadata::from_digest_at((*target).clone(), created_at)
                        .with_media_type((*media_type).clone());
                    acc.written_links.push(((*link).clone(), metadata));
                }
                LinkKind::Referrer { subject, referrer } => {
                    let mutation =
                        referrer_set_mutation(namespace, subject, referrer, descriptor.as_deref())
                            .map_err(TxError::Serde)?;
                    acc.finals.push(mutation);
                    let metadata = LinkMetadata::from_digest_at((*target).clone(), created_at)
                        .with_media_type((*media_type).clone())
                        .with_descriptor(descriptor.as_ref().map(|b| b.as_ref().clone()));
                    acc.written_links.push(((*link).clone(), metadata));
                }
                _ => {
                    let metadata = LinkMetadata::from_digest_at((*target).clone(), created_at)
                        .with_media_type((*media_type).clone())
                        .with_descriptor(descriptor.as_ref().map(|b| b.as_ref().clone()));
                    acc.put_link(namespace, link, metadata)?;
                }
            }
        }
    }
    Ok(acc)
}

/// The delete half of mutation planning: for each `Delete` op whose link
/// exists, either prune one referrer (a tracked link with references left
/// becomes a `Put`), append a tag tombstone, or remove the link outright (a
/// `Delete` plus the blob-index `Remove`).
fn build_delete_mutations(
    namespace: &Namespace,
    ops: &[OpSnapshot<'_>],
    tx: &LinksTx<'_>,
    mut acc: LinkMutations,
) -> Result<LinkMutations, TxError> {
    for op in ops {
        let OpSnapshot::Delete {
            link,
            metadata: Some(metadata),
            referrer,
        } = op
        else {
            continue;
        };

        if let LinkKind::Tag(tag) = link {
            // A tombstone entry, never a delete: it names the digest the tag
            // held (tag history requires it) and its timestamp orders it
            // against any concurrent push by key name alone.
            let created_at = tx.delete_source_ts().unwrap_or_else(Utc::now);
            let mutation = tag_del_mutation(
                namespace,
                tag,
                created_at,
                &metadata.target,
                metadata.media_type.clone(),
            )
            .map_err(TxError::Serde)?;
            acc.records.push(mutation);
            acc.deleted_links.push((*link).clone());
            continue;
        }

        if link.is_tracked() && referrer.is_some() {
            let mut pruned = (**metadata).clone();
            if let Some(manifest_digest) = referrer {
                pruned.remove_referrer(manifest_digest);
            }

            // References remain: keep the link with the referrer pruned;
            // otherwise remove it outright.
            if pruned.has_references() {
                acc.put_link(namespace, link, pruned)?;
            } else {
                acc.delete_link(namespace, link, &metadata.target);
            }
        } else {
            acc.delete_link(namespace, link, &metadata.target);
        }
    }
    Ok(acc)
}

/// The ownership pre-read: one reference lookup per newly-referenced digest
/// (a tracked Create whose link does not exist yet) of a policy-checked push.
/// A namespace owns a digest when it holds any reference entry for it, new
/// keys or legacy shard alike.
async fn preread_reference_ownership(
    store: &Store,
    namespace: &Namespace,
    ops: &[OpSnapshot<'_>],
    tx: &LinksTx<'_>,
) -> Result<ReferenceOwnership, TxError> {
    let mut ownership = ReferenceOwnership::new();
    if !matches!(
        tx.reference_policy(),
        Some(ReferencePolicy::Strict | ReferencePolicy::Permissive)
    ) {
        return Ok(ownership);
    }

    for op in ops {
        let OpSnapshot::Create {
            link,
            target,
            old_target,
            referrer,
            ..
        } = op
        else {
            continue;
        };
        if !link.is_tracked()
            || referrer.is_none()
            || old_target.is_some()
            || ownership.contains_key(*target)
        {
            continue;
        }
        let entries = namespace_entries_merged(store, namespace, target)
            .await
            .map_err(|e| TxError::Storage(StorageError::Backend(e.to_string())))?;
        ownership.insert((*target).clone(), !entries.is_empty());
    }
    Ok(ownership)
}

/// Fold `ops` to one final operation per link (last op wins), so wave A
/// carries at most one write per reference key.
fn fold_ref_ops(ops: &[BlobIndexOperation]) -> Vec<BlobIndexOperation> {
    let mut folded: Vec<BlobIndexOperation> = Vec::new();
    for op in ops {
        let (BlobIndexOperation::Insert(link) | BlobIndexOperation::Remove(link)) = op;
        folded.retain(|existing| {
            let (BlobIndexOperation::Insert(kept) | BlobIndexOperation::Remove(kept)) = existing;
            kept != link
        });
        folded.push(op.clone());
    }
    folded
}

/// Compile the pending blob-index ops into wave A plus the digests it
/// references. Inserts always land; the only removal a writer performs is
/// its own ownership key (an explicit blob delete). Every other removal is
/// the collector's: a stale entry over-approximates and is aged out, while a
/// writer-side delete could unpin a blob a concurrent push is committing.
fn build_ref_wave(
    namespace: &Namespace,
    pending_blob_ops: &HashMap<Digest, Vec<BlobIndexOperation>>,
) -> (Vec<Mutation>, Vec<Digest>) {
    let mut refs = Vec::new();
    let mut gc_digests = Vec::new();
    for (digest, ops) in pending_blob_ops {
        let mut referenced = false;
        for op in fold_ref_ops(ops) {
            match &op {
                BlobIndexOperation::Insert(_) => {
                    referenced = true;
                    refs.push(ref_mutation(namespace, digest, &op));
                }
                BlobIndexOperation::Remove(LinkKind::Blob(_)) => {
                    refs.push(ref_mutation(namespace, digest, &op));
                }
                BlobIndexOperation::Remove(_) => {}
            }
        }
        if referenced {
            gc_digests.push(digest.clone());
        }
    }
    (refs, gc_digests)
}

fn capture_prior_targets(ops: &[OpSnapshot<'_>]) -> Vec<(LinkKind, Option<Digest>)> {
    ops.iter()
        .filter_map(|op| match op {
            OpSnapshot::Create {
                link, old_target, ..
            } => Some(((*link).clone(), old_target.clone())),
            OpSnapshot::Delete { .. } => None,
        })
        .collect()
}

// store_manifest / delete_manifest: thin wrappers over the planner above.

impl MetadataStore {
    /// Persist a manifest's link metadata and blob-index reference keys as a
    /// single atomic transaction. The manifest blob-data itself is content and
    /// is written separately to the blob store by the caller. Returns the
    /// [`LinksCommit`] carrying each created link's commit-validated prior
    /// target.
    ///
    /// `reference_policy` governs newly-referenced digests the namespace does
    /// not own, checked under the caller's `blob-data:{digest}` lock so the
    /// decision cannot race a concurrent reclaim: Strict fails the push with
    /// [`Error::ManifestBlobUnknown`], Permissive drops the unowned link,
    /// Trusted grants blindly.
    pub async fn store_manifest(
        &self,
        namespace: &Namespace,
        operations: &[LinkOperation],
        created_at: Option<DateTime<Utc>>,
        reference_policy: ReferencePolicy,
    ) -> Result<LinksCommit, Error> {
        let tx = LinksTx::StoreManifest {
            created_at,
            reference_policy,
        };
        self.execute_links_tx(namespace, operations, tx).await
    }

    /// Delete a manifest: tag tombstones and referrer removals land first,
    /// the revision record last. Reference keys are left for the collector,
    /// and the bytes wait for a sweep, which is what the spec's
    /// `202 Accepted` licenses.
    pub async fn delete_manifest(
        &self,
        namespace: &Namespace,
        _digest: &Digest,
        operations: &[LinkOperation],
        source_ts: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        let tx = LinksTx::DeleteManifest { source_ts };
        self.execute_links_tx(namespace, operations, tx)
            .await
            .map(|_| ())
    }
}
