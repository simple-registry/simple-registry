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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::future::join_all;
use tracing::warn;

use angos_oci::{Descriptor, Digest, MediaType, Namespace};
use angos_storage::Error as StorageError;

use crate::registry::{
    Error,
    metadata_store::{
        BlobIndexOperation, LinkKind, LinkMetadata, LinkOperation, MetadataStore, ReferencePolicy,
        blob_index::{namespace_entries_merged, ref_mutation},
        link::record::{referrer_set_mutation, revision_set_mutation},
        link::tag::{TagEntryBody, tag_del_mutation, tag_set_mutation},
        mutation::Mutation,
    },
    path_builder,
};

// Consolidated write planner

/// The kind of link write the planner runs: one variant per public entry
/// point, each carrying exactly the blob-index side effects and timestamps
/// that operation needs. Modelling it as an enum (not a struct of optional
/// fields) makes invalid combinations unrepresentable.
pub enum LinksTx<'a> {
    /// Plain link create/delete batch (`update_links`): no blob-data or
    /// blob-index side effects and no replication timestamps.
    UpdateLinks,
    /// Link delete batch carrying a replicated delete's `source_ts` for the
    /// last-writer-wins gate (`delete_links`); `None` is a plain local delete.
    /// Unlike [`Self::DeleteManifest`] it does no blob-data reclamation.
    DeleteLinks { source_ts: Option<DateTime<Utc>> },
    /// `store_manifest`: ordered waves of idempotent write-once puts, the
    /// `v2/gc` marker check between waves A and C backing off while a
    /// collector run covers a referenced digest. `created_at` stamps new link
    /// metadata (a replicated write passes the author's `source_ts` for LWW);
    /// `reference_policy` governs newly-referenced unowned digests: Strict
    /// rejects the push, Permissive drops the link, Trusted grants blindly.
    StoreManifest {
        created_at: Option<DateTime<Utc>>,
        reference_policy: ReferencePolicy,
    },
    /// `delete_manifest`: tag tombstones and referrer removals land before the
    /// revision record's deletion, all idempotent and lock-free. Reference
    /// keys and blob-data are left to the collector, whose reclaim the `v2/gc`
    /// marker check coordinates. `source_ts` gates each deleted tag via LWW.
    DeleteManifest { source_ts: Option<DateTime<Utc>> },
    /// `revoke_blob_ownership`: one idempotent delete of `namespace`'s `_own`
    /// reference key, with no lock. The bytes stay until the collector finds
    /// every remaining reference stale and reclaims them under the `v2/gc`
    /// marker.
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

    /// Whether this write touches blob-data or the blob-index beyond its
    /// link operations, so the empty-no-op short-circuit must not fire.
    fn has_blob_side_effects(&self) -> bool {
        !matches!(self, LinksTx::UpdateLinks | LinksTx::DeleteLinks { .. })
    }
}

/// Data captured from a planned link write, used for post-apply cache and
/// cleanup steps.
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
    /// `Some(message)` when the last-writer-wins guard rejected the write;
    /// the plan is empty and the caller maps this to
    /// [`Error::ReplicationSuperseded`].
    superseded: Option<String>,
    /// `Some(digest)` when a strict push referenced a digest the namespace
    /// held no entry for at plan time; the plan is empty and the caller maps
    /// this to [`Error::ManifestBlobUnknown`].
    missing_reference: Option<Digest>,
}

/// Prior link state captured by a committed link write: the snapshot each
/// `Create` op was planned against, reported to callers for replication
/// dispatch.
#[derive(Default)]
pub struct LinksCommit {
    /// Prior target per `Create` op's link; `None` = the link did not exist.
    pub prior_targets: Vec<(LinkKind, Option<Digest>)>,
}

impl LinksCommit {
    /// Whether the commit changed `link`: it was absent or pointed at a
    /// different digest before. Fails open (`true`) when the write had no
    /// `Create` op for `link`, so a genuine write is never suppressed.
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
        size: &'a Option<u64>,
        annotations: &'a Option<BTreeMap<String, String>>,
        descriptor: &'a Option<Box<Descriptor>>,
    },
    /// A delete with the link's currently-stored metadata (`None` = already
    /// absent). Boxed because `LinkMetadata` dwarfs the common `Create`
    /// variant. A resolved tag also carries its winner entry's body, the
    /// descriptor fields the tombstone copies.
    Delete {
        link: &'a LinkKind,
        metadata: Option<Box<LinkMetadata>>,
        referrer: &'a Option<Digest>,
        tag_body: Option<TagEntryBody>,
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
    ) -> Result<(), Error> {
        let body = serde_json::to_vec(&metadata).map(Bytes::from)?;
        self.records.push(Mutation::Put {
            key: path_builder::link_path(link, namespace),
            body,
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
    fn delete_link(&mut self, namespace: &Namespace, link: &LinkKind) {
        let record_key = match link {
            LinkKind::Digest(digest) => Some(path_builder::revision_record_path(namespace, digest)),
            LinkKind::Referrer { subject, referrer } => Some(path_builder::referrer_record_path(
                namespace, subject, referrer,
            )),
            _ => None,
        };
        let wave = if matches!(link, LinkKind::Digest(_)) {
            &mut self.finals
        } else {
            &mut self.records
        };
        wave.push(Mutation::Delete {
            key: path_builder::link_path(link, namespace),
        });
        if let Some(key) = record_key {
            wave.push(Mutation::Delete { key });
        }
        self.deleted_links.push(link.clone());
    }
}

impl MetadataStore {
    /// Apply a plain link create/delete batch: a thin wrapper over
    /// [`Self::execute_links_tx`].
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

    /// Plan the write once, then apply it as ordered waves of idempotent
    /// single-object writes plus post-apply cleanup; a failed wave surfaces
    /// to the client and a replay is harmless. Every public entry point
    /// shares this body, differing only in the `tx` kind.
    pub async fn execute_links_tx(
        &self,
        namespace: &Namespace,
        operations: &[LinkOperation],
        tx: LinksTx<'_>,
    ) -> Result<LinksCommit, Error> {
        let (plan, result) = self.plan_links(namespace, operations, &tx).await?;

        if let Some(message) = result.superseded {
            return Err(Error::ReplicationSuperseded(message));
        }

        if let Some(digest) = result.missing_reference {
            warn!("Strict manifest push references {digest} with no blob-index entry; rejecting");
            return Err(Error::ManifestBlobUnknown);
        }

        // Wave A: reference keys, before anything that could commit them.
        let refs_started_at = Instant::now();
        self.apply_writes(&plan.refs).await?;
        // Wave B: the collector check. An unexpired run covering one of the
        // referenced blobs means a reclaim may be mid-flight; back off.
        if !plan.gc_digests.is_empty() {
            self.gc_backoff(&plan.gc_digests).await?;
            // The clearance vouches for one grace period counted from the
            // reference wave; a wave A plus backoff slower than that redoes
            // the check, since the records wave follows immediately.
            if refs_started_at.elapsed().as_secs() > self.gc_grace_secs {
                self.gc_backoff(&plan.gc_digests).await?;
            }
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
                Mutation::Put { key, body } => self.object_store().put(key, body.clone()).await,
                Mutation::Delete { key } => self.object_store().delete(key).await,
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
        Err(Error::ReclamationInProgress(
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
    ) -> Result<(WavePlan, LinksTxCaptured), Error> {
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

        let LinksSnapshot { ops, link_cache } = snapshot;

        // Ownership pre-read: one reference lookup per newly-referenced digest
        // of a policy-checked push.
        let ownership = preread_reference_ownership(self, namespace, &ops, tx).await?;

        // Plan: build the link mutations over the snapshot state.
        let LinkMutations {
            records,
            finals,
            mut pending_blob_ops,
            written_links,
            deleted_links,
            missing_reference,
        } = build_link_mutations(namespace, &ops, &link_cache, tx, &ownership)?;

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

    /// The snapshot pass: read each operation's link once, in parallel, for
    /// planning. A non-`NotFound` read error fails the attempt rather than
    /// being planned around as an absent link.
    ///
    /// Repeated operations are collapsed first: a manifest may legally list
    /// the same digest twice, and planning that link twice would double-plan
    /// writes to the same keys.
    async fn snapshot_links<'a>(
        &self,
        namespace: &Namespace,
        operations: &'a [LinkOperation],
    ) -> Result<LinksSnapshot<'a>, Error> {
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
            // shapes: concurrent writers of these kinds write disjoint or
            // identical keys, so no prior bytes need capturing.
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
                    Err(e) => return Err(e),
                };
                // A tag about to be tombstoned needs its winner entry's body:
                // the one targeted body read left off the serving path.
                let tag_body = match (op, link, &metadata) {
                    (LinkOperation::Delete { .. }, LinkKind::Tag(tag), Some(m)) => {
                        Some(self.read_tag_winner_body(namespace, tag, m).await?)
                    }
                    _ => None,
                };
                return Ok((op, metadata, tag_body));
            }
            let link_path = path_builder::link_path(link, namespace);
            let metadata = self.read_link_raw(&link_path).await?;
            Ok::<_, Error>((op, metadata, None))
        }))
        .await;

        let mut snapshot = LinksSnapshot {
            ops: Vec::with_capacity(operations.len()),
            link_cache: HashMap::new(),
        };
        for result in results {
            let (op, metadata, tag_body) = result?;
            snapshot.ops.push(match op {
                LinkOperation::Create {
                    link,
                    target,
                    referrer,
                    media_type,
                    size,
                    annotations,
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
                        size,
                        annotations,
                        descriptor,
                    }
                }
                LinkOperation::Delete { link, referrer } => OpSnapshot::Delete {
                    link,
                    metadata: metadata.map(Box::new),
                    referrer,
                    tag_body,
                },
            });
        }
        Ok(snapshot)
    }

    /// Read a link file's parsed metadata, or `None` when absent.
    async fn read_link_raw(&self, link_path: &str) -> Result<Option<LinkMetadata>, Error> {
        match self.object_store().get(link_path).await {
            Ok(data) => {
                let metadata: LinkMetadata = serde_json::from_slice(&data)?;
                Ok(Some(metadata))
            }
            Err(StorageError::NotFound) => Ok(None),
            Err(e) => Err(Error::from(e)),
        }
    }
}

/// The last-writer-wins gate for replicated writes and deletes: returns
/// `Some(message)` when a local tag is newer than the replicated source, so
/// the plan stays empty and the caller maps it to
/// [`Error::ReplicationSuperseded`]. A racing local tag write appends a
/// fresher entry that wins resolution by timestamp either way.
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

/// The planning step: turn the snapshot's creates and deletes into wave
/// mutations, threading a [`LinkMutations`] accumulator through the
/// create/delete processors.
fn build_link_mutations(
    namespace: &Namespace,
    ops: &[OpSnapshot<'_>],
    link_cache: &HashMap<LinkKind, LinkMetadata>,
    tx: &LinksTx<'_>,
    ownership: &ReferenceOwnership,
) -> Result<LinkMutations, Error> {
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
    link_cache: &HashMap<LinkKind, LinkMetadata>,
    tx: &LinksTx<'_>,
    ownership: &ReferenceOwnership,
    mut acc: LinkMutations,
) -> Result<LinkMutations, Error> {
    for op in ops {
        let OpSnapshot::Create {
            link,
            target,
            old_target,
            referrer,
            media_type,
            size,
            annotations,
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

            // The pin: one write-once key per referring manifest, always
            // written (idempotent), never merged, so concurrent pushes
            // sharing a blob cannot clobber each other's references. No
            // legacy link file is written; scrub retires the existing ones.
            if let Some(manifest_digest) = referrer {
                acc.push_blob_op(
                    target,
                    BlobIndexOperation::Insert(LinkKind::ReferencedBy((*manifest_digest).clone())),
                );
            }
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
                    let mutation = tag_set_mutation(
                        namespace,
                        tag,
                        created_at,
                        target,
                        (*media_type).clone(),
                        **size,
                        (*annotations).clone(),
                    )?;
                    acc.finals.push(mutation);
                    let created_at =
                        path_builder::tag_ord_ts(path_builder::tag_ord(Some(created_at)))
                            .unwrap_or(created_at);
                    // No media type: tag resolution carries none (the
                    // revision record serves it), so the cached write-through
                    // must match a fresh resolve.
                    let metadata = LinkMetadata::from_digest_at((*target).clone(), created_at);
                    acc.written_links.push(((*link).clone(), metadata));
                }
                LinkKind::Digest(digest) => {
                    let mutation = revision_set_mutation(
                        namespace,
                        digest,
                        Some(created_at),
                        (*media_type).clone(),
                    )?;
                    acc.records.push(mutation);
                    let metadata = LinkMetadata::from_digest_at((*target).clone(), created_at)
                        .with_media_type((*media_type).clone());
                    acc.written_links.push(((*link).clone(), metadata));
                }
                LinkKind::Referrer { subject, referrer } => {
                    let mutation =
                        referrer_set_mutation(namespace, subject, referrer, descriptor.as_deref())?;
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
) -> Result<LinkMutations, Error> {
    for op in ops {
        let OpSnapshot::Delete {
            link,
            metadata: Some(metadata),
            referrer,
            tag_body,
        } = op
        else {
            continue;
        };

        if let LinkKind::Tag(tag) = link {
            // A tombstone entry, never a delete: it names the digest the tag
            // held (tag history requires it), copies the superseded winner's
            // descriptor body, and its timestamp orders it against any
            // concurrent push by key name alone.
            let created_at = tx.delete_source_ts().unwrap_or_else(Utc::now);
            let mutation = tag_del_mutation(
                namespace,
                tag,
                created_at,
                &metadata.target,
                tag_body.as_ref().unwrap_or(&TagEntryBody::default()),
            )?;
            acc.records.push(mutation);
            acc.deleted_links.push((*link).clone());
            continue;
        }

        if link.is_tracked() && referrer.is_some() {
            // Writers never rewrite or delete a tracked link file: the pin
            // lives in the per-referrer reference entry, which goes stale on
            // its own once the referring revision is gone. Only the
            // collector's `update_links` path still prunes legacy files.
            if !matches!(tx, LinksTx::UpdateLinks) {
                continue;
            }
            let mut pruned = (**metadata).clone();
            if let Some(manifest_digest) = referrer {
                pruned.remove_referrer(manifest_digest);
            }

            // References remain: keep the link with the referrer pruned;
            // otherwise remove it outright.
            if pruned.has_references() {
                acc.put_link(namespace, link, pruned)?;
            } else {
                acc.delete_link(namespace, link);
            }
        } else {
            acc.delete_link(namespace, link);
        }
    }
    Ok(acc)
}

/// The ownership pre-read: one reference lookup per newly-referenced digest
/// (a tracked Create whose link does not exist yet) of a policy-checked push.
/// Writers never remove reference keys, so a raw entry is not ownership: the
/// namespace's own key counts directly, anything else only while
/// [`MetadataStore::reference_backed`] vouches for it, short-circuiting on
/// the first hit so an owned digest costs no extra reads.
async fn preread_reference_ownership(
    m: &MetadataStore,
    namespace: &Namespace,
    ops: &[OpSnapshot<'_>],
    tx: &LinksTx<'_>,
) -> Result<ReferenceOwnership, Error> {
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
        let entries = namespace_entries_merged(m.object_store(), namespace, target).await?;
        let mut owned = entries.contains(&LinkKind::Blob((*target).clone()));
        if !owned {
            for entry in &entries {
                if m.reference_backed(namespace, entry, target).await? {
                    owned = true;
                    break;
                }
            }
        }
        ownership.insert((*target).clone(), owned);
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
    /// Persist a manifest's link metadata and blob-index reference keys as
    /// ordered lock-free waves (reference keys, then the revision record
    /// after the `v2/gc` marker check, then the tag entry and referrer
    /// record), returning each created link's prior target; the manifest
    /// blob-data is written separately by the caller. `reference_policy`
    /// governs newly-referenced unowned digests: Strict fails with
    /// [`Error::ManifestBlobUnknown`], Permissive drops the link, Trusted
    /// grants blindly.
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
        operations: &[LinkOperation],
        source_ts: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        let tx = LinksTx::DeleteManifest { source_ts };
        self.execute_links_tx(namespace, operations, tx)
            .await
            .map(|_| ())
    }
}
