//! The consolidated link-write planner behind every public write method, each
//! of which passes a [`LinksTx`] kind that the planner turns into ordered
//! waves of unconditional single-object writes.
//!
//! The wave boundaries are load-bearing: reference keys land before the
//! collector check, and the revision record lands before anything that makes
//! it reachable, so a crash between waves leaves only over-approximated
//! references or a tagless revision, both legal.

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

/// The kind of link write the planner runs, one variant per public entry
/// point. An enum rather than a struct of optional fields, so invalid
/// combinations of side effects and timestamps are unrepresentable.
pub enum LinksTx<'a> {
    /// Plain link create/delete batch with no blob side effects.
    UpdateLinks,
    /// Link delete batch; `source_ts` is a replicated delete's author time for
    /// the last-writer-wins gate, `None` a plain local delete.
    DeleteLinks { source_ts: Option<DateTime<Utc>> },
    /// A manifest push. `created_at` stamps new link metadata, and
    /// `reference_policy` governs newly-referenced unowned digests.
    StoreManifest {
        created_at: Option<DateTime<Utc>>,
        reference_policy: ReferencePolicy,
    },
    /// A manifest delete: tag tombstones and referrer removals land before the
    /// revision record goes, and `source_ts` gates each deleted tag via LWW.
    DeleteManifest { source_ts: Option<DateTime<Utc>> },
    /// One idempotent delete of the namespace's `_own` reference key; the
    /// bytes stay until the collector finds every reference stale.
    RevokeBlobOwnership {
        blob: &'a Digest,
        ops: Vec<BlobIndexOperation>,
    },
}

impl<'a> LinksTx<'a> {
    fn blob_index_ops(&self) -> Option<(&'a Digest, &[BlobIndexOperation])> {
        match self {
            LinksTx::RevokeBlobOwnership { blob, ops } => Some((*blob, ops.as_slice())),
            _ => None,
        }
    }

    /// Timestamp stamped on newly-written link metadata; `None` means now.
    fn created_at(&self) -> Option<DateTime<Utc>> {
        match self {
            LinksTx::StoreManifest { created_at, .. } => *created_at,
            _ => None,
        }
    }

    fn reference_policy(&self) -> Option<ReferencePolicy> {
        match self {
            LinksTx::StoreManifest {
                reference_policy, ..
            } => Some(*reference_policy),
            _ => None,
        }
    }

    fn delete_source_ts(&self) -> Option<DateTime<Utc>> {
        match self {
            LinksTx::DeleteLinks { source_ts } | LinksTx::DeleteManifest { source_ts, .. } => {
                *source_ts
            }
            _ => None,
        }
    }

    /// Whether the write touches blobs beyond its link operations, in which
    /// case the empty-no-op short-circuit must not fire.
    fn has_blob_side_effects(&self) -> bool {
        !matches!(self, LinksTx::UpdateLinks | LinksTx::DeleteLinks { .. })
    }
}

/// What a planned link write captured, for the post-apply cache steps and the
/// two rejections that leave the plan empty.
#[derive(Default)]
struct LinksTxCaptured {
    written_links: Vec<(LinkKind, LinkMetadata)>,
    deleted_links: Vec<LinkKind>,
    prior_targets: Vec<(LinkKind, Option<Digest>)>,
    /// Set when the last-writer-wins guard rejected the write; the caller maps
    /// it to [`Error::ReplicationSuperseded`].
    superseded: Option<String>,
    /// Set when a strict push referenced a digest the namespace held no entry
    /// for; the caller maps it to [`Error::ManifestBlobUnknown`].
    missing_reference: Option<Digest>,
}

/// The prior link state a committed write was planned against, reported to
/// callers for replication dispatch.
#[derive(Default)]
pub struct LinksCommit {
    /// Prior target per `Create` op's link; `None` = the link did not exist.
    pub prior_targets: Vec<(LinkKind, Option<Digest>)>,
}

impl LinksCommit {
    /// Whether the commit changed `link`. Fails open when the write had no
    /// `Create` op for `link`, so a genuine write is never suppressed.
    #[must_use]
    pub fn changed(&self, link: &LinkKind, target: &Digest) -> bool {
        self.prior_targets
            .iter()
            .find(|(l, _)| l == link)
            .is_none_or(|(_, prior)| prior.as_ref() != Some(target))
    }
}

/// One operation's snapshot from the single per-attempt read pass, borrowing
/// from the originating [`LinkOperation`] so planning never re-reads.
enum OpSnapshot<'a> {
    /// A create with the link's current target, `None` when it does not exist.
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
    /// A delete with the link's stored metadata, boxed because `LinkMetadata`
    /// dwarfs the common `Create` variant. A resolved tag also carries its
    /// winner entry's body, the descriptor fields the tombstone copies.
    Delete {
        link: &'a LinkKind,
        metadata: Option<Box<LinkMetadata>>,
        referrer: &'a Option<Digest>,
        tag_body: Option<TagEntryBody>,
    },
}

struct LinksSnapshot<'a> {
    ops: Vec<OpSnapshot<'a>>,
    /// Current metadata per present `Create` link, consumed by the mutation
    /// builders when merging tracked-link referrers.
    link_cache: HashMap<LinkKind, LinkMetadata>,
}

/// Whether the pushing namespace already holds a reference entry for each
/// newly-referenced digest of a policy-checked push.
type ReferenceOwnership = HashMap<Digest, bool>;

/// The compiled waves of one link write: `refs` land first, `records` after
/// the collector check, `finals` last.
#[derive(Default)]
struct WavePlan {
    refs: Vec<Mutation>,
    records: Vec<Mutation>,
    finals: Vec<Mutation>,
    /// The digests `refs` references, checked against collector runs.
    gc_digests: Vec<Digest>,
}

/// The record and final waves under construction. A push puts its revision
/// record in `records` and its tag entry in `finals`, so a reader resolving a
/// tag sees a complete manifest; a delete tombstones tags in `records` and
/// removes the revision record in `finals`, so tags go first.
struct LinkMutations {
    records: Vec<Mutation>,
    finals: Vec<Mutation>,
    pending_blob_ops: HashMap<Digest, Vec<BlobIndexOperation>>,
    written_links: Vec<(LinkKind, LinkMetadata)>,
    deleted_links: Vec<LinkKind>,
    missing_reference: Option<Digest>,
}

impl LinkMutations {
    fn push_blob_op(&mut self, digest: &Digest, op: BlobIndexOperation) {
        self.pending_blob_ops
            .entry(digest.clone())
            .or_default()
            .push(op);
    }

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

    /// Delete `link`, and its record key too so the legacy fallback cannot
    /// resurrect it. A revision goes last, after the tombstones that reference
    /// it, and the blob-index entry is left for the collector because a
    /// writer-side removal could unpin a blob a concurrent push is committing.
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
    /// Apply a plain link create/delete batch.
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

    /// Delete links, gating each on `source_ts` under last-writer-wins; a
    /// `None` `source_ts` is a plain unconditional client delete. Unlike
    /// [`Self::delete_manifest`] this reclaims no blob data.
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
    /// single-object writes. A failed wave surfaces to the client, and the
    /// replay it prompts is harmless.
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

        // Reference keys land before anything that could commit them.
        let refs_started_at = Instant::now();
        self.apply_writes(&plan.refs).await?;
        if !plan.gc_digests.is_empty() {
            self.gc_backoff(&plan.gc_digests).await?;
            // The clearance vouches for one grace period counted from the
            // reference wave, so a reference wave plus backoff slower than
            // that has to redo the check.
            if refs_started_at.elapsed().as_secs() > self.gc_grace_secs {
                self.gc_backoff(&plan.gc_digests).await?;
            }
        }
        self.apply_writes(&plan.records).await?;
        self.apply_writes(&plan.finals).await?;

        // No directory sweep runs here: an unvalidated prefix delete could
        // erase a link a concurrent push just re-created.
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

    /// Apply one wave, fanning its writes out concurrently; the wave completes
    /// only once every write has.
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

    /// The writer half of the reclamation marker protocol: wait out a covering
    /// collector run briefly, then let the client retry. Both sides aborting
    /// is safe.
    async fn gc_backoff(&self, digests: &[Digest]) -> Result<(), Error> {
        let digests: Vec<&Digest> = digests.iter().collect();
        if self.gc_clear(&digests).await? {
            return Ok(());
        }
        Err(Error::ReclamationInProgress(
            "blob reclamation in progress for a referenced blob; retry".to_string(),
        ))
    }

    /// Snapshot the touched links, gate on no-op, LWW and reference
    /// ownership, then compile the ordered waves.
    async fn plan_links(
        &self,
        namespace: &Namespace,
        operations: &[LinkOperation],
        tx: &LinksTx<'_>,
    ) -> Result<(WavePlan, LinksTxCaptured), Error> {
        let snapshot = self.snapshot_links(namespace, operations).await?;

        if is_empty_noop(&snapshot.ops, tx) {
            return Ok((WavePlan::default(), LinksTxCaptured::default()));
        }

        // A racing writer landing between this read and the waves loses or
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

        let ownership = preread_reference_ownership(self, namespace, &ops, tx).await?;

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

    /// Read each operation's link once, in parallel; a non-`NotFound` read
    /// error fails the attempt rather than being planned around as an absent
    /// link. Repeated operations collapse first, because a manifest may
    /// legally list the same digest twice.
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
            // Tags, revisions and referrers resolve from their write-once
            // shapes: concurrent writers of those kinds write disjoint or
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
                // A tag about to be tombstoned needs its winner entry's body,
                // the one targeted read left off the serving path.
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

/// The last-writer-wins gate: `Some(message)` when a local tag is newer than
/// the replicated source. A racing local tag write appends a fresher entry
/// that wins resolution by timestamp either way.
fn lww_superseded(snapshot: &LinksSnapshot<'_>, tx: &LinksTx<'_>) -> Option<String> {
    // A stored tag timestamp carries the entry ordinal's millisecond
    // precision, so the incoming side must be compared at that precision or an
    // exact-equality tie would read as strictly newer.
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

/// No creates, no blob side effects, and every delete target already missing.
fn is_empty_noop(ops: &[OpSnapshot<'_>], tx: &LinksTx<'_>) -> bool {
    let had_creates = ops.iter().any(|op| matches!(op, OpSnapshot::Create { .. }));
    let all_deletes_absent = ops.iter().all(|op| match op {
        OpSnapshot::Create { .. } => true,
        OpSnapshot::Delete { metadata, .. } => metadata.is_none(),
    });
    !had_creates && !tx.has_blob_side_effects() && all_deletes_absent
}

/// Turn the snapshot's creates and deletes into wave mutations.
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

/// Append a link `Put` per `Create` op, recording the inserted or moved
/// blob-index entries and the written link metadata.
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
            // A newly-referenced digest must already hold a reference entry;
            // Permissive drops the link so the namespace gains no access it
            // did not have.
            if old_target.is_none() && ownership.get(*target) == Some(&false) {
                if tx.reference_policy() == Some(ReferencePolicy::Strict) {
                    acc.missing_reference = Some((*target).clone());
                    return Ok(acc);
                }
                continue;
            }

            // The pin is one write-once key per referring manifest, always
            // written and never merged, so concurrent pushes sharing a blob
            // cannot clobber each other's references.
            if let Some(manifest_digest) = referrer {
                acc.push_blob_op(
                    target,
                    BlobIndexOperation::Insert(LinkKind::ReferencedBy((*manifest_digest).clone())),
                );
            }
        } else {
            let same_target = old_target.as_ref() == Some(*target);
            if !same_target {
                acc.push_blob_op(target, BlobIndexOperation::Insert((*link).clone()));
                if let Some(old) = old_target
                    && *old != **target
                {
                    acc.push_blob_op(old, BlobIndexOperation::Remove((*link).clone()));
                }
            }

            // A same-digest re-push keeps the existing `created_at`: bumping
            // it would let an interleaved peer write lose locally yet win on
            // peers.
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
                    // millisecond is the same key, so a re-push is idempotent
                    // and concurrent writers never contend.
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
                    // No media type, because tag resolution carries none and
                    // the cached write-through must match a fresh resolve.
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

/// For each `Delete` op whose link exists, either prune one referrer, append a
/// tag tombstone, or remove the link outright.
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
            // held because tag history requires it, and its timestamp orders
            // it against any concurrent push by key name alone.
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
            // its own once the referring revision is gone.
            if !matches!(tx, LinksTx::UpdateLinks) {
                continue;
            }
            let mut pruned = (**metadata).clone();
            if let Some(manifest_digest) = referrer {
                pruned.remove_referrer(manifest_digest);
            }

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

/// One reference lookup per newly-referenced digest of a policy-checked push.
/// Writers never remove reference keys, so a raw entry is not ownership: the
/// namespace's own key counts directly, anything else only while
/// [`MetadataStore::reference_backed`] vouches for it.
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

/// Fold `ops` to one final operation per link, last op winning, so the
/// reference wave carries at most one write per key.
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

/// Compile the pending blob-index ops into the reference wave plus the digests
/// it references. The only removal a writer performs is its own ownership key;
/// every other removal is the collector's, because a stale entry merely
/// over-approximates while a writer-side delete could unpin a blob a
/// concurrent push is committing.
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

impl MetadataStore {
    /// Persist a manifest's link metadata and reference keys as ordered
    /// lock-free waves, returning each created link's prior target; the
    /// manifest blob data is written separately by the caller.
    /// `reference_policy` governs newly-referenced unowned digests: Strict
    /// fails with [`Error::ManifestBlobUnknown`], Permissive drops the link,
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

    /// Delete a manifest: tag tombstones and referrer removals land first, the
    /// revision record last. Reference keys and bytes wait for the collector,
    /// which is what the spec's `202 Accepted` licenses.
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
