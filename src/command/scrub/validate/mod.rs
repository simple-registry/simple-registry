//! Per-key validation for the scrub walk.
//!
//! [`Validator::process`] takes one raw key, categorizes it, and runs the
//! store-appropriate checks: repair derivable state, delete objects whose
//! content is unreadable, quarantine keys that match no known layout. It is
//! infallible per key (failures are warned and counted), so one bad object
//! never aborts a walk.

mod blob;
mod jobs;
mod link;
mod shard;
#[cfg(test)]
mod tests;

use std::{
    collections::HashSet,
    sync::{Arc, Mutex, atomic::Ordering},
};

use tracing::warn;

use angos_oci::Digest;

use crate::{
    command::maintenance::{
        Error,
        action::{Action, WalkedStore},
        categorize::{KeyCategory, categorize},
        executor::{ActionSink, object_younger_than_grace},
        walk::WalkStats,
    },
    registry::{Error as RegistryError, blob_store::BlobStore, metadata_store::MetadataStore},
};

/// One of the three walk passes. Later passes rely on earlier repairs:
/// links are healed and grants reconciled (M1) before shard entries are
/// pruned against them (M2), and the index is healed before blob GC reads
/// it (B).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pass {
    /// Metadata store, everything except the `v2/blobs/` subtree: links and
    /// job records.
    MetadataLinks,
    /// Metadata store, `v2/blobs/` and `v2/ref/` subtrees: legacy blob-index
    /// shards (converted to reference keys) and the reference keys themselves.
    MetadataShards,
    /// Blob store: blob data and upload artifacts.
    Blob,
}

/// Shared context of one scrub run: the stores, the action sink, and the
/// run counters. One `Arc<Validator>` serves every concurrent per-key task.
pub struct Validator {
    pub blob_store: Arc<BlobStore>,
    pub metadata_store: Arc<MetadataStore>,
    pub sink: Arc<dyn ActionSink>,
    pub stats: Arc<WalkStats>,
    /// Delete unrecognized keys outright instead of quarantining them
    /// (`--delete-unknown`).
    delete_unknown: bool,
    /// Names already handled by a once-per-container emission (invalid
    /// namespaces, orphan upload sessions), so the per-key walk does not
    /// repeat their prefix-level actions.
    handled: Mutex<HashSet<String>>,
    /// Digests exempted from this run's blob GC (see [`Self::hold_blob_gc`]).
    gc_holds: Mutex<HashSet<Digest>>,
    /// Digests the shard walk read live references for (see
    /// [`Self::record_shard_reference`]).
    shard_refs: Mutex<HashSet<Digest>>,
}

impl Validator {
    pub fn new(
        blob_store: Arc<BlobStore>,
        metadata_store: Arc<MetadataStore>,
        sink: Arc<dyn ActionSink>,
        stats: Arc<WalkStats>,
        delete_unknown: bool,
    ) -> Self {
        Self {
            blob_store,
            metadata_store,
            sink,
            stats,
            delete_unknown,
            handled: Mutex::new(HashSet::new()),
            gc_holds: Mutex::new(HashSet::new()),
            shard_refs: Mutex::new(HashSet::new()),
        }
    }

    /// Validate one key. Never fails: every error is warned and counted, so
    /// the walk continues past individual defects.
    pub async fn process(&self, pass: Pass, key: &str) {
        self.stats.keys.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = self.dispatch(pass, key).await {
            self.stats.failures.fetch_add(1, Ordering::Relaxed);
            warn!("scrub: validation failed for key '{key}': {e}");
        }
    }

    async fn dispatch(&self, pass: Pass, key: &str) -> Result<(), Error> {
        let category = categorize(key);
        // Already-quarantined keys are never touched. A leaked probe object
        // is left alone too: deleting it could race a previous binary's
        // startup CAS probe during a rolling upgrade and flip its verdict.
        if matches!(category, KeyCategory::LostAndFound | KeyCategory::Probe) {
            return Ok(());
        }

        match (pass, category) {
            (Pass::MetadataLinks, KeyCategory::TxLeftover) => self.reclaim_tx_leftover(key).await,
            (Pass::MetadataLinks, KeyCategory::Link { namespace, link }) => {
                self.validate_link(key, &namespace, link).await
            }
            (Pass::MetadataLinks, KeyCategory::TagEntry { namespace, tag }) => {
                self.validate_tag_entries(&namespace, &tag).await
            }
            (Pass::MetadataLinks, KeyCategory::TagAtimeEntry { namespace, tag }) => {
                self.collect_tag_atime_entries(&namespace, &tag).await
            }
            (Pass::MetadataLinks, KeyCategory::RevisionAtimeEntry { namespace, digest }) => {
                self.collect_revision_atime_entries(&namespace, &digest)
                    .await
            }
            (Pass::MetadataLinks, KeyCategory::RevisionRecord { namespace, digest }) => {
                self.validate_revision_record(&namespace, &digest).await
            }
            (
                Pass::MetadataLinks,
                KeyCategory::ReferrerRecord {
                    namespace,
                    subject,
                    referrer,
                },
            ) => {
                self.validate_referrer_record(&namespace, &subject, &referrer)
                    .await
            }
            (Pass::MetadataLinks, KeyCategory::JobRecord { queue, state }) => {
                self.validate_job_record(key, queue, state).await
            }
            (Pass::MetadataLinks, KeyCategory::JobIndex { .. }) => {
                self.validate_job_index(key).await
            }
            (Pass::MetadataShards, KeyCategory::BlobIndexShard { digest, namespace }) => {
                self.validate_shard(key, &digest, &namespace).await
            }
            (
                Pass::MetadataShards,
                KeyCategory::BlobRef {
                    digest,
                    namespace,
                    link,
                },
            ) => self.validate_ref(key, &digest, &namespace, link).await,
            (Pass::Blob, KeyCategory::BlobData { digest }) => self.validate_blob(&digest).await,
            (
                Pass::Blob,
                KeyCategory::UploadArtifact {
                    namespace,
                    artifact,
                },
            ) => {
                self.validate_upload_artifact(key, &namespace, artifact)
                    .await
            }
            (pass, KeyCategory::Unknown) => self.quarantine(walked_store(pass), key).await,
            // Anything else is a known category needing nothing here: owned
            // by another pass or the other store (the two stores may share
            // one physical root), write-once tag history under `!hist/`, or
            // a live collector run marker under `v2/gc/`.
            _ => Ok(()),
        }
    }

    /// Emit a repair/reclaim action and count it.
    pub async fn emit(&self, action: Action) -> Result<(), Error> {
        self.sink.apply(action).await?;
        self.stats.repairs.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Whether the metadata key at `key` is younger than the reclamation
    /// grace period. A young key may belong to a push between two of its
    /// waves, so no repair may be derived from (or applied to) it; a missing
    /// key is not young, its absence being the caller's evidence.
    pub async fn younger_than_grace(&self, key: &str) -> Result<bool, Error> {
        let young = object_younger_than_grace(
            self.metadata_store.object_store().as_ref(),
            key,
            self.metadata_store.gc_grace_secs(),
        )
        .await
        .map_err(RegistryError::from)?;
        Ok(young == Some(true))
    }

    /// Reclaim one leftover key of the removed transaction engine. Age-gated
    /// like every other reclaim: a young key may still belong to a live
    /// previous binary during a rolling upgrade.
    async fn reclaim_tx_leftover(&self, key: &str) -> Result<(), Error> {
        if self.younger_than_grace(key).await? {
            return Ok(());
        }
        self.emit(Action::ReclaimTxLeftover {
            key: key.to_string(),
        })
        .await
    }

    /// Handle a key that matches no known layout: quarantined by default,
    /// deleted outright under `--delete-unknown`. Either way it counts in
    /// the run's unknown-key tally.
    async fn quarantine(&self, store: WalkedStore, key: &str) -> Result<(), Error> {
        let action = if self.delete_unknown {
            Action::DeleteUnknownKey {
                store,
                key: key.to_string(),
            }
        } else {
            Action::QuarantineKey {
                store,
                key: key.to_string(),
            }
        };
        self.sink.apply(action).await?;
        self.stats.quarantined.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Delete an expected-shape object whose content is unreadable.
    pub async fn delete_corrupt(&self, store: WalkedStore, key: &str) -> Result<(), Error> {
        self.sink
            .apply(Action::DeleteCorruptObject {
                store,
                key: key.to_string(),
            })
            .await?;
        self.stats.corrupt.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Claim a once-per-container emission. Returns `false` when another key
    /// of the same container already claimed it.
    pub fn claim(&self, token: String) -> bool {
        match self.handled.lock() {
            Ok(mut handled) => handled.insert(token),
            Err(poisoned) => poisoned.into_inner().insert(token),
        }
    }

    /// Exempt `digest` from this run's blob GC. Deleting a corrupt shard
    /// removes references the link pass could not re-grant (the grant write
    /// fails against unreadable shard content), so reclaiming the bytes this
    /// run would destroy a still-referenced blob; the next run re-grants from
    /// the manifests and then GC sees the truth.
    pub fn hold_blob_gc(&self, digest: &Digest) {
        match self.gc_holds.lock() {
            Ok(mut holds) => holds.insert(digest.clone()),
            Err(poisoned) => poisoned.into_inner().insert(digest.clone()),
        };
    }

    /// Whether `digest` was exempted from this run's blob GC.
    pub fn blob_gc_held(&self, digest: &Digest) -> bool {
        match self.gc_holds.lock() {
            Ok(holds) => holds.contains(digest),
            Err(poisoned) => poisoned.into_inner().contains(digest),
        }
    }

    /// Record that the shard walk read a live reference to `digest`. The walk
    /// enumerates the whole store, so this is an independent witness against
    /// the per-blob listing blob GC otherwise decides from.
    pub fn record_shard_reference(&self, digest: &Digest) {
        match self.shard_refs.lock() {
            Ok(mut refs) => refs.insert(digest.clone()),
            Err(poisoned) => poisoned.into_inner().insert(digest.clone()),
        };
    }

    /// Whether the shard walk read a live reference to `digest`.
    pub fn shard_walk_saw_references(&self, digest: &Digest) -> bool {
        match self.shard_refs.lock() {
            Ok(refs) => refs.contains(digest),
            Err(poisoned) => poisoned.into_inner().contains(digest),
        }
    }
}

/// The store a pass walks, for raw-key actions.
fn walked_store(pass: Pass) -> WalkedStore {
    match pass {
        Pass::MetadataLinks | Pass::MetadataShards => WalkedStore::Metadata,
        Pass::Blob => WalkedStore::Blob,
    }
}
