//! Shared helpers used by both the CAS and Locked executors.
//!
//! Each function takes `&dyn ObjectStore` (the lowest common trait) so it works
//! with both `ConditionalStore` (CAS executor) and plain `ObjectStore` (Locked
//! executor): both traits are supertraits of `ObjectStore`.

use std::{collections::HashSet, future::Future};

use bytes::Bytes;
use chrono::Utc;
use futures_util::stream::{self, StreamExt};
use serde_json::Value;
use tracing::warn;

use angos_storage::{Error as StorageError, Etag, ObjectStore};

use crate::{
    error::Error,
    executor::STORE_CONCURRENCY,
    intent::{
        INLINE_BODY_MAX_BYTES, INTENT_BODIES_PREFIX, IntentRecord, MutationBody, MutationProgress,
        MutationRecord, PlannedMutation, body_ref_key,
    },
    transaction::{Mutation, Read, Transaction},
};

use uuid::Uuid;

/// Serialise `intent` to JSON and PUT it at its canonical log key.
///
/// # Errors
///
/// Returns [`Error::Serde`] if serialisation fails or [`Error::Storage`] if the
/// PUT operation fails.
pub async fn write_intent(store: &dyn ObjectStore, intent: &IntentRecord) -> Result<(), Error> {
    let key = intent.log_key();
    let body = serde_json::to_vec(intent)?;
    store.put(&key, Bytes::from(body)).await?;
    Ok(())
}

/// Re-PUT `intent` so the progress marked on it survives this process, warning
/// rather than failing: a lost progress write only costs the recovery loop an
/// idempotent re-apply.
pub async fn save_progress(store: &dyn ObjectStore, intent: &IntentRecord) {
    if let Err(e) = write_intent(store, intent).await {
        warn!(
            tx_id = %intent.id,
            error = %e,
            "Failed to persist mutation progress; recovery will re-apply idempotently"
        );
    }
}

/// Mark mutation `idx` `Applied`, persisting the intent only at the commit
/// point, the first mutation to apply, which is what switches recovery from
/// rollback to replay-forward.
///
/// Later marks stay in memory, so the durable record trails the applied set,
/// which is what `Pending` already means: recovery re-applies every unconfirmed
/// slot idempotently. [`finish`] writes the accumulated progress back on the
/// paths that leave the intent behind, so only a process death loses it.
pub async fn stamp_applied(store: &dyn ObjectStore, intent: &mut IntentRecord, idx: usize) {
    let commit_point = !intent.any_applied();
    intent.mark_applied(idx);
    if commit_point {
        save_progress(store, intent).await;
    }
}

/// Carry `body` in the record when it is small enough, otherwise stage it at
/// `.tx-bodies/<tx_id>/<idx>` and record where it went.
///
/// # Errors
///
/// Returns [`Error::Storage`] if the staging PUT fails.
async fn place_body(
    store: &dyn ObjectStore,
    body: &Bytes,
    tx_id: Uuid,
    idx: usize,
) -> Result<MutationBody, Error> {
    if body.len() <= INLINE_BODY_MAX_BYTES {
        return Ok(MutationBody::Inline {
            bytes: body.clone(),
        });
    }
    let body_ref = body_ref_key(tx_id, idx);
    store
        .put(&body_ref, body.clone())
        .await
        .map_err(Error::Storage)?;
    Ok(MutationBody::Staged(body_ref))
}

/// Stage one mutation's body, if it carries one, and return its
/// [`MutationRecord`].
///
/// # Errors
///
/// Returns [`Error::Storage`] if the body PUT fails.
async fn stage_mutation(
    store: &dyn ObjectStore,
    mutation: &Mutation,
    tx_id: Uuid,
    idx: usize,
) -> Result<MutationRecord, Error> {
    match mutation {
        Mutation::Put {
            key,
            body,
            expected,
        } => Ok(MutationRecord::Put {
            key: key.clone(),
            body: place_body(store, body, tx_id, idx).await?,
            expected: expected.clone(),
        }),
        Mutation::PutIfAbsent { key, body } => Ok(MutationRecord::PutIfAbsent {
            key: key.clone(),
            body: place_body(store, body, tx_id, idx).await?,
        }),
        Mutation::Delete { key, expected } => Ok(MutationRecord::Delete {
            key: key.clone(),
            expected: expected.clone(),
        }),
        Mutation::Copy { src, dst } => Ok(MutationRecord::Copy {
            src: src.clone(),
            dst: dst.clone(),
        }),
        Mutation::Move { src, dst } => Ok(MutationRecord::Move {
            src: src.clone(),
            dst: dst.clone(),
        }),
        Mutation::MergeSet { key, add, remove } => Ok(MutationRecord::MergeSet {
            key: key.clone(),
            add: add.clone(),
            remove: remove.clone(),
        }),
    }
}

/// Stage `Put`/`PutIfAbsent` bodies at `.tx-bodies/<tx_id>/<idx>` and return
/// the matching [`MutationRecord`]s for the intent, in mutation order.
///
/// Every staging is awaited even once one fails, so the caller's
/// [`discard_staged_bodies`] has the complete set to reclaim.
///
/// # Errors
///
/// Returns [`Error::Storage`] from the first failing body PUT.
pub async fn stage_bodies(
    store: &dyn ObjectStore,
    tx: &Transaction,
    tx_id: Uuid,
) -> Result<Vec<MutationRecord>, Error> {
    let stagings: Vec<_> = tx
        .mutations
        .iter()
        .enumerate()
        .map(|(idx, mutation)| stage_mutation(store, mutation, tx_id, idx))
        .collect();
    stream::iter(stagings)
        .buffered(STORE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect()
}

/// Assemble the [`IntentRecord`] written at the Commit-intent stage.
///
/// Folds in the read-records mapping (each [`Read`]'s key and the state it
/// observed) and initialises a `Pending` progress slot per mutation. Shared by
/// both executors so the intent literal lives once.
#[must_use]
pub fn build_intent(
    tx_id: Uuid,
    ttl_secs: u64,
    reads: &[Read],
    mutations: Vec<MutationRecord>,
) -> IntentRecord {
    let mutations = mutations
        .into_iter()
        .map(|record| PlannedMutation {
            record,
            progress: MutationProgress::Pending,
        })
        .collect();
    IntentRecord {
        id: tx_id,
        created_at: Utc::now(),
        ttl_secs,
        reads: reads.to_vec(),
        mutations,
    }
}

/// Apply a `Move` idempotently: copy `src` to `dst`, then delete `src`
/// tolerating a missing source.
///
/// Shared by both appliers' reconcile paths ([`apply_object_store`] and
/// [`super::cas::apply_cas`]) so the idempotent Move shape stays in lock-step.
/// The `copy` still propagates errors; only a `NotFound` on the source delete is
/// swallowed so re-application after a partial Move converges.
///
/// # Errors
///
/// Returns the underlying [`angos_storage::Error`] from `copy`, or from
/// `delete` when it fails with anything other than `NotFound`.
pub async fn move_idempotent(
    store: &dyn ObjectStore,
    src: &str,
    dst: &str,
) -> Result<(), StorageError> {
    store.copy(src, dst).await?;
    match store.delete(src).await {
        Ok(()) | Err(StorageError::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Merge `add`/`remove` into the JSON-array set held in `current` (an empty
/// slice for an absent key), returning the re-serialised body or `None` when the
/// set becomes empty and the key should be deleted.
///
/// Members compare by structural JSON equality. `add` and `remove` are assumed
/// disjoint, so apply order does not matter. Shared by both appliers so the
/// CAS retry loop and the locked read-modify-write stay in lock-step.
///
/// # Errors
///
/// Returns [`serde_json::Error`] when `current` is not a JSON array or the
/// merged set fails to serialise.
pub fn merge_json_set(
    current: &[u8],
    add: &[Value],
    remove: &[Value],
) -> Result<Option<Bytes>, serde_json::Error> {
    let mut members: Vec<Value> = if current.is_empty() {
        Vec::new()
    } else {
        serde_json::from_slice(current)?
    };
    members.retain(|member| !remove.contains(member));
    for member in add {
        if !members.contains(member) {
            members.push(member.clone());
        }
    }
    if members.is_empty() {
        return Ok(None);
    }
    Ok(Some(Bytes::from(serde_json::to_vec(&members)?)))
}

/// Apply a [`MutationRecord::MergeSet`] against a plain [`ObjectStore`] under the
/// caller's lock: read the current set, merge, then write or delete. Idempotent
/// in both modes, so recovery replays it unchanged.
///
/// # Errors
///
/// Returns [`Error::Serde`] when the stored body is not a JSON array, or
/// [`Error::Storage`] on a hard storage error.
async fn apply_merge_set_object(
    store: &dyn ObjectStore,
    key: &str,
    add: &[Value],
    remove: &[Value],
) -> Result<(), Error> {
    let current = match store.get(key).await {
        Ok(body) => body,
        Err(StorageError::NotFound) => Vec::new(),
        Err(e) => return Err(Error::Storage(e)),
    };
    match merge_json_set(&current, add, remove)? {
        Some(body) => store.put(key, body).await.map_err(Error::Storage),
        None => match store.delete(key).await {
            Ok(()) | Err(StorageError::NotFound) => Ok(()),
            Err(e) => Err(Error::Storage(e)),
        },
    }
}

/// Per-key precondition-failure semantics shared by [`apply_object_store`] and
/// [`super::cas::apply_cas`]: the op dispatch is identical across both modes,
/// only the handling of a failed precondition (and of an absent target)
/// differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    /// Healthy-path apply: a failed precondition is a hard
    /// `Err(Error::Precondition)` and an absent staged body or delete target
    /// propagates as a storage error.
    Abort,
    /// Recovery reconcile / replay-forward path: already-applied outcomes are
    /// `Ok(())`; only true contention (a live body differing from the staged
    /// body under CAS) is `Err(Error::PartialCommit)`.
    Reconcile,
}

/// Resolve a mutation's bytes: an inline body is already here, a staged one is
/// fetched.
///
/// Returns `Ok(None)` when a staged body is gone and the mutation should be
/// skipped, which only happens in [`ApplyMode::Reconcile`], where a vanished
/// staging object means the canonical write already landed and the prefix was
/// reaped. In [`ApplyMode::Abort`] a missing body propagates as a storage error.
///
/// # Errors
///
/// Returns [`Error::Storage`] on a hard storage error, and in `Abort` mode on a
/// `NotFound` for a staged body.
pub async fn resolve_body(
    store: &dyn ObjectStore,
    body: &MutationBody,
    mode: ApplyMode,
) -> Result<Option<Bytes>, Error> {
    match body {
        MutationBody::Inline { bytes } => Ok(Some(bytes.clone())),
        MutationBody::Staged(key) => match store.get(key).await {
            Ok(bytes) => Ok(Some(Bytes::from(bytes))),
            Err(StorageError::NotFound) if mode == ApplyMode::Reconcile => Ok(None),
            Err(e) => Err(Error::Storage(e)),
        },
    }
}

/// Apply one mutation against a plain [`ObjectStore`] (the Locked-executor world,
/// which has no conditional store). Conditional `Put`/`Delete` are honored via a
/// HEAD/ETag compare under the caller's lock. The conditional-store equivalent is
/// [`super::cas::apply_cas`]; keeping both as mode-parameterized appliers stops
/// the `Move`/`PutIfAbsent`/precondition semantics from drifting.
///
/// # Errors
///
/// In `Abort`, returns [`Error::Precondition`] when a conditional `Put`/`Delete`
/// or a `PutIfAbsent` finds the key in the wrong state. Either mode returns
/// [`Error::Storage`] on a hard storage error.
pub async fn apply_object_store(
    store: &dyn ObjectStore,
    mutation: &MutationRecord,
    mode: ApplyMode,
) -> Result<(), Error> {
    match mutation {
        MutationRecord::Put {
            key,
            body,
            expected,
        } => {
            if mode == ApplyMode::Abort
                && let Some(etag) = expected
            {
                check_expected_match(store, key, etag).await?;
            }
            let Some(bytes) = resolve_body(store, body, mode).await? else {
                return Ok(());
            };
            store.put(key, bytes).await.map_err(Error::Storage)
        }
        MutationRecord::PutIfAbsent { key, body } => match store.head(key).await {
            // Abort: the key exists, so the precondition fails. Reconcile: that is
            // the expected idempotent outcome of a replayed insert.
            Ok(_) => match mode {
                ApplyMode::Abort => Err(Error::Precondition),
                ApplyMode::Reconcile => Ok(()),
            },
            Err(StorageError::NotFound) => {
                let Some(bytes) = resolve_body(store, body, mode).await? else {
                    return Ok(());
                };
                store.put(key, bytes).await.map_err(Error::Storage)
            }
            Err(e) => Err(Error::Storage(e)),
        },
        MutationRecord::Delete { key, expected } => {
            if mode == ApplyMode::Abort
                && let Some(etag) = expected
            {
                match store.head(key).await {
                    Ok(meta) => {
                        if meta.etag.as_ref() != Some(etag) {
                            return Err(Error::Precondition);
                        }
                    }
                    // Already gone: a conditional delete is a no-op success.
                    Err(StorageError::NotFound) => return Ok(()),
                    Err(e) => return Err(Error::Storage(e)),
                }
            }
            match store.delete(key).await {
                Ok(()) => Ok(()),
                Err(StorageError::NotFound) if mode == ApplyMode::Reconcile => Ok(()),
                Err(e) => Err(Error::Storage(e)),
            }
        }
        MutationRecord::Copy { src, dst } => store.copy(src, dst).await.map_err(Error::Storage),
        MutationRecord::Move { src, dst } => match mode {
            ApplyMode::Abort => store.move_object(src, dst).await.map_err(Error::Storage),
            ApplyMode::Reconcile => move_idempotent(store, src, dst)
                .await
                .map_err(Error::Storage),
        },
        MutationRecord::MergeSet { key, add, remove } => {
            apply_merge_set_object(store, key, add, remove).await
        }
    }
}

/// HEAD `key` and require its current `ETag` to equal `expected`, mirroring the
/// CAS executor's `put_if_match` / `delete_if_match`. A missing key, an `ETag`
/// mismatch, or a backend that cannot surface an `ETag` all yield
/// [`Error::Precondition`] (no write).
async fn check_expected_match(
    store: &dyn ObjectStore,
    key: &str,
    expected: &Etag,
) -> Result<(), Error> {
    match store.head(key).await {
        Ok(meta) if meta.etag.as_ref() == Some(expected) => Ok(()),
        Ok(_) | Err(StorageError::NotFound) => Err(Error::Precondition),
        Err(e) => Err(Error::Storage(e)),
    }
}

/// `true` when no key is touched by two of `records`, so they commute and
/// [`apply_rest`] can fan them out.
fn keys_are_distinct(records: &[MutationRecord]) -> bool {
    let mut seen = HashSet::new();
    records
        .iter()
        .flat_map(MutationRecord::all_keys)
        .all(|key| seen.insert(key))
}

/// Apply the mutations that follow the commit point, returning one outcome per
/// record in order.
///
/// They belong to a committed transaction, so every one is applied even after
/// another fails: landing them is what the recovery loop would do anyway, and
/// the caller reconciles the failures from the returned outcomes. A transaction
/// touching one key twice applies serially, keeping the two in order.
pub async fn apply_rest<'a, F, Fut>(
    records: &'a [MutationRecord],
    apply: F,
) -> Vec<Result<(), Error>>
where
    F: Fn(&'a MutationRecord) -> Fut,
    Fut: Future<Output = Result<(), Error>>,
{
    let concurrency = if keys_are_distinct(records) {
        STORE_CONCURRENCY
    } else {
        1
    };
    let applies: Vec<Fut> = records.iter().map(apply).collect();
    stream::iter(applies).buffered(concurrency).collect().await
}

/// Which cleanup path is running, selecting the warn labels and the
/// prefix-delete-failure behaviour for [`cleanup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupMode {
    /// Committed transaction. If the body-prefix delete fails the intent log is
    /// left intact so the recovery loop can retry the full reap on the next
    /// sweep (early return before deleting the log entry).
    Reap,
    /// Failed transaction with no applied mutations. A body-prefix delete
    /// failure is warned but cleanup proceeds to delete the intent log entry.
    Rollback,
}

/// Delete a transaction's staged body objects, then its intent log entry.
///
/// A transaction whose bodies all rode inline staged nothing, so it skips
/// straight to the log entry rather than deleting a prefix that was never
/// written. `mode` selects the warn labels and the prefix-delete-failure
/// behaviour: see [`CleanupMode`].
async fn cleanup(store: &dyn ObjectStore, intent: &IntentRecord, mode: CleanupMode) {
    let prefix = intent.bodies_prefix();
    if intent.has_staged_bodies()
        && let Err(e) = store.delete_prefix(&prefix).await
    {
        match mode {
            CleanupMode::Reap => {
                warn!(
                    tx_id = %intent.id,
                    prefix,
                    error = %e,
                    "Reap: failed to delete body staging objects; intent left for recovery"
                );
                return;
            }
            CleanupMode::Rollback => {
                warn!(
                    tx_id = %intent.id,
                    prefix,
                    error = %e,
                    "Rollback: failed to delete body staging objects"
                );
            }
        }
    }
    let log_key = intent.log_key();
    if let Err(e) = store.delete(&log_key).await {
        match mode {
            CleanupMode::Reap => warn!(
                tx_id = %intent.id,
                key = log_key,
                error = %e,
                "Reap: failed to delete intent log entry"
            ),
            CleanupMode::Rollback => warn!(
                tx_id = %intent.id,
                key = log_key,
                error = %e,
                "Rollback: failed to delete intent log entry"
            ),
        }
    }
}

/// Best-effort reclaim of a transaction's staged bodies on an error return
/// taken before its intent was written, so an aborted attempt leaves no
/// staging garbage behind. A failure here is logged, not surfaced: the caller
/// already has a terminal error, and the body janitor sweeps what is left.
///
/// Safe even when the intent write itself failed ambiguously and the record did
/// land: the intent's slots are all `Pending` until Apply starts, so recovery
/// rolls it back rather than replaying it against the bodies removed here.
pub async fn discard_staged_bodies(store: &dyn ObjectStore, tx_id: Uuid) {
    let prefix = format!("{INTENT_BODIES_PREFIX}/{tx_id}/");
    if let Err(e) = store.delete_prefix(&prefix).await {
        warn!(
            tx_id = %tx_id,
            prefix,
            error = %e,
            "Failed to discard staged bodies of an aborted transaction; the body janitor will reclaim them"
        );
    }
}

/// Reap a committed transaction: delete body staging objects, then the intent
/// log entry.
///
/// If deleting the body prefix fails the intent log is left intact so the
/// recovery loop can retry the full reap on the next sweep.
pub async fn reap(store: &dyn ObjectStore, intent: &IntentRecord) {
    cleanup(store, intent, CleanupMode::Reap).await;
}

/// Roll back a failed transaction: delete staged body objects and the intent
/// log entry.
pub async fn rollback(store: &dyn ObjectStore, intent: &IntentRecord) {
    cleanup(store, intent, CleanupMode::Rollback).await;
}

/// Run the Apply-stage reap gate shared by both executors.
///
/// Reap only when the transaction either fully committed (`apply_result` is
/// `Ok`) or applied nothing (`!intent.any_applied()`). Once any mutation has
/// applied but the transaction did not finish, the intent is preserved so the
/// recovery loop can replay-forward idempotently and converge; reaping here
/// would orphan the partial canonical write. On the `Precondition` +
/// nothing-applied path the executor has already rolled back, so reaping
/// deleted objects here is a harmless no-op. Preserving it also writes the
/// progress accumulated since the commit point back, so the sweep that picks
/// the transaction up skips what already applied.
pub async fn finish(
    store: &dyn ObjectStore,
    apply_result: &Result<(), Error>,
    intent: &IntentRecord,
) {
    if apply_result.is_ok() || !intent.any_applied() {
        reap(store, intent).await;
    } else {
        save_progress(store, intent).await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use bytes::Bytes;
    use tokio::{
        sync::Barrier,
        time::{sleep, timeout},
    };

    use angos_storage::{
        Error as StorageError, MemoryObjectStore, ObjectStore,
        test_util::{HookedStore, StoreHook, StoreOp},
    };

    use crate::{
        executor::TransactionExecutor,
        intent::{INLINE_BODY_MAX_BYTES, INTENT_BODIES_PREFIX, INTENT_LOG_PREFIX},
        test_util::{list_count, locked_executor, memory_lock},
        transaction::{Mutation, Transaction},
    };

    /// The cap decides where a body travels, and either route must land the
    /// same bytes and leave no staging behind.
    #[tokio::test]
    async fn the_cap_decides_whether_a_body_is_staged() {
        for (len, staging_writes) in [(8, 0), (INLINE_BODY_MAX_BYTES + 1, 1)] {
            let store = hooked(PrefixWrites::under(INTENT_BODIES_PREFIX));
            let executor = locked_executor(store.clone(), memory_lock());
            let body = Bytes::from(vec![b'x'; len]);

            executor
                .execute(
                    Transaction::builder()
                        .mutation(Mutation::Put {
                            key: "k".to_owned(),
                            body: body.clone(),
                            expected: None,
                        })
                        .build(),
                )
                .await
                .expect("commit");

            assert_eq!(
                store.hook().count.load(Ordering::Relaxed),
                staging_writes,
                "a {len}-byte body must take {staging_writes} staging write(s)"
            );
            assert_eq!(store.get("k").await.expect("k"), &body[..]);
            assert_eq!(
                list_count(store.as_ref(), ".tx-bodies/").await,
                0,
                "a {len}-byte body must leave no staging behind"
            );
        }
    }

    /// An unconditional `Put` of `key`, the shape every test here builds on.
    fn put(key: &str) -> Mutation {
        Mutation::Put {
            key: key.to_owned(),
            body: Bytes::from(format!("body-{key}")),
            expected: None,
        }
    }

    /// Build a store whose calls run through `hook`, and an executor over it.
    fn hooked<H: StoreHook + 'static>(hook: H) -> Arc<HookedStore<Arc<dyn ObjectStore>, H>> {
        Arc::new(HookedStore::new(
            Arc::new(MemoryObjectStore::new()) as Arc<dyn ObjectStore>,
            hook,
        ))
    }

    /// Counts writes under one prefix, leaving every call to proceed.
    struct PrefixWrites {
        prefix: &'static str,
        count: AtomicUsize,
    }

    impl PrefixWrites {
        fn under(prefix: &'static str) -> Self {
            Self {
                prefix,
                count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl StoreHook for PrefixWrites {
        async fn before(&self, op: StoreOp<'_>) -> Result<(), StorageError> {
            if let StoreOp::Put { key, .. } = op
                && key.starts_with(self.prefix)
            {
                self.count.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        }
    }

    /// A committed transaction writes its intent twice whatever its size: once
    /// to log it, once to record the commit point. Stamping every mutation made
    /// the write path cost one extra round trip per mutation, all of them
    /// against an intent the reap deletes moments later.
    #[tokio::test]
    async fn a_transaction_writes_its_intent_twice_whatever_its_size() {
        for mutations in [1usize, 12] {
            let store = hooked(PrefixWrites::under(INTENT_LOG_PREFIX));
            let executor = locked_executor(store.clone(), memory_lock());

            let mut builder = Transaction::builder();
            for idx in 0..mutations {
                builder = builder.mutation(put(&format!("k{idx}")));
            }
            executor.execute(builder.build()).await.expect("commit");

            assert_eq!(
                store.hook().count.load(Ordering::Relaxed),
                2,
                "{mutations} mutations must still cost two intent writes"
            );
        }
    }

    /// Holds every write to a key under `prefix` until `barrier` releases.
    struct GateWrites {
        prefix: &'static str,
        barrier: Barrier,
    }

    #[async_trait]
    impl StoreHook for GateWrites {
        async fn before(&self, op: StoreOp<'_>) -> Result<(), StorageError> {
            if let StoreOp::Put { key, .. } = op
                && key.starts_with(self.prefix)
            {
                self.barrier.wait().await;
            }
            Ok(())
        }
    }

    /// Only the two mutations past the commit point are gated, so a barrier of
    /// two releases exactly when they overlap and never when applies are
    /// serial.
    #[tokio::test]
    async fn mutations_past_the_commit_point_apply_concurrently() {
        let store = hooked(GateWrites {
            prefix: "gated/",
            barrier: Barrier::new(2),
        });
        let executor = locked_executor(store.clone(), memory_lock());

        let tx = Transaction::builder()
            .mutation(put("commit-point"))
            .mutation(put("gated/a"))
            .mutation(put("gated/b"))
            .build();

        timeout(Duration::from_secs(5), executor.execute(tx))
            .await
            .expect("serial applies would leave the first gated mutation waiting forever")
            .expect("commit");
    }

    /// Delays every write to `key`, so applying it alongside a later mutation
    /// on the same key would let that one land first.
    struct SlowKey {
        key: &'static str,
    }

    #[async_trait]
    impl StoreHook for SlowKey {
        async fn before(&self, op: StoreOp<'_>) -> Result<(), StorageError> {
            if let StoreOp::Put { key, .. } = op
                && key == self.key
            {
                sleep(Duration::from_millis(50)).await;
            }
            Ok(())
        }
    }

    /// Two mutations on one key do not commute, so they apply in order even
    /// though they sit past the commit point. Applying them together would let
    /// the delete land first and leave the key present.
    #[tokio::test]
    async fn mutations_on_one_key_keep_their_order() {
        let store = hooked(SlowKey { key: "shared" });
        let executor = locked_executor(store.clone(), memory_lock());

        let tx = Transaction::builder()
            .mutation(put("commit-point"))
            .mutation(put("shared"))
            .mutation(Mutation::Delete {
                key: "shared".to_owned(),
                expected: None,
            })
            .build();
        executor.execute(tx).await.expect("commit");

        assert!(
            matches!(store.get("shared").await, Err(StorageError::NotFound)),
            "the delete must apply after the put it follows"
        );
    }

    /// A precondition lost on the commit point commits nothing, so the error
    /// stays retriable and the caller re-runs the whole transaction. Past that
    /// point the same failure is a non-retriable partial commit.
    #[tokio::test]
    async fn a_precondition_lost_on_the_commit_point_stays_retriable() {
        let store = hooked(PrefixWrites::under(INTENT_LOG_PREFIX));
        store
            .put("taken", Bytes::from_static(b"held"))
            .await
            .expect("seed");
        let executor = locked_executor(store.clone(), memory_lock());

        let tx = Transaction::builder()
            .mutation(Mutation::PutIfAbsent {
                key: "taken".to_owned(),
                body: Bytes::from_static(b"loses"),
            })
            .mutation(put("sibling"))
            .build();

        let error = executor
            .execute(tx)
            .await
            .expect_err("the commit point loses");
        assert!(
            error.is_retriable(),
            "expected a retriable error, got {error:?}"
        );
        assert!(
            matches!(store.get("sibling").await, Err(StorageError::NotFound)),
            "no mutation may land once the commit point failed"
        );
    }
}
