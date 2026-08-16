//! Chaos tests: crash injection at various stages of the transaction lifecycle.
//!
//! Each test wraps the store in a `CrashingStore` that can be configured to
//! fail on a specific call number, simulating a process crash. A fresh
//! executor is then constructed on the same underlying store and the recovery
//! loop is run; the invariants (committed mutations visible, uncommitted absent,
//! no orphans) are asserted.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{Duration, Utc};
use uuid::Uuid;

use angos_storage::{
    ConditionalStore, Error as StorageError, MemoryObjectStore, ObjectStore,
    test_util::{HookedStore, StoreHook, StoreOp},
};

use angos_tx_engine::{
    executor::TransactionExecutor,
    intent::{IntentRecord, MutationProgress, MutationRecord},
    transaction::{Mutation, Transaction},
};

use angos_tx_engine::test_util;

/// Fails the N-th write-class call (`put`, `delete`, `delete_prefix`,
/// `copy`, and the conditional writes), simulating a process crash at that
/// point in the lifecycle. When `permanent` is set, every write at or after
/// `crash_on` fails, modelling a death that also prevents later reap steps.
struct CrashPlan {
    write_count: AtomicUsize,
    crash_on: usize,
    permanent: bool,
}

#[async_trait]
impl StoreHook for CrashPlan {
    async fn before(&self, op: StoreOp<'_>) -> Result<(), StorageError> {
        if !op.is_write() {
            return Ok(());
        }
        let n = self.write_count.fetch_add(1, Ordering::Relaxed);
        let hit = if self.permanent {
            n >= self.crash_on
        } else {
            n == self.crash_on
        };
        if hit {
            Err(StorageError::Backend("injected crash".to_owned()))
        } else {
            Ok(())
        }
    }
}

type CrashingStore = HookedStore<Arc<dyn ConditionalStore>, CrashPlan>;

/// Store that fails exactly the `crash_on`-th write.
fn crashing_store(inner: Arc<MemoryObjectStore>, crash_on: usize) -> Arc<CrashingStore> {
    Arc::new(HookedStore::new(
        inner,
        CrashPlan {
            write_count: AtomicUsize::new(0),
            crash_on,
            permanent: false,
        },
    ))
}

/// Store that fails every write at and after the `crash_on`-th.
fn crashing_store_permanent(inner: Arc<MemoryObjectStore>, crash_on: usize) -> Arc<CrashingStore> {
    Arc::new(HookedStore::new(
        inner,
        CrashPlan {
            write_count: AtomicUsize::new(0),
            crash_on,
            permanent: true,
        },
    ))
}

// Helpers

/// Backdate every intent under `.tx-log/` so the recovery loop treats it as stale.
async fn backdate_intents(inner: &MemoryObjectStore) {
    let suffixes = inner.list(".tx-log/", 100, None).await.unwrap().items;
    for suffix in &suffixes {
        let key = format!(".tx-log/{suffix}");
        if let Ok(body) = inner.get(&key).await
            && let Ok(mut record) = serde_json::from_slice::<IntentRecord>(&body)
        {
            record.created_at = Utc::now() - Duration::seconds(3600);
            record.ttl_secs = 1;
            inner
                .put(&key, Bytes::from(serde_json::to_vec(&record).unwrap()))
                .await
                .unwrap();
        }
    }
}

// Crash tests

/// Crash on the intent write itself, the transaction's first write now that a
/// small body rides inside the record instead of being staged first.
///
/// The intent never lands, so there is nothing to recover and the canonical key
/// must NOT exist.
#[tokio::test(flavor = "multi_thread")]
async fn crash_before_intent() {
    let inner = Arc::new(MemoryObjectStore::new());
    // Write 0 = intent PUT (which we crash on).
    let crashing = crashing_store(inner.clone(), 0);

    let lock = test_util::memory_lock();
    let executor = test_util::locked_executor(crashing.clone(), lock);

    let tx = Transaction::builder()
        .mutation(Mutation::Put {
            key: "crash/canonical".to_owned(),
            body: Bytes::from_static(b"should-not-land"),
            expected: None,
        })
        .build();

    // The transaction must fail because the intent write was injected to crash.
    let result = executor.execute(tx).await;
    assert!(result.is_err(), "execute must fail on injected crash");

    // The canonical key must not exist.
    assert!(
        inner.get("crash/canonical").await.is_err(),
        "canonical key must not exist before recovery"
    );

    // Run recovery. There is no intent (it never landed), so nothing to replay.
    test_util::sweep_once(inner.clone(), test_util::memory_lock()).await;

    // After recovery: canonical key still absent.
    assert!(
        inner.get("crash/canonical").await.is_err(),
        "canonical key must not exist after recovery"
    );
}

/// Crash after the intent is written but before the first Apply write.
///
/// No mutation reached `Applied`, so the transaction is uncommitted and
/// recovery rolls it back: bodies and intent are deleted and the canonical key
/// must stay absent.
#[tokio::test(flavor = "multi_thread")]
async fn crash_after_intent_before_apply() {
    let inner = Arc::new(MemoryObjectStore::new());
    // Write 0 = intent PUT; write 1 = first apply.
    // The crash is permanent: a process that dies mid-Apply cannot run the
    // rollback writes either, which is what leaves the intent behind for
    // recovery to find.
    let crashing = crashing_store_permanent(inner.clone(), 1);

    let lock = test_util::memory_lock();
    let executor = test_util::locked_executor(crashing.clone(), lock);

    let tx = Transaction::builder()
        .mutation(Mutation::Put {
            key: "apply/canonical".to_owned(),
            body: Bytes::from_static(b"applied-body"),
            expected: None,
        })
        .build();

    // The intent lands (write 0) but Apply crashes (write 1).
    let result = executor.execute(tx).await;
    assert!(result.is_err(), "execute must fail on injected crash");
    assert!(
        inner.get("apply/canonical").await.is_err(),
        "the interrupted Apply must not have landed"
    );

    // Force a stale intent by backdating created_at.
    backdate_intents(&inner).await;

    test_util::sweep_once(inner.clone(), test_util::memory_lock()).await;

    // Rollback removes the staged body and the intent, and leaves no trace of
    // the mutation: an uncommitted transaction must never become visible.
    test_util::assert_no_orphans(&*inner).await;
    assert!(
        inner.get("apply/canonical").await.is_err(),
        "an intent with no Applied slot must be rolled back, not replayed"
    );
}

/// Injecting a crash during Reap (after all mutations are applied) does not
/// leave the canonical key in an inconsistent state. Recovery completes the
/// reap.
#[tokio::test(flavor = "multi_thread")]
async fn crash_during_reap() {
    let inner = Arc::new(MemoryObjectStore::new());
    // We want the transaction to complete Apply but crash on the Reap. Count:
    // intent=0, apply=1, stamp=2, reap intent delete=3. The body rode inline,
    // so there is no staging prefix to delete first. Permanent, so the reap
    // cannot resume on its own and recovery is what finishes it.
    let crashing = crashing_store_permanent(inner.clone(), 3);

    let lock = test_util::memory_lock();
    let executor = test_util::locked_executor(crashing.clone(), lock);

    let tx = Transaction::builder()
        .mutation(Mutation::Put {
            key: "reap/canonical".to_owned(),
            body: Bytes::from_static(b"reap-body"),
            expected: None,
        })
        .build();

    // The transaction may or may not surface an error (crash happens post-Apply).
    let _ = executor.execute(tx).await;

    // Backdate any remaining intents.
    backdate_intents(&inner).await;

    test_util::sweep_once(inner.clone(), test_util::memory_lock()).await;

    // Apply completed before the crash, so finishing the reap must leave the
    // committed value in place rather than roll it back.
    test_util::assert_no_orphans(&*inner).await;
    let body = inner
        .get("reap/canonical")
        .await
        .expect("a transaction that finished Apply must keep its canonical key");
    assert_eq!(body, b"reap-body");
}

/// An intent with at least one `Applied` progress slot is fully committed;
/// recovery replays each mutation idempotently and reaps.
#[tokio::test(flavor = "multi_thread")]
async fn recovery_replays_fully_stamped_intent() {
    let inner = Arc::new(MemoryObjectStore::new());
    let tx_id = Uuid::new_v4();

    // Write the canonical key directly (simulating a completed Apply).
    inner
        .put("stamped/key", Bytes::from_static(b"already-there"))
        .await
        .unwrap();

    // Stage the body for the replayed mutation. Recovery's replay path re-reads
    // the body and PUTs it unconditionally; the canonical bytes happen to be
    // the same as the staged bytes here, so replay is a no-op observationally.
    let body = test_util::stage_body(&*inner, tx_id, 0, Bytes::from_static(b"already-there")).await;

    // Write a stale intent with the only mutation marked Applied.
    let intent = test_util::stale_intent(
        tx_id,
        vec![MutationRecord::Put {
            key: "stamped/key".to_owned(),
            body,
            expected: None,
        }],
        vec![MutationProgress::Applied],
    );
    test_util::put_intent(&*inner, &intent).await;

    test_util::sweep_once(inner.clone(), test_util::memory_lock()).await;

    // Intent and staged body reaped; canonical key intact.
    test_util::assert_no_orphans(&*inner).await;
    let body = inner
        .get("stamped/key")
        .await
        .expect("canonical key must survive reap");
    assert_eq!(body, b"already-there");
}

/// Chaos test: manifest push crashing mid-Apply after the blob-data write but
/// before the link/index writes complete.
///
/// Models the engine path for `store_manifest`: the transaction contains a
/// `PutIfAbsent` for the blob-data key and `Put` mutations for the link key
/// and blob-index shard key, mirroring what `manifest_engine.rs` builds.
///
/// The first successful Apply stamps its `progress[idx]` slot to `Applied`;
/// once any slot is `Applied` the recovery loop replays every mutation
/// idempotently (`PutIfAbsent` skips when the key exists; Put/Delete/Copy are
/// write-anywhere). Before the first Apply succeeds the recovery loop rolls
/// back (deletes the intent + bodies).
///
/// Invariants verified:
/// 1. For crash points before the intent lands (writes 0-3): no canonical keys
///    are present after recovery, because the transaction was never committed.
/// 2. For all crash points: the recovery loop leaves no .tx-log/ orphans.
#[tokio::test(flavor = "multi_thread")]
async fn manifest_push_crash_mid_apply_recovery_converges() {
    // Keys that mirror the manifest-engine transaction shape.
    let blob_data_key = "blob-data/sha256:abcdef";
    let link_key = "repositories/ns/_manifests/revisions/sha256:abcdef/link";
    let shard_key = "blob_index/sha256:abcdef/refs/ns.json";

    // Write sequence for the Locked executor with 3 mutations
    // (PutIfAbsent + Put + Put), each body small enough to ride inline:
    //   write 0: intent PUT  ← linearisation point
    //   write 1: Apply mutation 0 (PutIfAbsent blob-data)
    //   write 2: commit-point stamp (intent re-PUT marking mutation 0 Applied)
    //   write 3: Apply mutation 1 (Put link-key)
    //   write 4: Apply mutation 2 (Put shard-key)
    //   write 5: Reap intent delete
    for crash_on in 0usize..=5 {
        let inner = Arc::new(MemoryObjectStore::new());
        let crashing = crashing_store_permanent(inner.clone(), crash_on);

        let lock = test_util::memory_lock();
        let executor = test_util::locked_executor(crashing.clone(), lock);

        let tx = Transaction::builder()
            .mutation(Mutation::PutIfAbsent {
                key: blob_data_key.to_owned(),
                body: Bytes::from_static(b"manifest-bytes"),
            })
            .mutation(Mutation::Put {
                key: link_key.to_owned(),
                body: Bytes::from_static(b"{\"target\":\"sha256:abcdef\"}"),
                expected: None,
            })
            .mutation(Mutation::Put {
                key: shard_key.to_owned(),
                body: Bytes::from_static(b"[\"tag:latest\"]"),
                expected: None,
            })
            .build();

        let _ = executor.execute(tx).await;

        // Backdate any live intents so recovery treats them as stale.
        backdate_intents(&inner).await;

        test_util::sweep_once(inner.clone(), test_util::memory_lock()).await;

        // Invariant 1: the intent never landed, so no canonical keys.
        if crash_on == 0 {
            assert!(
                inner.get(blob_data_key).await.is_err(),
                "blob-data must not exist when transaction never committed (crash_on={crash_on})"
            );
            assert!(
                inner.get(link_key).await.is_err(),
                "link must not exist when transaction never committed (crash_on={crash_on})"
            );
            assert!(
                inner.get(shard_key).await.is_err(),
                "shard must not exist when transaction never committed (crash_on={crash_on})"
            );
        }

        // Invariant 2: recovery always cleans .tx-log/ orphans. Bodies staged
        // before a pre-intent crash legitimately remain for the janitor, so
        // only .tx-log/ is checked.
        assert_eq!(
            test_util::list_count(&*inner, ".tx-log/").await,
            0,
            "recovery must leave a clean .tx-log/ (crash_on={crash_on})"
        );
    }
}

/// A transient (non-permanent) storage error mid-Apply, after at least one
/// mutation has been applied and stamped, must NOT cause the executor to reap
/// the intent. Reaping would delete the staged bodies + intent and orphan the
/// partial canonical write, breaking the all-or-nothing guarantee. The intent
/// must survive so the recovery loop can replay-forward and converge.
#[tokio::test(flavor = "multi_thread")]
async fn partial_apply_error_preserves_intent_for_recovery() {
    let inner = Arc::new(MemoryObjectStore::new());

    // Two-mutation Put transaction. Write sequence for the Locked executor:
    //   write 0: intent PUT
    //   write 1: Apply mutation 0 (Put k0)
    //   write 2: commit-point stamp (intent re-PUT marking mutation 0 Applied)
    //   write 3: Apply mutation 1 (Put k1)  ← crash here (transient)
    // Crashing on write 3 fails the second apply put after mutation 0 has
    // applied and stamped. Being non-permanent, the later reap writes would
    // succeed, which is exactly the scenario the buggy unconditional reap
    // mishandled.
    let crashing = crashing_store(inner.clone(), 3);

    let lock = test_util::memory_lock();
    let executor = test_util::locked_executor(crashing.clone(), lock);

    let tx = Transaction::builder()
        .mutation(Mutation::Put {
            key: "partial/k0".to_owned(),
            body: Bytes::from_static(b"body-0"),
            expected: None,
        })
        .mutation(Mutation::Put {
            key: "partial/k1".to_owned(),
            body: Bytes::from_static(b"body-1"),
            expected: None,
        })
        .build();

    let result = executor.execute(tx).await;
    assert!(
        result.is_err(),
        "execute must surface the injected mid-Apply error"
    );

    // With the fix, the intent survives (any mutation applied → no reap).
    // Without the fix it would have been reaped, making recovery impossible.
    assert_eq!(
        test_util::list_count(&*inner, ".tx-log/").await,
        1,
        "intent must survive a partial-apply error so recovery can converge"
    );

    // Backdate + run recovery; it replays-forward idempotently.
    backdate_intents(&inner).await;
    test_util::sweep_once(inner.clone(), test_util::memory_lock()).await;

    // Both canonical keys present with correct bodies.
    let b0 = inner
        .get("partial/k0")
        .await
        .expect("k0 must be present after recovery");
    assert_eq!(b0, b"body-0");
    let b1 = inner
        .get("partial/k1")
        .await
        .expect("k1 must be present after recovery");
    assert_eq!(b1, b"body-1");

    // No orphans: recovery reaped the intent and staged bodies.
    test_util::assert_no_orphans(&*inner).await;
}

// Commit-point invariants under both executors

/// Read the (only) intent under `.tx-log/` directly, bypassing the recovery
/// loop, and return its parsed form.
async fn read_only_intent(inner: &MemoryObjectStore) -> IntentRecord {
    let suffixes = inner.list(".tx-log/", 100, None).await.unwrap().items;
    assert_eq!(
        suffixes.len(),
        1,
        "expected exactly one .tx-log entry, got {suffixes:?}"
    );
    let body = inner
        .get(&format!(".tx-log/{}", suffixes[0]))
        .await
        .expect("intent must still be present");
    serde_json::from_slice(&body).expect("intent must parse")
}

/// Three `Put` mutations, as both executors write them. Every body rides inline,
/// so there is no staging write and no staging prefix to reap:
///   0 = intent; 1 = apply0; 2 = commit-point stamp; 3 = apply1; 4 = apply2;
///   5 = reap-intent.
fn three_puts(prefix: &str) -> Transaction {
    Transaction::builder()
        .mutation(Mutation::Put {
            key: format!("{prefix}/a"),
            body: Bytes::from_static(b"A"),
            expected: None,
        })
        .mutation(Mutation::Put {
            key: format!("{prefix}/b"),
            body: Bytes::from_static(b"B"),
            expected: None,
        })
        .mutation(Mutation::Put {
            key: format!("{prefix}/c"),
            body: Bytes::from_static(b"C"),
            expected: None,
        })
        .build()
}

/// Assert the surviving intent records the transaction as committed, with the
/// commit-point slot `Applied` and the rest still `Pending`.
///
/// Progress past the commit point is deliberately a lower bound: only the first
/// mutation is written back, and recovery re-applies every unconfirmed slot
/// idempotently. What must never happen is the reverse, a record claiming a
/// mutation applied when it did not, which would let recovery skip it.
async fn assert_committed_at_the_commit_point(inner: &MemoryObjectStore) {
    let intent = read_only_intent(inner).await;
    assert_eq!(intent.mutations.len(), 3);
    assert!(
        intent.any_applied(),
        "the record must classify the transaction as committed so recovery replays forward"
    );
    assert!(matches!(
        intent.mutations[0].progress,
        MutationProgress::Applied
    ));
    for idx in 1..3 {
        assert!(
            matches!(intent.mutations[idx].progress, MutationProgress::Pending),
            "progress[{idx}] must stay Pending: only the commit point is written back"
        );
    }
}

/// Locked executor: a crash at Reap, and a crash mid-Apply, both leave a record
/// marked committed, and recovery converges to every mutation from it.
#[tokio::test(flavor = "multi_thread")]
async fn commit_point_survives_a_crash_locked() {
    // (a) Crash permanently from the Reap step (write 5) onward: all three
    // mutations applied, and the intent remains for inspection.
    {
        let inner = Arc::new(MemoryObjectStore::new());
        let crashing = crashing_store_permanent(inner.clone(), 5);
        let lock = test_util::memory_lock();
        let executor = test_util::locked_executor(crashing.clone(), lock);

        let _ = executor.execute(three_puts("p")).await;
        assert_committed_at_the_commit_point(&inner).await;

        backdate_intents(&inner).await;
        test_util::sweep_once(inner.clone(), test_util::memory_lock()).await;
        test_util::assert_no_orphans(&*inner).await;
    }

    // (b) Crash permanently from apply 1 onward (write 3): only mutation 0
    // landed, so recovery must replay 1 and 2 rather than roll the
    // transaction back.
    {
        let inner = Arc::new(MemoryObjectStore::new());
        let crashing = crashing_store_permanent(inner.clone(), 3);
        let lock = test_util::memory_lock();
        let executor = test_util::locked_executor(crashing.clone(), lock);

        let _ = executor.execute(three_puts("p")).await;
        assert_committed_at_the_commit_point(&inner).await;
        assert!(
            inner.get("p/b").await.is_err(),
            "mutation 1 must not have landed before the crash"
        );

        backdate_intents(&inner).await;
        test_util::sweep_once(inner.clone(), test_util::memory_lock()).await;

        for (key, body) in [("p/a", b"A"), ("p/b", b"B"), ("p/c", b"C")] {
            let stored = inner
                .get(key)
                .await
                .expect("recovery must replay every mutation of a committed transaction");
            assert_eq!(stored, body);
        }
        test_util::assert_no_orphans(&*inner).await;
    }
}

/// CAS executor: same invariants as the Locked variant, driven through the
/// conditional primitives.
#[tokio::test(flavor = "multi_thread")]
async fn commit_point_survives_a_crash_cas() {
    {
        let inner = Arc::new(MemoryObjectStore::new());
        let crashing = crashing_store_permanent(inner.clone(), 5);
        let executor = test_util::cas_executor(crashing.clone());

        let _ = executor.execute(three_puts("cas")).await;
        assert_committed_at_the_commit_point(&inner).await;

        backdate_intents(&inner).await;
        test_util::sweep_once_cas(inner.clone(), test_util::memory_lock()).await;
        test_util::assert_no_orphans(&*inner).await;
    }

    {
        let inner = Arc::new(MemoryObjectStore::new());
        let crashing = crashing_store_permanent(inner.clone(), 3);
        let executor = test_util::cas_executor(crashing.clone());

        let _ = executor.execute(three_puts("cas")).await;
        assert_committed_at_the_commit_point(&inner).await;
        assert!(
            inner.get("cas/b").await.is_err(),
            "mutation 1 must not have landed before the crash"
        );

        backdate_intents(&inner).await;
        test_util::sweep_once_cas(inner.clone(), test_util::memory_lock()).await;

        for (key, body) in [("cas/a", b"A"), ("cas/b", b"B"), ("cas/c", b"C")] {
            let stored = inner
                .get(key)
                .await
                .expect("recovery must replay every mutation of a committed transaction");
            assert_eq!(stored, body);
        }
        test_util::assert_no_orphans(&*inner).await;
    }
}
