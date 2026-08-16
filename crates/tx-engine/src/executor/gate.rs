//! In-process serialisation of transactions whose conditional writes overlap.
//!
//! The CAS executor coordinates through conditional storage operations alone, so
//! sibling requests in one process race each other: one wins its
//! `put_if_match` and the rest fail a precondition having already staged their
//! bodies and written their intents. Holding a gate over the keys they contend
//! on turns that into a conflict the loser sees while verifying its reads,
//! before it writes anything, and leaves only cross-process contention for the
//! conditional operations to resolve.

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash as _, Hasher as _},
    sync::Arc,
    time::Duration,
};

use tokio::{
    sync::{Mutex, OwnedMutexGuard},
    time::timeout,
};
use tracing::debug;

/// Independent gates the key space is spread over. Two unrelated keys landing on
/// one gate serialise needlessly, which costs a little latency and never
/// correctness, so this only has to sit far above the number of keys one process
/// writes at a time.
const GATES: u64 = 1024;

/// How long a transaction waits for its gates before proceeding uncoordinated.
///
/// The gate only saves work: the conditional operations are what make a commit
/// safe, so a wedged key degrades to the contention that existed without it
/// rather than failing the request. The bound sits past the wait the retry
/// budget it replaces would have cost anyway.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// A fixed set of gates that transactions claim by key.
///
/// Constructed by the executor that owns it; one per process.
pub struct KeyGate {
    gates: Vec<Arc<Mutex<()>>>,
}

impl Default for KeyGate {
    fn default() -> Self {
        Self {
            gates: (0..GATES).map(|_| Arc::new(Mutex::new(()))).collect(),
        }
    }
}

impl KeyGate {
    /// The gate `key` claims.
    fn index(key: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        // The remainder is below `GATES`, so it always fits.
        usize::try_from(hasher.finish() % GATES).unwrap_or_default()
    }

    /// Claim every gate `keys` maps to, holding them until the returned guards
    /// drop.
    ///
    /// Gates are claimed in index order so two transactions whose key sets
    /// overlap can never deadlock against each other. Waiting longer than
    /// [`ACQUIRE_TIMEOUT`] yields no guards and lets the caller proceed
    /// uncoordinated.
    pub async fn acquire(&self, keys: &[String]) -> Vec<OwnedMutexGuard<()>> {
        if keys.is_empty() {
            return Vec::new();
        }
        let mut indices: Vec<usize> = keys.iter().map(|key| Self::index(key)).collect();
        indices.sort_unstable();
        indices.dedup();

        let claim = async {
            let mut guards = Vec::with_capacity(indices.len());
            for index in &indices {
                guards.push(Arc::clone(&self.gates[*index]).lock_owned().await);
            }
            guards
        };
        let Ok(guards) = timeout(ACQUIRE_TIMEOUT, claim).await else {
            debug!(
                keys = keys.len(),
                "Key gate timed out; proceeding on conditional operations alone"
            );
            return Vec::new();
        };
        guards
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::Barrier;

    use super::*;

    /// A key whose gate differs from `other`'s, so a test can hold two gates
    /// without relying on the hash not colliding.
    fn key_on_another_gate(other: &str) -> String {
        (0..)
            .map(|n| format!("k{n}"))
            .find(|key| KeyGate::index(key) != KeyGate::index(other))
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn overlapping_keys_serialise() {
        let gate = KeyGate::default();
        let held = gate.acquire(&["a".to_string()]).await;

        let contended = timeout(Duration::from_millis(50), gate.acquire(&["a".to_string()])).await;
        assert!(
            contended.is_err(),
            "a second claim on the same key must wait for the first"
        );

        drop(held);
        let acquired = timeout(Duration::from_millis(50), gate.acquire(&["a".to_string()])).await;
        assert!(
            acquired.is_ok(),
            "the key must be claimable once the first guard drops"
        );
    }

    /// Transactions that share no key must not wait on each other, or the gate
    /// would serialise the pushes it exists to keep parallel.
    #[tokio::test]
    async fn disjoint_keys_do_not_serialise() {
        let gate = Arc::new(KeyGate::default());
        let other = key_on_another_gate("a");
        let barrier = Arc::new(Barrier::new(2));

        let mut claims = Vec::new();
        for key in ["a".to_string(), other] {
            let (gate, barrier) = (Arc::clone(&gate), Arc::clone(&barrier));
            claims.push(tokio::spawn(async move {
                let _guard = gate.acquire(&[key]).await;
                barrier.wait().await;
            }));
        }
        for claim in claims {
            timeout(Duration::from_secs(5), claim)
                .await
                .expect("disjoint keys must be claimable at the same time")
                .expect("claim task");
        }
    }
}
