//! [`JobStore`]: unified job-queue storage, producer, and consumer backed by
//! the shared object store.
//!
//! The queue is lock-free and collector-free. Every mutation is an ordered
//! sequence of idempotent object writes: enqueue dedup and claims rest on
//! atomic `create_if_absent` (degrading to advisory put-settle-verify claims
//! on backends that cannot enforce it), workers serialise on leased claim
//! keys, and each crash window re-runs work instead of losing it (handlers
//! are idempotent, so duplicates are safe).

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::{
    select, spawn,
    task::JoinHandle,
    time::{MissedTickBehavior, interval, sleep},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use uuid::Uuid;

use angos_backoff::{Backoff, jitter_below};
use angos_storage::{Error as StorageError, ObjectStore, Page};

use crate::{
    jobs::{JobState, Queue},
    metrics_provider::metrics_provider,
};

// Storage layout of the durable queues.

pub const JOBS_ROOT: &str = "_jobs";

fn job_pending_dir(queue: &str) -> String {
    format!("{JOBS_ROOT}/pending/{queue}")
}

pub fn job_pending_path(queue: &str, id: &str) -> String {
    format!("{JOBS_ROOT}/pending/{queue}/{id}.json")
}

fn job_failed_dir(queue: &str) -> String {
    format!("{JOBS_ROOT}/failed/{queue}")
}

pub fn job_failed_path(queue: &str, id: &str) -> String {
    format!("{JOBS_ROOT}/failed/{queue}/{id}.json")
}

/// Path to the `lock_key` → `storage_key` dedup index file. Each pending
/// envelope has at most one such file alongside it; `find_pending_with_lock_key`
/// reads it for an O(1) lookup instead of scanning all pending bodies.
pub fn job_lock_key_index_path(queue: &str, lock_key: &LockKey) -> String {
    format!("{JOBS_ROOT}/index/{queue}/{}.json", lock_key.encode())
}

/// Path of the claim key serialising execution of one `lock_key` across
/// workers. Created with `create_if_absent`, leased, refreshed by the holder,
/// and deleted on release; a lapsed lease is taken over by deletion.
pub fn job_claim_path(lock_key: &LockKey) -> String {
    format!("{JOBS_ROOT}/claims/{}.json", lock_key.encode())
}

/// A job's per-key serialization token: at most one worker executes a given
/// lock key at a time, and one pending job per key is kept by the dedup index.
///
/// Valid keys are non-empty and free of `%`, which [`Self::encode`] reserves as
/// its escape character; allowing it would let two distinct keys encode to one
/// index path and falsely dedup.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct LockKey(String);

impl LockKey {
    /// # Errors
    ///
    /// Returns [`Error::InvalidLockKey`] when `key` is empty or contains `%`.
    pub fn new(key: impl Into<String>) -> Result<Self, Error> {
        let key = key.into();
        if key.is_empty() {
            return Err(Error::InvalidLockKey("lock key is empty".to_string()));
        }
        if key.contains('%') {
            return Err(Error::InvalidLockKey(format!(
                "lock key '{key}' contains a reserved '%'"
            )));
        }
        Ok(Self(key))
    }

    /// Percent-encode characters that are unsafe as a filesystem filename or as
    /// part of an S3 key path component, so a key lands on the same path
    /// regardless of backend. Injective: `%` cannot appear in a [`LockKey`], so
    /// no escaped form is reachable by any other key.
    fn encode(&self) -> String {
        self.0
            .chars()
            .map(|c| match c {
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => {
                    format!("%{:02X}", c as u32)
                }
                c => c.to_string(),
            })
            .collect()
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LockKey {
    type Error = Error;

    fn try_from(key: String) -> Result<Self, Error> {
        Self::new(key)
    }
}

impl Serialize for LockKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl fmt::Display for LockKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("job queue initialization failed: {0}")]
    Initialization(String),
    #[error("storage error: {0}")]
    Storage(String),
    /// A job handler failed to do its work (deserialize its payload, reach an
    /// upstream, apply its effect). Distinct from [`Self::Storage`] so a handler
    /// fault does not dead-letter mislabelled as a queue storage error.
    #[error("job execution failed: {0}")]
    Execution(String),
    #[error("invalid lock key: {0}")]
    InvalidLockKey(String),
    #[error("not found")]
    NotFound,
    /// A stored record's body will not deserialize. Distinct from
    /// [`Self::Storage`] so one poison object is skipped rather than aborting
    /// the scan that reached it: the body will not fix itself, where a
    /// transient backend fault must still stop the caller.
    #[error("corrupt record: {0}")]
    Corrupt(String),
    /// The job can never succeed; the runner dead-letters it on the spot
    /// instead of burning its retry budget.
    #[error("terminal failure: {0}")]
    Terminal(String),
}

impl From<StorageError> for Error {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::NotFound => Error::NotFound,
            other => Error::Storage(other.to_string()),
        }
    }
}

/// How claim keys serialise workers on this backend, as determined by
/// [`ensure_claim_support`]'s startup probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimMode {
    /// The backend's `create_if_absent` is honest: one atomic create wins.
    Atomic,
    /// The backend cannot enforce the atomic create; claims fall back to a
    /// put-settle-verify sequence that admits transient claim races.
    Advisory,
}

/// Startup probe for `[global.job_queue]` claim serialisation: create a
/// scratch key twice and read how the backend behaves. An honest backend
/// (second create fails) gets [`ClaimMode::Atomic`]; a dishonest one degrades
/// to [`ClaimMode::Advisory`] with a logged warning, since claims are an
/// efficiency mechanism and correctness rests on handler idempotency. Probe
/// IO errors still fail startup.
pub async fn ensure_claim_support(store: &Arc<dyn ObjectStore>) -> Result<ClaimMode, Error> {
    let key = format!("{JOBS_ROOT}/claims/.probe-{}", Uuid::new_v4());
    let first = store
        .create_if_absent(&key, Bytes::from_static(b"probe"))
        .await;
    let second = store
        .create_if_absent(&key, Bytes::from_static(b"probe"))
        .await;
    let _ = store.delete(&key).await;
    match (first, second) {
        (Ok(true), Ok(false)) => Ok(ClaimMode::Atomic),
        (Ok(_), Ok(_)) => {
            warn!(
                "job queue: the metadata store's backend did not enforce atomic \
                 create-if-absent; falling back to advisory claims: claim races admit \
                 multiple workers, so idempotent jobs may execute more than once until \
                 the losing claimants self-cancel within a refresh period"
            );
            Ok(ClaimMode::Advisory)
        }
        (Err(e), _) | (_, Err(e)) => Err(Error::Storage(format!(
            "[global.job_queue] claim-support probe failed: {e}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Job-queue tunables. `[global.job_queue]` does not change durability (jobs
/// persist under the store's `_jobs/` prefix either way); it switches draining
/// to separate `angos worker` processes and enables the queue-depth gauge.
///
/// Storage is inherited from the shared `[metadata_store]` configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct JobQueueConfig {
    /// Lease on a job claim, in seconds. A crashed worker's jobs are taken
    /// over after this long; the holder refreshes the lease at a third of it.
    #[serde(
        default = "default_claim_ttl_secs",
        deserialize_with = "deserialize_claim_ttl_secs"
    )]
    pub claim_ttl_secs: u64,
    #[serde(
        default = "default_pending_refresh_interval_secs",
        deserialize_with = "deserialize_pending_refresh_interval_secs"
    )]
    pub pending_refresh_interval_secs: u64,
    #[serde(default = "default_pending_ready_horizon_secs")]
    pub pending_ready_horizon_secs: u64,
    #[serde(default = "default_job_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_retry_backoff_min_ms")]
    pub retry_backoff_min_ms: u64,
    #[serde(default = "default_retry_backoff_max_ms")]
    pub retry_backoff_max_ms: u64,
}

impl JobQueueConfig {
    /// The retry policy an operator configured for the durable queue.
    #[must_use]
    pub fn retry_policy(&self) -> JobRetryPolicy {
        JobRetryPolicy {
            max_attempts: self.max_attempts,
            backoff_min_ms: self.retry_backoff_min_ms,
            backoff_max_ms: self.retry_backoff_max_ms,
            claim_ttl_secs: self.claim_ttl_secs,
        }
    }
}

/// The retry budget, backoff bounds, and claim-lease TTL a [`JobStore`]
/// applies. Defaults match the historical in-code constants; the durable
/// queue sources them from [`JobQueueConfig`].
#[derive(Clone, Copy, Debug)]
pub struct JobRetryPolicy {
    pub max_attempts: u32,
    pub backoff_min_ms: u64,
    pub backoff_max_ms: u64,
    pub claim_ttl_secs: u64,
}

impl Default for JobRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: default_job_max_attempts(),
            backoff_min_ms: default_retry_backoff_min_ms(),
            backoff_max_ms: default_retry_backoff_max_ms(),
            claim_ttl_secs: default_claim_ttl_secs(),
        }
    }
}

fn default_job_max_attempts() -> u32 {
    5
}

fn default_retry_backoff_min_ms() -> u64 {
    100
}

fn default_retry_backoff_max_ms() -> u64 {
    10_000
}

fn default_claim_ttl_secs() -> u64 {
    CLAIM_TTL_SECS
}

/// Floor on `claim_ttl_secs`. The holder refreshes at a third of the lease,
/// so a shorter lease lapses before its first refresh can land.
const MIN_CLAIM_TTL_SECS: u64 = 3;

fn deserialize_claim_ttl_secs<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let value = u64::deserialize(deserializer)?;
    if value < MIN_CLAIM_TTL_SECS {
        return Err(serde::de::Error::custom(format!(
            "claim_ttl_secs must be at least {MIN_CLAIM_TTL_SECS} \
             (the lease is refreshed at a third of it)",
        )));
    }
    Ok(value)
}

/// Floor on `pending_refresh_interval_secs`. The same value is the documented
/// S3 floor (sub-5s ticks induce LIST storms when multiple server replicas
/// each refresh in parallel); applying it as a hard config-time guard prevents
/// operators from accidentally configuring `0` or `1` and discovering the
/// consequences in production.
const MIN_PENDING_REFRESH_INTERVAL_SECS: u64 = 5;

fn deserialize_pending_refresh_interval_secs<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<u64, D::Error> {
    let value = u64::deserialize(deserializer)?;
    if value < MIN_PENDING_REFRESH_INTERVAL_SECS {
        return Err(serde::de::Error::custom(format!(
            "pending_refresh_interval_secs must be at least {MIN_PENDING_REFRESH_INTERVAL_SECS} \
             (sub-{MIN_PENDING_REFRESH_INTERVAL_SECS}s refresh ticks induce LIST storms on S3)",
        )));
    }
    Ok(value)
}

fn default_pending_refresh_interval_secs() -> u64 {
    15
}

fn default_pending_ready_horizon_secs() -> u64 {
    600
}

// ---------------------------------------------------------------------------
// JobEnvelope
// ---------------------------------------------------------------------------

/// Envelope that travels through the queue. The `payload` field is untyped so
/// the envelope shape stays stable across payload churn; handlers deserialize
/// it into a concrete type.
///
/// Note: `not_before` is **not** stored on the envelope. It is encoded in the
/// storage key (the filename stem) as a sortable hex unix-millis prefix; see
/// [`make_storage_key`]. The filename is the single source of truth so a
/// claim loop can decide readiness from a LIST result alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobEnvelope {
    pub id: String,
    /// Logical queue; selects the storage prefix and the worker's `--queue`
    /// filter.
    pub queue: Queue,
    /// Job type identifier (e.g. `"cache.fetch_blob"`). Handlers reject
    /// envelopes whose `kind` they do not recognize.
    pub kind: String,
    pub lock_key: LockKey,
    pub created_at: DateTime<Utc>,
    pub attempts: u32,
    /// Retry budget. `None` until [`JobStore::enqueue`] stamps the queue's
    /// configured one, so a caller can pin its own, zero included, without
    /// colliding with "not set yet".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_attempts: Option<u32>,
    pub payload: serde_json::Value,
}

impl JobEnvelope {
    /// Build an envelope with a new UUID v4, default retry budget, and a typed
    /// payload that will be serialized to JSON.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when `lock_key` is not a valid [`LockKey`] or the
    /// payload type cannot be serialized.
    pub fn new<P: Serialize>(
        queue: Queue,
        kind: impl Into<String>,
        lock_key: impl Into<String>,
        payload: &P,
    ) -> Result<Self, Error> {
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            queue,
            kind: kind.into(),
            lock_key: LockKey::new(lock_key)?,
            created_at: Utc::now(),
            attempts: 0,
            max_attempts: None,
            payload: serde_json::to_value(payload).map_err(|e| Error::Execution(e.to_string()))?,
        })
    }
}

// ---------------------------------------------------------------------------
// Storage-key helpers
// ---------------------------------------------------------------------------

/// Width of the hex unix-millis prefix in a storage key. 16 hex chars cover
/// `u64::MAX` milliseconds (well past year 5 billion), so the prefix is
/// fixed-width and lexicographic sort always matches time order.
pub const STORAGE_KEY_PREFIX_LEN: usize = 16;

/// Build a storage key (filename stem) encoding `not_before` as a sortable
/// hex unix-millis prefix followed by `-<id>`. Lexicographic sort of these
/// keys matches time order, so [`JobStore::list_pending`] returns ready
/// envelopes first and the claim loop can stop scanning as soon as it sees a
/// prefix in the future.
///
/// Negative timestamps (pre-1970) clamp to 0; the queue is not meaningful
/// before unix epoch.
pub fn make_storage_key(not_before: DateTime<Utc>, id: &str) -> String {
    let millis = u64::try_from(not_before.timestamp_millis()).unwrap_or(0);
    format!("{millis:016x}-{id}")
}

/// Parse the `not_before` instant encoded in a storage-key prefix. Returns
/// `None` for malformed keys (missing prefix, bad hex). Used by the claim
/// loop to skip backed-off envelopes without reading their bodies.
pub fn parse_not_before(storage_key: &str) -> Option<DateTime<Utc>> {
    let bytes = storage_key.as_bytes();
    if bytes.len() <= STORAGE_KEY_PREFIX_LEN || bytes[STORAGE_KEY_PREFIX_LEN] != b'-' {
        return None;
    }
    let hex = &storage_key[..STORAGE_KEY_PREFIX_LEN];
    let millis = u64::from_str_radix(hex, 16).ok()?;
    DateTime::<Utc>::from_timestamp_millis(i64::try_from(millis).ok()?)
}

/// Hex unix-millis prefix (same format as [`make_storage_key`]) marking the
/// upper bound of the ready window for the autoscaler gauge. Storage keys
/// whose 16-hex prefix compares lexicographically greater are scheduled
/// past the horizon and excluded from the count.
///
/// `horizon_secs` is sourced from
/// [`JobQueueConfig::pending_ready_horizon_secs`].
pub fn pending_ready_cutoff_prefix(horizon_secs: u64) -> String {
    let cutoff =
        Utc::now() + ChronoDuration::seconds(i64::try_from(horizon_secs).unwrap_or(i64::MAX));
    let millis = u64::try_from(cutoff.timestamp_millis()).unwrap_or(u64::MAX);
    format!("{millis:016x}")
}

// ---------------------------------------------------------------------------
// Dedup-index helpers
// ---------------------------------------------------------------------------

/// On-disk shape of the per-`lock_key` dedup index file written alongside
/// every pending envelope. Holds the `storage_key` of the most-recent
/// pending file for this `lock_key`, which lets `find_pending_with_lock_key`
/// do an O(1) `HEAD <pending>` instead of LIST-scanning bodies.
///
/// The index is best-effort: a crash between writing the pending file and
/// writing the index leaves no index (next enqueue dedup-misses, spurious
/// duplicate eventually idempotently handled). A crash between deleting the
/// pending file and the index leaves an orphan index; the next enqueue
/// detects this via the absent pending and self-heals.
#[derive(Debug, Serialize, Deserialize)]
pub struct LockKeyIndex {
    pub storage_key: String,
}

pub fn serialize_lock_key_index(storage_key: &str) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&LockKeyIndex {
        storage_key: storage_key.to_string(),
    })
    .map_err(|e| Error::Storage(format!("failed to serialize lock-key index: {e}")))
}

pub fn parse_lock_key_index(bytes: &[u8]) -> Result<LockKeyIndex, Error> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Storage(format!("failed to parse lock-key index: {e}")))
}

// ---------------------------------------------------------------------------
// Dead-letter serializer
// ---------------------------------------------------------------------------

/// On-disk shape of a dead-letter record.
#[derive(Debug, Serialize)]
struct DeadLetterRecord<'a> {
    #[serde(flatten)]
    envelope: &'a JobEnvelope,
    last_error: &'a str,
    failed_at: DateTime<Utc>,
}

/// Owned, deserializable view of a dead-letter record. The borrowing
/// [`DeadLetterRecord`] is write-only; this is its read counterpart. The
/// flattened envelope plus `last_error`/`failed_at` round-trip the JSON
/// written by [`serialize_dead_letter`].
#[derive(Debug, Clone, Deserialize)]
pub struct DeadLetterRead {
    #[serde(flatten)]
    pub envelope: JobEnvelope,
    pub last_error: String,
    pub failed_at: DateTime<Utc>,
}

pub fn serialize_dead_letter(envelope: &JobEnvelope, last_error: &str) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&DeadLetterRecord {
        envelope,
        last_error,
        failed_at: Utc::now(),
    })
    .map_err(|e| Error::Storage(format!("failed to serialize dead-letter: {e}")))
}

// ---------------------------------------------------------------------------
// JobHandler trait
// ---------------------------------------------------------------------------

/// Executor for a single job kind.
///
/// `execute` applies its effects directly; `Ok(())` reports success and an
/// `Err` fails the job over to the retry/dead-letter policy.
///
/// # Idempotency
///
/// Handlers MUST be idempotent: a lost claim or a crash between execution
/// and cleanup re-runs the job, so a duplicate run is possible but a lost
/// job is not.
#[async_trait]
pub trait JobHandler: Send + Sync {
    async fn execute(&self, envelope: &JobEnvelope) -> Result<(), Error>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of pending envelopes inspected per scan. Deeper queues fall
/// back to lock-based serialization, which is the actual correctness primitive.
pub const MAX_SCAN: u16 = 1000;

/// Maximum value reported by [`JobStore::count_pending`]. The gauge feeds KEDA
/// autoscaling, which only needs ordinal granularity at high queue depths:
/// once the queue exceeds 10x the worker pool size you're at max scale anyway.
/// Capping here bounds S3 `LIST` cost per refresh tick to ~10 paginated calls
/// regardless of how deep the queue actually is. Operators reading the gauge
/// should treat the cap value as "at least this many".
pub const MAX_REPORTED_PENDING: u64 = 10_000;

// ---------------------------------------------------------------------------
// Consumer types
// ---------------------------------------------------------------------------

/// Default lease on a claim key; `[global.job_queue].claim_ttl_secs`
/// overrides it. The holder's refresh task re-stamps the claim at a third
/// of the lease; a claimant finding a lapsed lease takes the key over.
const CLAIM_TTL_SECS: u64 = 60;

/// Advisory-claim settle floor: how long a racing claimant's PUT gets to land
/// before the verify read decides the winner.
const ADVISORY_SETTLE_BASE_MS: u64 = 100;

/// Upper bound on the random extra settle, decorrelating claimants that PUT in
/// the same instant so their verify reads do not tie.
const ADVISORY_SETTLE_JITTER_MS: u64 = 200;

/// The stored body of a claim key.
#[derive(Serialize, Deserialize)]
struct ClaimRecord {
    instance: String,
    expires_at: DateTime<Utc>,
}

/// A held claim: the key, the instance token proving ownership, a flag the
/// refresh task raises when the claim is lost (lapsed or taken over), and
/// the refresh task itself, aborted on drop.
pub struct JobClaim {
    key: String,
    instance: String,
    lost: CancellationToken,
    refresher: Option<JoinHandle<()>>,
}

impl JobClaim {
    /// Whether the lease lapsed or another worker took the key over; the
    /// holder must stop touching queue state it no longer owns.
    fn lost(&self) -> bool {
        self.lost.is_cancelled()
    }
}

impl Drop for JobClaim {
    fn drop(&mut self) {
        if let Some(refresher) = self.refresher.take() {
            refresher.abort();
        }
    }
}

/// A job claimed by a worker, ready to execute. `claim` leases the job's
/// `lock_key`; its refresh task keeps the lease alive, and the claim is
/// released on `complete`/`fail`. `storage_key` identifies the pending file
/// the envelope was loaded from so `complete`/`fail` can delete or rewrite
/// that file.
pub struct ClaimedJob {
    pub envelope: JobEnvelope,
    pub storage_key: String,
    claim: JobClaim,
}

impl ClaimedJob {
    /// Cancelled the moment the claim's lease is lost, so the runner can
    /// abort a handler mid-execution.
    pub fn lock_lost(&self) -> CancellationToken {
        self.claim.lost.clone()
    }

    /// Test-only: a claimed job over a hand-built claim, so runner tests can
    /// drive the lost-claim branch without a backend.
    #[cfg(test)]
    pub fn for_test(envelope: JobEnvelope, storage_key: String, lost: CancellationToken) -> Self {
        let claim = JobClaim {
            key: job_claim_path(&envelope.lock_key),
            instance: String::new(),
            lost,
            refresher: None,
        };
        Self {
            envelope,
            storage_key,
            claim,
        }
    }
}

pub enum FailOutcome {
    Retried { next_at: DateTime<Utc> },
    MovedToDeadLetter,
}

/// Outcome of [`JobStore::complete`]. A failure to commit the work-product +
/// cleanup transaction is **not** surfaced as an error the caller must handle
/// out-of-band: the job is failed over (retried with backoff, or dead-lettered
/// once its budget is spent) so a persistently-failing commit cannot leave the
/// pending file re-claimable in a hot loop. The variant tells the caller which
/// happened for logging.
pub enum CompleteOutcome {
    /// The work commit and queue cleanup landed; the job is done.
    Completed,
    /// The commit (or the dedup-index read that precedes it) failed; the job
    /// was failed over via [`JobStore::fail`] instead.
    FailedOver(FailOutcome),
}

/// Outcome of a single `claim_one` attempt. `claimed` is `Some` when a job was
/// claimed; otherwise `next_ready` carries the soonest `not_before` observed
/// across the scan so the caller can sleep until then rather than polling at
/// full cadence through unchanged backed-off envelopes.
pub struct ClaimOutcome {
    pub claimed: Option<ClaimedJob>,
    pub next_ready: Option<DateTime<Utc>>,
}

impl ClaimOutcome {
    /// How long the caller should idle before the next `claim_one` attempt.
    /// When only backed-off envelopes were seen, the sleep extends to the
    /// soonest `not_before`, clamped to `[poll_interval, max(poll_interval, 1 min)]`
    /// so the worker stops re-reading unchanged envelopes every tick while
    /// still picking up newly-enqueued ready jobs promptly.
    pub fn idle_sleep(&self, poll_interval: Duration) -> Duration {
        let max_sleep = poll_interval.max(Duration::from_mins(1));
        self.next_ready.map_or(poll_interval, |t| {
            (t - Utc::now())
                .to_std()
                .unwrap_or_default()
                .clamp(poll_interval, max_sleep)
        })
    }
}

// ---------------------------------------------------------------------------
// Error conversion helper
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// JobStore: unified producer + consumer + storage
// ---------------------------------------------------------------------------

/// Unified job-queue store: producer (`enqueue`), consumer
/// (`claim_one` / `complete` / `fail`), and raw storage primitives
/// (`list_pending`, `count_pending`, `find_pending_with_lock_key`).
///
/// All writes go straight to the `ObjectStore`: atomicity rests on
/// `create_if_absent` for dedup and claims, and on ordered idempotent
/// writes everywhere else.
///
/// `worker_id` is an optional per-process identifier attached to structured
/// log entries from `claim_one`; supply an empty string or any identifier when
/// constructing for producer-only use.
pub struct JobStore {
    store: Arc<dyn ObjectStore>,
    worker_id: String,
    claim_mode: ClaimMode,
    retry_backoff: Backoff,
    claim_error_backoff: Backoff,
    consecutive_claim_errors: AtomicU32,
    max_attempts: u32,
    /// Claim-lease seconds, clamped at construction so chrono arithmetic on
    /// it cannot overflow.
    claim_ttl_secs: i64,
}

impl JobStore {
    /// Construct a new `JobStore`.
    ///
    /// `worker_id` is a structured-log tag that makes concurrent workers'
    /// `claim_one` actions distinguishable in aggregated logs. Pass an empty
    /// string for producer-only instances. `claim_mode` is the probed claim
    /// serialisation mode (see [`ensure_claim_support`]); pass
    /// [`ClaimMode::Atomic`] when the backend is known honest. The retry
    /// policy defaults to [`JobRetryPolicy::default`]; the durable queue
    /// overrides it with [`Self::with_retry_policy`].
    pub fn new(
        store: Arc<dyn ObjectStore>,
        worker_id: impl Into<String>,
        claim_mode: ClaimMode,
    ) -> Self {
        Self::with_retry_policy(store, worker_id, claim_mode, JobRetryPolicy::default())
    }

    /// [`Self::new`] with an operator-configured retry policy (see
    /// [`JobQueueConfig::retry_policy`]).
    pub fn with_retry_policy(
        store: Arc<dyn ObjectStore>,
        worker_id: impl Into<String>,
        claim_mode: ClaimMode,
        retry: JobRetryPolicy,
    ) -> Self {
        let backoff = || {
            Backoff::exponential(
                Duration::from_millis(retry.backoff_min_ms),
                Duration::from_millis(retry.backoff_max_ms),
            )
        };
        Self {
            store,
            worker_id: worker_id.into(),
            claim_mode,
            retry_backoff: backoff(),
            claim_error_backoff: backoff(),
            consecutive_claim_errors: AtomicU32::new(0),
            max_attempts: retry.max_attempts,
            claim_ttl_secs: i64::try_from(retry.claim_ttl_secs)
                .unwrap_or(i64::MAX)
                .clamp(1, 86_400),
        }
    }

    // -----------------------------------------------------------------------
    // Storage primitives
    // -----------------------------------------------------------------------

    /// List up to `n` pending storage keys in ascending order. Storage keys
    /// start with a sortable hex-millis prefix, so callers can stop scanning
    /// at the first key whose prefix is in the future.
    pub async fn list_pending(&self, queue: Queue, n: u16) -> Result<Vec<String>, Error> {
        let prefix = job_pending_dir(queue.as_str());
        let page = self.store.list(&prefix, n, None).await?;

        Ok(page
            .items
            .into_iter()
            .filter_map(|name| name.strip_suffix(".json").map(str::to_string))
            .collect())
    }

    pub async fn read_pending(
        &self,
        queue: Queue,
        storage_key: &str,
    ) -> Result<JobEnvelope, Error> {
        let key = job_pending_path(queue.as_str(), storage_key);
        let data = self.store.get(&key).await?;
        serde_json::from_slice(&data)
            .map_err(|e| Error::Corrupt(format!("failed to parse envelope: {e}")))
    }

    /// Read a dead-letter record by `storage_key`. Returns [`Error::NotFound`]
    /// when the record is absent (e.g. a stale key the UI is still showing).
    pub async fn read_failed(
        &self,
        queue: Queue,
        storage_key: &str,
    ) -> Result<DeadLetterRead, Error> {
        let key = job_failed_path(queue.as_str(), storage_key);
        let data = self.store.get(&key).await?;
        serde_json::from_slice(&data)
            .map_err(|e| Error::Corrupt(format!("failed to parse dead-letter: {e}")))
    }

    /// One keyset page of pending storage keys in ascending (time) order. Pass
    /// `after = Some(last_key)` from a previous page to resume; the cursor is
    /// the plain storage key (non-opaque). The returned `next` is `Some(key)`
    /// when the backend reports more entries beyond this page.
    pub async fn list_pending_page(
        &self,
        queue: Queue,
        n: u16,
        after: Option<&str>,
    ) -> Result<Page<String>, Error> {
        self.list_page(&job_pending_dir(queue.as_str()), n, after)
            .await
    }

    /// One keyset page of dead-letter storage keys in ascending (failure-time)
    /// order. See [`Self::list_pending_page`] for the cursor contract.
    pub async fn list_failed_page(
        &self,
        queue: Queue,
        n: u16,
        after: Option<&str>,
    ) -> Result<Page<String>, Error> {
        self.list_page(&job_failed_dir(queue.as_str()), n, after)
            .await
    }

    /// Shared keyset pager over a job directory. Children are flat `<key>.json`
    /// files, so `list_children` returns them as bare `objects` in lexicographic
    /// (== time) order; `start_after` skips up to and including its argument, so
    /// the cursor is suffixed with `.json` to match the stored child name.
    async fn list_page(
        &self,
        dir: &str,
        n: u16,
        after: Option<&str>,
    ) -> Result<Page<String>, Error> {
        let start_after = after.map(|k| format!("{k}.json"));
        let page = self.store.list_children(dir, n, None, start_after).await?;
        let keys: Vec<String> = page
            .objects
            .into_iter()
            .filter_map(|name| name.strip_suffix(".json").map(str::to_string))
            .collect();
        // The backend's `next_token` is the accurate "more entries exist"
        // signal; surface our own last storage key as the (non-opaque) cursor.
        let next_token = page
            .next_token
            .is_some()
            .then(|| keys.last().cloned())
            .flatten();
        Ok(Page {
            items: keys,
            next_token,
        })
    }

    /// Count pending envelopes ready for handling within
    /// `[..., now + ready_horizon_secs]`. Capped at [`MAX_REPORTED_PENDING`].
    pub async fn count_pending(&self, queue: Queue, ready_horizon_secs: u64) -> Result<u64, Error> {
        let prefix = job_pending_dir(queue.as_str());
        let cutoff_prefix = pending_ready_cutoff_prefix(ready_horizon_secs);
        let mut count: u64 = 0;
        let mut token: Option<String> = None;
        loop {
            let page = self.store.list(&prefix, 1000, token).await?;
            for name in &page.items {
                let Some(stem) = name.strip_suffix(".json") else {
                    continue;
                };
                // Storage list returns lex-sorted keys, which equals `not_before`
                // order due to the fixed-width hex unix-millis prefix. Stop
                // counting at the first key past the readiness cutoff.
                if let Some(p) = stem.get(..STORAGE_KEY_PREFIX_LEN)
                    && p > cutoff_prefix.as_str()
                {
                    return Ok(count.min(MAX_REPORTED_PENDING));
                }
                count += 1;
                if count >= MAX_REPORTED_PENDING {
                    return Ok(MAX_REPORTED_PENDING);
                }
            }
            match page.next_token {
                Some(t) => token = Some(t),
                None => return Ok(count),
            }
        }
    }

    /// Count dead-lettered envelopes in `queue`, capped at
    /// [`MAX_REPORTED_PENDING`]. Feeds the server-published
    /// `angos_job_queue_failed` gauge so dead-letters stay observable even when
    /// `angos worker` (which has no metrics endpoint) drains the queue.
    pub async fn count_failed(&self, queue: Queue) -> Result<u64, Error> {
        let prefix = job_failed_dir(queue.as_str());
        let mut count: u64 = 0;
        let mut token: Option<String> = None;
        loop {
            let page = self.store.list(&prefix, 1000, token).await?;
            for name in &page.items {
                if name.strip_suffix(".json").is_none() {
                    continue;
                }
                count += 1;
                if count >= MAX_REPORTED_PENDING {
                    return Ok(MAX_REPORTED_PENDING);
                }
            }
            match page.next_token {
                Some(t) => token = Some(t),
                None => return Ok(count),
            }
        }
    }

    /// `true` when any pending job in `queue` carries `lock_key`. Best-effort
    /// dedup backed by an O(1) index file written alongside each pending
    /// envelope (see [`LockKeyIndex`]).
    ///
    /// When the index references a pending file that has vanished (orphan),
    /// the stale index is removed read-then-delete: a concurrent enqueue
    /// refreshing the index in that window loses its entry, which only costs
    /// a missed dedup later. A transient failure to delete the orphan is
    /// returned as an error rather than `false`, so the caller never proceeds
    /// to an enqueue the lingering index would silently coalesce away.
    pub async fn find_pending_with_lock_key(
        &self,
        queue: Queue,
        lock_key: &LockKey,
    ) -> Result<bool, Error> {
        let index_path = job_lock_key_index_path(queue.as_str(), lock_key);
        let data = match self.store.get(&index_path).await {
            Ok(d) => d,
            Err(StorageError::NotFound) => return Ok(false),
            Err(e) => return Err(Error::from(e)),
        };
        let index = parse_lock_key_index(&data)?;

        let pending_key = job_pending_path(queue.as_str(), &index.storage_key);
        match self.store.head(&pending_key).await {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound) => {
                // Orphan: pending file vanished but the index lingers. Remove
                // it so the caller's enqueue does not collide on the atomic
                // create and drop a distinct job as a false dedup hit. A
                // concurrent enqueue refreshing the index in the window loses
                // its entry, which only costs a missed dedup later.
                match self.store.delete(&index_path).await {
                    Ok(()) => Ok(false),
                    Err(e) => {
                        warn!(
                            lock_key = %lock_key,
                            error = %e,
                            "Failed to remove orphan lock-key index",
                        );
                        Err(Error::from(e))
                    }
                }
            }
            Err(e) => Err(Error::from(e)),
        }
    }

    pub async fn get_raw(&self, key: &str) -> Result<Vec<u8>, Error> {
        self.store.get(key).await.map_err(Error::from)
    }

    /// Retire the dedup index of a just-claimed job so a same-`lock_key`
    /// enqueue arriving mid-execution starts a fresh pending file rather than
    /// coalescing into the already-resolved job and silently dropping its write.
    /// The pending file stays as the crash-recovery record, and the delete is
    /// read-then-delete on the index's content so a producer's newer index is
    /// never clobbered.
    ///
    /// Returns whether the index is known not to point at `storage_key` any
    /// more: retired here, already absent, pointing elsewhere, or swung by a
    /// producer between the read and the apply (the guard's `Conflict` /
    /// `Precondition`). `false` means the claim must not proceed, since a stale
    /// index left in place coalesces every same-`lock_key` enqueue into a job
    /// that is already running.
    async fn retire_claimed_index(
        &self,
        queue: Queue,
        lock_key: &LockKey,
        storage_key: &str,
    ) -> bool {
        match self
            .cleanup_index_if_ours(queue, lock_key, storage_key)
            .await
        {
            Ok(()) => true,
            Err(e) => {
                warn!(%lock_key, error = %e, "Failed to retire dedup index at claim");
                false
            }
        }
    }

    /// Delete the dedup index when it still points at `storage_key` (or does
    /// not parse). Read-then-delete: a producer re-pointing the index in the
    /// window loses its entry, which only costs a missed dedup, never a job,
    /// because pending files are claimed off the scan, not the index.
    async fn cleanup_index_if_ours(
        &self,
        queue: Queue,
        lock_key: &LockKey,
        storage_key: &str,
    ) -> Result<(), Error> {
        let index_path = job_lock_key_index_path(queue.as_str(), lock_key);
        let ours = match self.get_raw(&index_path).await {
            Ok(body) => {
                parse_lock_key_index(&body).map_or(true, |index| index.storage_key == storage_key)
            }
            Err(Error::NotFound) => return Ok(()),
            Err(e) => return Err(e),
        };
        if ours {
            self.store.delete(&index_path).await?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Claims: create-if-absent keys plus leases
    // -----------------------------------------------------------------------

    /// Try to claim `lock_key`: one atomic create of the claim key; a held
    /// unexpired claim yields `None`, a lapsed one is deleted and re-created.
    /// The takeover is deliberately unfenced: racing claimants may both
    /// execute briefly (each loser's refresher notices within one refresh
    /// period), costing a duplicate run of an idempotent handler, never a
    /// lost job.
    async fn try_claim(&self, lock_key: &LockKey) -> Result<Option<JobClaim>, Error> {
        let key = job_claim_path(lock_key);
        let instance = Uuid::new_v4().to_string();
        let mut stamped_until = self.acquire_claim(&key, &instance).await?;
        if stamped_until.is_none() {
            if !self.claim_is_stale(&key).await? {
                return Ok(None);
            }
            self.store.delete(&key).await?;
            stamped_until = self.acquire_claim(&key, &instance).await?;
        }
        let Some(stamped_until) = stamped_until else {
            return Ok(None);
        };
        let lost = CancellationToken::new();
        let refresher = spawn(refresh_claim_loop(
            self.store.clone(),
            key.clone(),
            instance.clone(),
            stamped_until,
            self.claim_ttl_secs,
            lost.clone(),
        ));
        Ok(Some(JobClaim {
            key,
            instance,
            lost,
            refresher: Some(refresher),
        }))
    }

    /// Acquire the claim record per the probed [`ClaimMode`]. Advisory
    /// acquisition can let two claimants transiently coexist; that stays safe
    /// because every downstream path (lease refresh, release, complete/fail)
    /// detects a foreign instance in the record and stands down.
    async fn acquire_claim(
        &self,
        key: &str,
        instance: &str,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        match self.claim_mode {
            ClaimMode::Atomic => self.put_claim_if_absent(key, instance).await,
            ClaimMode::Advisory => self.put_claim_advisory(key, instance).await,
        }
    }

    /// Advisory acquisition for backends whose `create_if_absent` is not
    /// honest: lose to a fresh foreign record, otherwise put our record,
    /// settle, and win only if the record read back still carries this
    /// instance.
    async fn put_claim_advisory(
        &self,
        key: &str,
        instance: &str,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        match self.store.get(key).await {
            Ok(raw) => {
                if let Ok(record) = serde_json::from_slice::<ClaimRecord>(&raw)
                    && record.instance != instance
                    && record.expires_at >= Utc::now()
                {
                    return Ok(None);
                }
            }
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(Error::from(e)),
        }
        let record = ClaimRecord {
            instance: instance.to_string(),
            expires_at: Utc::now() + ChronoDuration::seconds(self.claim_ttl_secs),
        };
        let body = Bytes::from(
            serde_json::to_vec(&record)
                .map_err(|e| Error::Storage(format!("claim serialization failed: {e}")))?,
        );
        self.store.put(key, body).await?;
        sleep(Duration::from_millis(
            ADVISORY_SETTLE_BASE_MS + jitter_below(ADVISORY_SETTLE_JITTER_MS + 1),
        ))
        .await;
        match self.store.get(key).await {
            Ok(raw) => Ok(serde_json::from_slice::<ClaimRecord>(&raw)
                .ok()
                .filter(|read_back| read_back.instance == instance)
                .map(|read_back| read_back.expires_at)),
            Err(StorageError::NotFound) => Ok(None),
            Err(e) => Err(Error::from(e)),
        }
    }

    /// Atomically create the claim record; returns its `expires_at` when the
    /// create won, `None` when the key already exists.
    async fn put_claim_if_absent(
        &self,
        key: &str,
        instance: &str,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        let record = ClaimRecord {
            instance: instance.to_string(),
            expires_at: Utc::now() + ChronoDuration::seconds(self.claim_ttl_secs),
        };
        let body = Bytes::from(
            serde_json::to_vec(&record)
                .map_err(|e| Error::Storage(format!("claim serialization failed: {e}")))?,
        );
        let created = self.store.create_if_absent(key, body).await?;
        Ok(created.then_some(record.expires_at))
    }

    /// Whether the claim at `key` is safe to take over: its lease lapsed, or
    /// it is unreadable and old enough that no live refresher can own it.
    async fn claim_is_stale(&self, key: &str) -> Result<bool, Error> {
        match self.store.get(key).await {
            Ok(raw) => {
                if let Ok(record) = serde_json::from_slice::<ClaimRecord>(&raw) {
                    return Ok(record.expires_at < Utc::now());
                }
            }
            Err(StorageError::NotFound) => return Ok(true),
            Err(e) => return Err(Error::from(e)),
        }
        // Unreadable: age it on its mtime so a corrupt claim cannot wedge
        // the lock key forever, with double the lease as the safety margin.
        let meta = match self.store.head(key).await {
            Ok(meta) => meta,
            Err(StorageError::NotFound) => return Ok(true),
            Err(e) => return Err(Error::from(e)),
        };
        // A backend that reports no timestamp gives corruption nothing to
        // age against; read it as stale, since duplicate execution is
        // tolerated and a wedged lock key is not.
        Ok(meta.last_modified.is_none_or(|modified| {
            Utc::now().signed_duration_since(modified).num_seconds() > self.claim_ttl_secs * 2
        }))
    }

    /// Release a claim the holder still owns; a lost or taken-over claim is
    /// left for its new owner.
    async fn release_claim(&self, mut claim: JobClaim) {
        if let Some(refresher) = claim.refresher.take() {
            refresher.abort();
        }
        if claim.lost() {
            return;
        }
        match self.store.get(&claim.key).await {
            Ok(raw) => {
                if serde_json::from_slice::<ClaimRecord>(&raw)
                    .is_ok_and(|record| record.instance == claim.instance)
                    && let Err(e) = self.store.delete(&claim.key).await
                {
                    warn!("job queue: failed to release claim '{}': {e}", claim.key);
                }
            }
            Err(StorageError::NotFound) => {}
            Err(e) => warn!(
                "job queue: failed to read claim '{}' at release: {e}",
                claim.key
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Producer: enqueue
    // -----------------------------------------------------------------------

    /// Enqueue a job.
    ///
    /// Fast-path: `find_pending_with_lock_key` checks the dedup index and
    /// self-heals orphans (same semantics as a HEAD index + HEAD pending).
    ///
    /// Slow-path: atomic `create_if_absent` on the index, then the pending
    /// file. If two replicas race and both observe absence, only one create
    /// wins; the loser is treated as a dedup hit.
    pub async fn enqueue(&self, mut envelope: JobEnvelope) -> Result<(), Error> {
        // Apply the queue's configured retry budget unless a caller pinned one.
        envelope.max_attempts.get_or_insert(self.max_attempts);

        // Fast path: index present and pending exists, a hit, no writes needed.
        // A lookup error (including a failed orphan self-heal) is propagated
        // rather than swallowed as a miss, so a lingering orphan index cannot
        // make the slow-path `PutIfAbsent` coalesce this distinct job away.
        if self
            .find_pending_with_lock_key(envelope.queue, &envelope.lock_key)
            .await?
        {
            metrics_provider()
                .job_queue_enqueued_total
                .with_label_values(&[envelope.queue.as_str(), "hit"])
                .inc();
            return Ok(());
        }

        // Slow path: index first, then pending, both atomic creates. Losing
        // the index race means another replica enqueued this `lock_key`: a
        // dedup hit, not an error. A crash between the two leaves an orphan
        // index that `find_pending_with_lock_key` self-heals.
        let storage_key = make_storage_key(Utc::now(), &envelope.id);
        let pending_path = job_pending_path(envelope.queue.as_str(), &storage_key);
        let index_path = job_lock_key_index_path(envelope.queue.as_str(), &envelope.lock_key);

        let pending_body = Bytes::from(
            serde_json::to_vec(&envelope)
                .map_err(|e| Error::Storage(format!("envelope serialization failed: {e}")))?,
        );
        let index_body = Bytes::from(serialize_lock_key_index(&storage_key)?);

        let objects = &self.store;
        let outcome = if objects.create_if_absent(&index_path, index_body).await? {
            objects
                .create_if_absent(&pending_path, pending_body)
                .await?;
            "miss"
        } else {
            "hit"
        };
        metrics_provider()
            .job_queue_enqueued_total
            .with_label_values(&[envelope.queue.as_str(), outcome])
            .inc();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Consumer: claim / complete / fail
    // -----------------------------------------------------------------------

    /// Claim the next available job from `queue`, self-throttling on backend
    /// failure: a storage error sleeps an exponential, capped backoff before
    /// returning so the caller can loop without managing retry timing itself.
    /// The backoff resets on the next successful claim.
    pub async fn claim_one(&self, queue: Queue) -> Result<ClaimOutcome, Error> {
        match self.try_claim_one(queue).await {
            Ok(outcome) => {
                self.consecutive_claim_errors.store(0, Ordering::Relaxed);
                Ok(outcome)
            }
            Err(error) => {
                let attempt = self
                    .consecutive_claim_errors
                    .fetch_add(1, Ordering::Relaxed);
                sleep(self.claim_error_backoff.delay(attempt)).await;
                Err(error)
            }
        }
    }

    /// Walk pending storage keys in ascending order (`list_pending` returns
    /// them sorted by the hex unix-millis prefix, i.e. by `not_before`). Stops
    /// at the first key whose prefix is in the future without reading its body:
    /// the prefix is the authoritative readiness signal. When no claim is made,
    /// `next_ready` carries that first future instant so the caller can sleep
    /// until then.
    ///
    /// On a successful claim the job's dedup index is retired (see
    /// [`Self::retire_claimed_index`]) so a same-`lock_key` enqueue arriving
    /// while the job runs is not coalesced into the already-resolved job.
    /// Drop a pending record whose body will not parse. The scan walks keys in
    /// ascending time order, so leaving it would strand every job queued after
    /// it; keeping it would only re-warn on every scan, since the body cannot
    /// name the work it stood for. Both queues converge without it: a cache
    /// fill re-enqueues on the next pull-through, and a replication push on the
    /// next write or `angos replicate` sweep. Its dedup index entry is left to
    /// `prune`'s orphan-job sweep.
    async fn discard_poison_pending(&self, queue: Queue, storage_key: &str, reason: &str) {
        let path = job_pending_path(queue.as_str(), storage_key);
        match self.store.delete(&path).await {
            Ok(()) => {
                warn!("job queue: discarded unreadable pending job '{storage_key}': {reason}");
            }
            Err(e) => {
                warn!(
                    "job queue: unreadable pending job '{storage_key}' ({reason}) not deleted: {e}"
                );
            }
        }
    }

    async fn try_claim_one(&self, queue: Queue) -> Result<ClaimOutcome, Error> {
        let now = Utc::now();
        let mut next_ready: Option<DateTime<Utc>> = None;
        for storage_key in self.list_pending(queue, MAX_SCAN).await? {
            // Read the readiness time off the filename; never GET the body for
            // a backed-off entry. A missing/malformed prefix falls through to
            // the body read so legacy keys (if any) still work.
            if let Some(not_before) = parse_not_before(&storage_key)
                && not_before > now
            {
                next_ready = Some(not_before);
                break;
            }
            let envelope = match self.read_pending(queue, &storage_key).await {
                Ok(e) => e,
                Err(Error::NotFound) => continue,
                Err(Error::Corrupt(e)) => {
                    self.discard_poison_pending(queue, &storage_key, &e).await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            if let Some(claim) = self.try_claim(&envelope.lock_key).await? {
                // Re-read under the claim: another worker may have completed
                // this job (deleting the pending file) between the first read
                // and the claim. Without this the stale envelope would be
                // re-run and could dead-letter a finished job.
                let envelope = match self.read_pending(queue, &storage_key).await {
                    Ok(envelope) => envelope,
                    Err(Error::NotFound) => {
                        self.release_claim(claim).await;
                        continue;
                    }
                    Err(Error::Corrupt(e)) => {
                        self.discard_poison_pending(queue, &storage_key, &e).await;
                        self.release_claim(claim).await;
                        continue;
                    }
                    Err(e) => {
                        self.release_claim(claim).await;
                        return Err(e);
                    }
                };
                // Claiming while the index still points at this job would let
                // every same-`lock_key` enqueue coalesce into it for the whole
                // execution and drop its write, so leave the job for the next
                // scan instead.
                if !self
                    .retire_claimed_index(queue, &envelope.lock_key, &storage_key)
                    .await
                {
                    self.release_claim(claim).await;
                    continue;
                }
                debug!(
                    lock_key = envelope.lock_key.as_str(),
                    worker_id = self.worker_id.as_str(),
                    "Claimed job"
                );
                return Ok(ClaimOutcome {
                    claimed: Some(ClaimedJob {
                        envelope,
                        storage_key,
                        claim,
                    }),
                    next_ready: None,
                });
            }
        }
        Ok(ClaimOutcome {
            claimed: None,
            next_ready,
        })
    }

    /// Mark a claimed job as complete: delete its pending file, retire the
    /// dedup index when it still points at it, and release the claim. A lost
    /// claim skips the cleanup entirely: the key's new holder owns that state
    /// now, and a redundant re-run is what the handler contract covers.
    pub async fn complete(&self, claimed: ClaimedJob) -> Result<CompleteOutcome, Error> {
        let ClaimedJob {
            envelope,
            storage_key,
            claim,
        } = claimed;
        if claim.lost() {
            warn!(
                lock_key = envelope.lock_key.as_str(),
                "job queue: claim lapsed during execution; leaving cleanup to the new holder"
            );
            return Ok(CompleteOutcome::Completed);
        }
        let pending_path = job_pending_path(envelope.queue.as_str(), &storage_key);
        let cleanup = async {
            self.store.delete(&pending_path).await?;
            self.cleanup_index_if_ours(envelope.queue, &envelope.lock_key, &storage_key)
                .await
        };
        match cleanup.await {
            Ok(()) => {
                self.release_claim(claim).await;
                Ok(CompleteOutcome::Completed)
            }
            Err(e) => {
                // The cleanup did not land: fail the job over (backoff, then
                // dead-letter) instead of leaving the pending file
                // re-claimable in a hot loop. We still hold the claim.
                let claimed = ClaimedJob {
                    envelope,
                    storage_key,
                    claim,
                };
                self.fail(claimed, &format!("complete: cleanup failed: {e}"))
                    .await
                    .map(CompleteOutcome::FailedOver)
            }
        }
    }

    /// Record a failure. The job is either re-queued with backoff or moved to
    /// the dead-letter store when its retry budget is exhausted. On retry the
    /// envelope is rewritten to a *new* storage key encoding the bumped
    /// `not_before`; the previous key is deleted afterwards. A crash between
    /// the two writes re-runs the previous envelope at its old (already
    /// elapsed) `not_before`, which the handler-side idempotency contract
    /// already covers.
    pub async fn fail(&self, claimed: ClaimedJob, err: &str) -> Result<FailOutcome, Error> {
        let ClaimedJob {
            envelope,
            storage_key,
            claim,
        } = claimed;
        let new_attempts = envelope.attempts.saturating_add(1);

        // Every stored envelope carries a budget; the queue's stands in for one
        // that somehow reached here without going through `enqueue`.
        if new_attempts >= envelope.max_attempts.unwrap_or(self.max_attempts) {
            return self
                .fail_dead_letter(claim, envelope, storage_key, err)
                .await;
        }

        let delay = self.retry_backoff.delay(new_attempts);
        let next_at = Utc::now() + ChronoDuration::from_std(delay).unwrap_or_default();
        let updated = JobEnvelope {
            attempts: new_attempts,
            ..envelope
        };

        self.fail_retry(claim, updated, storage_key, next_at).await
    }

    /// Record a non-retryable failure: the job is dead-lettered immediately,
    /// bypassing the retry budget. Used when retrying cannot succeed (an
    /// authorization denial).
    pub async fn fail_terminal(
        &self,
        claimed: ClaimedJob,
        err: &str,
    ) -> Result<FailOutcome, Error> {
        let ClaimedJob {
            envelope,
            storage_key,
            claim,
        } = claimed;
        self.fail_dead_letter(claim, envelope, storage_key, err)
            .await
    }

    /// Rewrite the pending file under a new storage key encoding the bumped
    /// `not_before`, then delete the old one; a crash between the two re-runs
    /// the old envelope, which the handler-side idempotency contract covers.
    async fn fail_retry(
        &self,
        claim: JobClaim,
        updated: JobEnvelope,
        old_storage_key: String,
        next_at: DateTime<Utc>,
    ) -> Result<FailOutcome, Error> {
        // Mirrors `complete`: a lost claim must not touch queue state the
        // key's new holder now owns, so report the intended outcome only.
        if claim.lost() {
            warn!(
                lock_key = updated.lock_key.as_str(),
                "job queue: claim lapsed during execution; leaving the retry to the new holder"
            );
            return Ok(FailOutcome::Retried { next_at });
        }
        let new_storage_key = make_storage_key(next_at, &updated.id);
        let new_pending_path = job_pending_path(updated.queue.as_str(), &new_storage_key);
        let old_pending_path = job_pending_path(updated.queue.as_str(), &old_storage_key);
        let index_path = job_lock_key_index_path(updated.queue.as_str(), &updated.lock_key);

        let pending_body = Bytes::from(
            serde_json::to_vec(&updated)
                .map_err(|e| Error::Storage(format!("envelope serialization failed: {e}")))?,
        );
        let index_body = Bytes::from(serialize_lock_key_index(&new_storage_key)?);

        let rewrite = async {
            self.store.put(&new_pending_path, pending_body).await?;
            self.store.delete(&old_pending_path).await?;
            // Point the index at the rescheduled job only while it is
            // absent: a producer that indexed a fresh job in the meantime
            // keeps its entry, and this retry stays unindexed until an
            // enqueue self-heals it. A missed dedup hit costs a duplicate
            // job; clobbering the entry would strand that producer's file.
            let _ = self.store.create_if_absent(&index_path, index_body).await?;
            Ok::<_, StorageError>(())
        };
        let result = rewrite.await;
        self.release_claim(claim).await;
        result?;

        Ok(FailOutcome::Retried { next_at })
    }

    /// Write the failed record, remove the pending file, and retire the
    /// index when it still points at this job. Record first, so a crash
    /// duplicates into the dead letter rather than losing the failure.
    async fn fail_dead_letter(
        &self,
        claim: JobClaim,
        envelope: JobEnvelope,
        storage_key: String,
        err: &str,
    ) -> Result<FailOutcome, Error> {
        // Mirrors `complete`: a lost claim must not touch queue state the
        // key's new holder now owns, so report the intended outcome only.
        if claim.lost() {
            warn!(
                lock_key = envelope.lock_key.as_str(),
                "job queue: claim lapsed during execution; leaving the dead-letter to the new holder"
            );
            return Ok(FailOutcome::MovedToDeadLetter);
        }
        let failed_path = job_failed_path(envelope.queue.as_str(), &storage_key);
        let pending_path = job_pending_path(envelope.queue.as_str(), &storage_key);

        let failed_body = Bytes::from(serialize_dead_letter(&envelope, err)?);

        let bury = async {
            self.store.put(&failed_path, failed_body).await?;
            self.store.delete(&pending_path).await?;
            self.cleanup_index_if_ours(envelope.queue, &envelope.lock_key, &storage_key)
                .await
        };
        let result = bury.await;
        self.release_claim(claim).await;
        result?;

        Ok(FailOutcome::MovedToDeadLetter)
    }

    // -----------------------------------------------------------------------
    // Administrative mutations (operator-driven retry / delete)
    // -----------------------------------------------------------------------

    /// Move a dead-letter record back to pending with its retry budget reset
    /// to zero: an atomic create of a fresh pending file (new `not_before` =
    /// now) followed by a delete of the failed record. Returns
    /// [`Error::NotFound`] when the failed record is already gone (a stale
    /// key).
    ///
    /// The dedup index is deliberately **not** re-established: a retried job has
    /// no `lock_key` index entry, so a concurrent producer enqueuing the same
    /// `lock_key` may create a second pending file. That is safe: the
    /// per-`lock_key` execution lock still serialises the two, and the handler
    /// contract makes a redundant run idempotent.
    pub async fn retry_failed(&self, queue: Queue, storage_key: &str) -> Result<(), Error> {
        let failed_path = job_failed_path(queue.as_str(), storage_key);
        // Surface a stale key as `NotFound` before touching any state; a
        // double-retry stays safe because it collides on the atomic create.
        self.store.head(&failed_path).await?;

        let mut envelope = self.read_failed(queue, storage_key).await?.envelope;
        envelope.attempts = 0;

        let new_storage_key = make_storage_key(Utc::now(), &envelope.id);
        let pending_path = job_pending_path(queue.as_str(), &new_storage_key);
        let pending_body = Bytes::from(
            serde_json::to_vec(&envelope)
                .map_err(|e| Error::Storage(format!("envelope serialization failed: {e}")))?,
        );

        // Pending first, so a crash duplicates into a re-runnable job rather
        // than losing the record; a concurrent retry collides on the atomic
        // create and both observe the job back in flight.
        let _ = self
            .store
            .create_if_absent(&pending_path, pending_body)
            .await?;
        self.store.delete(&failed_path).await?;
        Ok(())
    }

    /// Delete a job by `state`/`storage_key`. Failed records are removed
    /// head-then-delete: the head surfaces a stale key as
    /// [`Error::NotFound`], then the idempotent delete removes the record.
    /// Pending deletes additionally fold in the conditional dedup-index
    /// delete (only when the index still points at this key), mirroring
    /// [`Self::fail_dead_letter`].
    ///
    /// Deleting a *pending* job is best-effort against a worker that may be
    /// mid-execution: the operator holds no execution lock, so a claim already
    /// in flight still commits its handler effect.
    /// Returns [`Error::NotFound`] for a stale key.
    pub async fn delete_job(
        &self,
        queue: Queue,
        state: JobState,
        storage_key: &str,
    ) -> Result<(), Error> {
        match state {
            JobState::Failed => {
                let failed_path = job_failed_path(queue.as_str(), storage_key);
                // Surface a stale key as `NotFound` before the idempotent delete.
                self.store.head(&failed_path).await?;
                self.store.delete(&failed_path).await.map_err(Error::from)
            }
            JobState::Pending => self.delete_pending(queue, storage_key).await,
        }
    }

    async fn delete_pending(&self, queue: Queue, storage_key: &str) -> Result<(), Error> {
        let pending_path = job_pending_path(queue.as_str(), storage_key);
        // Read the envelope (for its `lock_key`); a missing pending file
        // surfaces as `NotFound` for a 404. Only the
        // `lock_key` needs the body, so a record that will not parse is still
        // deletable: the operator retiring it is the one recovery path, and
        // its index entry is reclaimed by the orphan-job sweep.
        let lock_key = match self.read_pending(queue, storage_key).await {
            Ok(envelope) => Some(envelope.lock_key),
            Err(Error::Corrupt(e)) => {
                warn!("job queue: deleting unreadable pending job '{storage_key}': {e}");
                None
            }
            Err(e) => return Err(e),
        };
        // Surface a stale key as `NotFound` before the idempotent delete.
        self.store.head(&pending_path).await?;
        self.store.delete(&pending_path).await?;
        if let Some(lock_key) = lock_key {
            self.cleanup_index_if_ours(queue, &lock_key, storage_key)
                .await?;
        }
        Ok(())
    }
}

/// What one refresh-tick read of the claim key concluded.
enum ClaimCheck {
    /// The record still carries this instance with an unexpired lease.
    Owned { expires_at: DateTime<Utc> },
    /// Positive loss: the record is gone, unparseable, expired, or carries
    /// another instance.
    Lost,
    /// The read failed, so ownership is unknown this tick.
    Unverifiable,
}

/// Whether the refresher must raise `lost`: a positive loss always cancels,
/// while an unverifiable read only cancels once the last verified expiry has
/// passed, because the lease itself is the tolerance for transient errors.
fn should_cancel_claim(
    check: &ClaimCheck,
    last_verified_expiry: DateTime<Utc>,
    now: DateTime<Utc>,
) -> bool {
    match check {
        ClaimCheck::Owned { .. } => false,
        ClaimCheck::Lost => true,
        ClaimCheck::Unverifiable => now >= last_verified_expiry,
    }
}

/// The claim holder's lease refresher: re-stamp the record at a third of the
/// lease, stop and raise `lost` when the key positively no longer carries
/// this instance, or when read errors persist past the last verified expiry.
/// The re-stamp is an unconditional put that can overwrite a takeover's
/// record; like the `try_claim` race, that costs at most a bounded duplicate
/// run of an idempotent handler, never a lost job.
async fn refresh_claim_loop(
    store: Arc<dyn ObjectStore>,
    key: String,
    instance: String,
    stamped_until: DateTime<Utc>,
    claim_ttl_secs: i64,
    lost: CancellationToken,
) {
    let period = Duration::from_secs(u64::try_from(claim_ttl_secs / 3).unwrap_or(20).max(1));
    let mut last_verified_expiry = stamped_until;
    loop {
        sleep(period).await;
        let check = match store.get(&key).await {
            Ok(raw) => match serde_json::from_slice::<ClaimRecord>(&raw) {
                Ok(record) if record.instance == instance && record.expires_at >= Utc::now() => {
                    ClaimCheck::Owned {
                        expires_at: record.expires_at,
                    }
                }
                _ => ClaimCheck::Lost,
            },
            Err(StorageError::NotFound) => ClaimCheck::Lost,
            // A transient read error is not loss; retry on the next tick
            // while the last verified stamp still covers us.
            Err(_) => ClaimCheck::Unverifiable,
        };
        if should_cancel_claim(&check, last_verified_expiry, Utc::now()) {
            lost.cancel();
            return;
        }
        let ClaimCheck::Owned { expires_at } = check else {
            continue;
        };
        last_verified_expiry = expires_at;
        let record = ClaimRecord {
            instance: instance.clone(),
            expires_at: Utc::now() + ChronoDuration::seconds(claim_ttl_secs),
        };
        let Ok(body) = serde_json::to_vec(&record) else {
            lost.cancel();
            return;
        };
        // A missed stamp is survivable inside the lease; the next tick
        // retries, and a lapse is what `lost` reports.
        if store.put(&key, Bytes::from(body)).await.is_ok() {
            last_verified_expiry = record.expires_at;
        }
    }
}

// ---------------------------------------------------------------------------
// Queue-depth gauge refresh loop
// ---------------------------------------------------------------------------

/// Refresh the queue-depth gauges (`angos_job_queue_pending` and
/// `angos_job_queue_failed`) for `queue` on every `period` tick, until
/// `shutdown` is cancelled. Uses `tokio::time::interval` so the cadence stays
/// fixed across slow count calls; missed ticks are coalesced rather than
/// catching up.
///
/// `ready_horizon_secs` is forwarded to `count_pending`: only envelopes ready
/// within that window contribute to the pending gauge. The server runs this
/// loop so both gauges are scrapeable even when `angos worker` drains the queue.
pub async fn queue_depth_refresh_loop(
    store: Arc<JobStore>,
    queue: Queue,
    period: Duration,
    ready_horizon_secs: u64,
    shutdown: CancellationToken,
) {
    let mut timer = interval(period);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Consume the immediate first tick so the first refresh happens after `period`.
    timer.tick().await;

    loop {
        select! {
            () = shutdown.cancelled() => return,
            _ = timer.tick() => {}
        }
        match store.count_pending(queue, ready_horizon_secs).await {
            Ok(count) => {
                metrics_provider()
                    .job_queue_pending
                    .with_label_values(&[queue.as_str()])
                    .set(i64::try_from(count).unwrap_or(i64::MAX));
            }
            Err(e) => debug!(queue = %queue, error = %e, "Failed to refresh pending gauge"),
        }
        match store.count_failed(queue).await {
            Ok(count) => {
                metrics_provider()
                    .job_queue_failed
                    .with_label_values(&[queue.as_str()])
                    .set(i64::try_from(count).unwrap_or(i64::MAX));
            }
            Err(e) => debug!(queue = %queue, error = %e, "Failed to refresh dead-letter gauge"),
        }
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
