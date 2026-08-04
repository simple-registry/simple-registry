//! Distributed-lock primitive for the transaction engine.
//!
//! The single concrete type is [`primitive::Lock`]. Callers never see a RAII guard:
//! they call [`primitive::Lock::acquire`] (blocking retry) or [`primitive::Lock::try_acquire`]
//! (non-blocking, single attempt) with the keys to lock, run their work, then
//! await [`LockSession::release`], always on the calling task's own call
//! path. A background heartbeat task refreshes the lock TTL and fires the
//! session's [`tokio_util::sync::CancellationToken`] when ownership is lost, so a caller racing
//! its operation against [`LockSession::cancellation`] can short-circuit to
//! [`Error::Invalidated`] at the next await point.
//!
//! ## Lifetime contract
//!
//! - **Release**: the happy path awaits [`LockSession::release`] on the
//!   calling task's own call path. If the session is instead dropped before
//!   `release` runs (outer task cancellation), `LockSession`'s `Drop`
//!   best-effort spawns the async release on the current Tokio runtime so the
//!   remote lock is freed promptly instead of waiting on TTL. The spawn is
//!   fire-and-forget; if no runtime is available the lock expires via TTL.
//! - **Heartbeat failure**: the heartbeat task fires the
//!   [`tokio_util::sync::CancellationToken`] when the heartbeat tick fails (ownership lost,
//!   refresh failed, max hold exceeded). Callers that race their operation
//!   against the token short-circuit to [`Error::Invalidated`] at the next
//!   await point.
//!
//! ## Storage flavours
//!
//! [`primitive::Lock`] is parameterised by a [`storage::LockStorage`] implementation selected at
//! startup from the operator's `lock_strategy` config:
//!
//! | `lock_strategy` | [`storage::LockStorage`] impl | Notes |
//! |---|---|---|
//! | `memory` | [`storage::memory::MemoryLockStorage`] | In-process; single-process only (default for FS deployments) |
//! | `redis`  | `RedisLockStorage` | Feature `redis`; suitable for FS stores under heavy load |
//! | `s3`     | [`storage::s3::S3LockStorage`] | CAS-capable S3; uses `.tx-locks/<shard>/<key>` objects |

use std::{fmt::Debug, future::Future, pin::Pin};

use serde::Deserialize;
use tokio::{runtime::Handle, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::lock::storage::redis::RedisLockStorageConfig;

pub mod metrics;
pub mod primitive;
pub mod storage;

/// Errors produced by lock operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("lock error: {0}")]
    Lock(String),
    #[error("invalid data: {0}")]
    InvalidData(String),
    #[error("storage backend error: {0}")]
    StorageBackend(String),
    /// The heartbeat fired mid-operation.
    #[error("lock invalidated mid-operation")]
    Invalidated,
    /// Key was not found (used by `LockStorage` implementations).
    #[error("lock object not found")]
    NotFound,
}

#[cfg(feature = "redis")]
impl From<::redis::RedisError> for Error {
    fn from(err: ::redis::RedisError) -> Self {
        Error::Lock(format!("Redis error: {err}"))
    }
}

type AsyncReleaseFn = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// Opaque bookkeeping returned by [`primitive::Lock::acquire`].
///
/// Backends construct one of these from their `acquire` impl; callers consume
/// it by awaiting [`release`](Self::release) and nothing else should reach for
/// the held release or `cancellation` directly.
///
/// **Release contract:** the happy path runs through
/// [`release`](Self::release), awaited on the calling task's call path before
/// returning. [`Drop`] is a best-effort fallback that fires when the session is
/// dropped without an explicit release (outer task cancellation): it aborts the
/// heartbeat synchronously and spawns the async release on the current Tokio
/// runtime so the remote lock is freed without waiting on TTL. If no runtime is
/// available the remote lock expires via the backend's TTL.
pub struct LockSession {
    /// The held lock, absent for a session over an empty key set.
    held: Option<HeldLock>,
    /// Fired by the backend's heartbeat task to signal lock-ownership
    /// loss.
    cancellation: CancellationToken,
}

/// What a session holds while it owns the lock: the release the backend handed
/// back, and the heartbeat keeping ownership alive. A session has both or
/// neither, so they travel as one value.
struct HeldLock {
    release: AsyncReleaseFn,
    heartbeat: JoinHandle<()>,
}

impl LockSession {
    /// Session for an empty key set: nothing to release, no heartbeat.
    #[must_use]
    pub fn noop() -> Self {
        Self {
            held: None,
            cancellation: CancellationToken::new(),
        }
    }

    /// Distributed session backed by an async release and a heartbeat task.
    pub fn with_async_release_and_heartbeat(
        release_fn: impl FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
        cancellation: CancellationToken,
        heartbeat_handle: JoinHandle<()>,
    ) -> Self {
        Self {
            held: Some(HeldLock {
                release: Box::new(release_fn),
                heartbeat: heartbeat_handle,
            }),
            cancellation,
        }
    }

    /// Clone the session's cancellation token so callers can race their
    /// operation against heartbeat-loss events.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Release the lock on the calling task's call path.
    pub async fn release(mut self) {
        if let Some(held) = self.held.take() {
            // Abort first: a heartbeat that refreshed after the release would
            // hand ownership back to a session that no longer holds it.
            held.heartbeat.abort();
            (held.release)().await;
        }
    }
}

impl Drop for LockSession {
    fn drop(&mut self) {
        if let Some(held) = self.held.take() {
            held.heartbeat.abort();
            if let Ok(runtime) = Handle::try_current() {
                runtime.spawn((held.release)());
            } else {
                debug!("LockSession::drop: no Tokio runtime; remote lock will expire via TTL");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tokio::time::sleep;

    use super::{CancellationToken, LockSession};

    /// The heartbeat is stopped before the lock is handed back. A refresh
    /// landing after the release would renew a key this session no longer
    /// owns, and another holder may already have taken it.
    #[tokio::test]
    async fn releasing_stops_the_heartbeat_first() {
        let releasing = Arc::new(AtomicBool::new(false));
        let ticked_during_release = Arc::new(AtomicBool::new(false));

        let heartbeat = tokio::spawn({
            let releasing = releasing.clone();
            let ticked_during_release = ticked_during_release.clone();
            async move {
                loop {
                    sleep(Duration::from_millis(1)).await;
                    if releasing.load(Ordering::SeqCst) {
                        ticked_during_release.store(true, Ordering::SeqCst);
                    }
                }
            }
        });

        let session = LockSession::with_async_release_and_heartbeat(
            {
                let releasing = releasing.clone();
                move || {
                    Box::pin(async move {
                        releasing.store(true, Ordering::SeqCst);
                        // Long enough for a still-running heartbeat to tick.
                        sleep(Duration::from_millis(50)).await;
                    })
                }
            },
            CancellationToken::new(),
            heartbeat,
        );

        session.release().await;

        assert!(
            !ticked_during_release.load(Ordering::SeqCst),
            "the heartbeat must be aborted before the lock is released"
        );
    }

    /// A session over an empty key set holds nothing, so releasing it is a
    /// no-op rather than a half-initialised release.
    #[tokio::test]
    async fn a_noop_session_releases_cleanly() {
        let session = LockSession::noop();
        assert!(!session.cancellation().is_cancelled());
        session.release().await;
    }
}

// Lock strategy config

/// Parsed configuration for the S3-backed lock storage.
///
/// This is a DTO: deserialized from operator config and used to construct an
/// [`storage::s3::S3LockStorage`]. Not held as a field on any runtime struct.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct S3LockConfig {
    /// Lock TTL in seconds; the bounds are enforced when the lock is built.
    #[serde(default = "S3LockConfig::default_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default = "S3LockConfig::default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "S3LockConfig::default_retry_delay_ms")]
    pub retry_delay_ms: u64,
    #[serde(default = "S3LockConfig::default_max_hold_secs")]
    pub max_hold_secs: u64,
    /// Timeout (seconds) for a single storage operation. Defaults to 15.
    #[serde(default = "S3LockConfig::default_operation_timeout_secs")]
    pub operation_timeout_secs: u64,
    /// Timeout (seconds) per attempt inside a retried storage operation. Defaults to 4.
    #[serde(default = "S3LockConfig::default_operation_attempt_timeout_secs")]
    pub operation_attempt_timeout_secs: u64,
    /// Maximum attempts per storage operation. Defaults to 2.
    #[serde(default = "S3LockConfig::default_max_attempts")]
    pub max_attempts: u32,
    /// Maximum attempts (initial write plus reconciling retries) for a
    /// conditional lock write whose transport outcome is ambiguous. Defaults
    /// to 3.
    #[serde(default = "S3LockConfig::default_conditional_max_attempts")]
    pub conditional_max_attempts: u32,
}

impl S3LockConfig {
    fn default_ttl_secs() -> u64 {
        30
    }
    fn default_max_retries() -> u32 {
        100
    }
    fn default_retry_delay_ms() -> u64 {
        50
    }
    fn default_max_hold_secs() -> u64 {
        300
    }
    fn default_operation_timeout_secs() -> u64 {
        15
    }
    fn default_operation_attempt_timeout_secs() -> u64 {
        4
    }
    fn default_max_attempts() -> u32 {
        2
    }
    fn default_conditional_max_attempts() -> u32 {
        3
    }
}

impl Default for S3LockConfig {
    fn default() -> Self {
        Self {
            ttl_secs: Self::default_ttl_secs(),
            max_retries: Self::default_max_retries(),
            retry_delay_ms: Self::default_retry_delay_ms(),
            max_hold_secs: Self::default_max_hold_secs(),
            operation_timeout_secs: Self::default_operation_timeout_secs(),
            operation_attempt_timeout_secs: Self::default_operation_attempt_timeout_secs(),
            max_attempts: Self::default_max_attempts(),
            conditional_max_attempts: Self::default_conditional_max_attempts(),
        }
    }
}

/// Lock strategy configuration.
///
/// Determines which [`storage::LockStorage`] implementation is constructed at startup.
/// Deserialized from operator configuration; selection is per-deployment.
/// `lock_strategy = "memory" | "redis" | "s3"` selects the lock-object storage
/// backend.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LockStrategy {
    Memory,
    /// Parsed unconditionally (DTOs always parse); selecting it without the
    /// `redis` feature is rejected by [`crate::store::Store::new`].
    Redis(RedisLockStorageConfig),
    S3(S3LockConfig),
}

/// Resolve the configured [`LockStrategy`] from operator config, applying
/// precedence rules and validating constraints.
///
/// Returns `Ok(None)` when the operator configured nothing; the caller picks
/// the backend-appropriate default (memory for FS, CAS-dependent for S3).
/// Returns a `serde::de::Error` for any configuration conflict so this
/// function can be called from a custom `Deserialize` impl.
///
/// # Errors
///
/// Returns `Err(E::custom(...))` when both `lock_strategy` and `redis` are
/// provided, or when the S3 lock strategy is requested on a non-S3 metadata
/// store. A Redis selection without the `redis` feature parses here and is
/// rejected by [`crate::store::Store::new`].
pub fn resolve_lock_strategy<E: serde::de::Error>(
    lock_strategy: Option<LockStrategy>,
    redis: Option<RedisLockStorageConfig>,
    allow_s3: bool,
) -> Result<Option<LockStrategy>, E> {
    match (lock_strategy, redis) {
        (Some(_), Some(_)) => Err(E::custom(
            "cannot set both 'lock_strategy' and 'redis'; use lock_strategy.redis instead",
        )),
        (Some(LockStrategy::S3(_)), None) if !allow_s3 => Err(E::custom(
            "S3 lock strategy is not supported for filesystem metadata store",
        )),
        (Some(strategy), None) => Ok(Some(strategy)),
        (None, Some(redis_config)) => Ok(Some(LockStrategy::Redis(redis_config))),
        (None, None) => Ok(None),
    }
}
