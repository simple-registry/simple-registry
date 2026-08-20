//! The blob-reclamation marker protocol: the one place a writer and the
//! collector must agree, with no lock.
//!
//! A collector about to delete blob data publishes a [`GcRun`] naming its
//! digest range, re-reads that marker before the irreversible delete, and
//! removes it afterwards; a writer that has just written reference keys lists
//! `v2/gc/` once and backs off on an unexpired run covering one of its
//! digests. Either the writer's reference completed before the collector's
//! liveness listing (the key is younger than the grace period, so the blob
//! reads live), or it completed after, in which case the marker was already
//! visible to the writer's check.
//!
//! The marker's expiry only stops a crashed collector from wedging writers; a
//! live collector fences itself by refreshing before each delete.

use std::time::Duration as StdDuration;

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use uuid::Uuid;

use angos_backoff::Backoff;

use angos_oci::Digest;
use angos_storage::Error as StorageError;

use crate::registry::{Error, metadata_store::MetadataStore, path_builder};

/// Attempts and jittered backoff for a writer waiting out a collector run; a
/// run only covers one batch, so the wait is short.
const WRITER_BACKOFF_ATTEMPTS: u32 = 5;
const WRITER_BACKOFF: Backoff =
    Backoff::exponential(StdDuration::from_millis(50), StdDuration::from_millis(800)).with_jitter();

/// One collector run's published claim over an inclusive digest range.
/// `Digest` ordering matches the lexical order of its `algo:hash` string, so
/// the range covers exactly the stored keys between its bounds.
#[derive(Debug, Serialize, Deserialize)]
pub struct GcRun {
    pub start: Digest,
    pub end: Digest,
    pub expires_at: DateTime<Utc>,
    pub instance: String,
}

/// A held claim: the marker key plus the token that proves ownership on
/// refresh.
pub struct GcClaim {
    key: String,
    instance: String,
    start: Digest,
    end: Digest,
}

impl MetadataStore {
    /// Writer-side wait: brief backoff while an unexpired collector run
    /// covers any of `digests`. `false` means still covered after the budget,
    /// so the caller must treat the blobs as being reclaimed.
    pub async fn gc_clear(&self, digests: &[&Digest]) -> Result<bool, Error> {
        for attempt in 0..WRITER_BACKOFF_ATTEMPTS {
            if !self.gc_blocked(digests).await? {
                return Ok(true);
            }
            sleep(WRITER_BACKOFF.delay(attempt)).await;
        }
        Ok(false)
    }

    /// Whether an unexpired collector run covers any of `digests`; one
    /// listing, nothing per blob.
    pub async fn gc_blocked(&self, digests: &[&Digest]) -> Result<bool, Error> {
        let mut token = None;
        loop {
            let page = self
                .object_store()
                .list(path_builder::GC_ROOT, 100, token)
                .await?;
            for run in &page.items {
                let key = path_builder::gc_run_path(run);
                let raw = match self.object_store().get(&key).await {
                    Ok(raw) => raw,
                    // Released between the listing and the read.
                    Err(StorageError::NotFound) => continue,
                    Err(e) => return Err(e.into()),
                };
                // An unreadable marker blocks: failing open here would let a
                // corrupt marker green-light a delete race.
                let Ok(run) = serde_json::from_slice::<GcRun>(&raw) else {
                    return Ok(true);
                };
                if run.expires_at < Utc::now() {
                    continue;
                }
                if digests
                    .iter()
                    .any(|digest| run.start <= **digest && **digest <= run.end)
                {
                    return Ok(true);
                }
            }
            token = page.next_token;
            if token.is_none() {
                return Ok(false);
            }
        }
    }

    /// Collector side: publish a run marker covering `start..=end`. The
    /// expiry is generous because safety rests on [`Self::gc_refresh`], not
    /// on the timer.
    pub async fn gc_claim(&self, start: &Digest, end: &Digest) -> Result<GcClaim, Error> {
        let claim = GcClaim {
            key: path_builder::gc_run_path(&Uuid::new_v4().to_string()),
            instance: Uuid::new_v4().to_string(),
            start: start.clone(),
            end: end.clone(),
        };
        // A fresh UUID cannot legitimately exist; adopting one would fence
        // against another collector's live marker.
        let body = self.gc_run_body(&claim)?;
        if !self
            .object_store()
            .create_if_absent(&claim.key, body)
            .await?
        {
            return Err(Error::Internal(format!(
                "gc run marker collision at {}",
                claim.key
            )));
        }
        Ok(claim)
    }

    /// Re-read and re-stamp the claim before an irreversible delete. `false`
    /// means the marker was lost or overwritten, so stop collecting: a writer
    /// may already have read it as expired and skipped its check.
    pub async fn gc_refresh(&self, claim: &GcClaim) -> Result<bool, Error> {
        match self.object_store().get(&claim.key).await {
            Ok(raw) => {
                let Ok(run) = serde_json::from_slice::<GcRun>(&raw) else {
                    return Ok(false);
                };
                if run.instance != claim.instance || run.expires_at < Utc::now() {
                    return Ok(false);
                }
            }
            Err(StorageError::NotFound) => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        self.put_gc_run(claim).await?;
        Ok(true)
    }

    /// Remove the claim once the range is done.
    pub async fn gc_release(&self, claim: GcClaim) -> Result<(), Error> {
        self.object_store()
            .delete(&claim.key)
            .await
            .map_err(Error::from)
    }

    async fn put_gc_run(&self, claim: &GcClaim) -> Result<(), Error> {
        let body = self.gc_run_body(claim)?;
        self.object_store()
            .put(&claim.key, body)
            .await
            .map_err(Error::from)
    }

    fn gc_run_body(&self, claim: &GcClaim) -> Result<Bytes, Error> {
        // Twice the grace, floored so a marker outlives its own publish even
        // under a tiny grace setting.
        let ttl = i64::try_from(self.gc_grace_secs)
            .unwrap_or(i64::MAX)
            .saturating_mul(2)
            .max(60);
        let run = GcRun {
            start: claim.start.clone(),
            end: claim.end.clone(),
            expires_at: Utc::now() + Duration::seconds(ttl),
            instance: claim.instance.clone(),
        };
        Ok(Bytes::from(serde_json::to_vec(&run)?))
    }
}
