//! Blob-data and upload-artifact validation (absorbed from the old
//! `BlobChecker` orphan GC and the orphan-namespace sweeps). Runs last: the
//! index has been healed, so an empty index really means no references.

use chrono::{DateTime, Utc};
use tracing::warn;

use angos_oci::{Digest, Namespace};
use angos_tx_engine::StorageError;

use crate::{
    command::{
        maintenance::{
            Error,
            action::{Action, WalkedStore},
            categorize::UploadArtifact,
        },
        scrub::validate::Validator,
    },
    registry::{Error as RegistryError, path_builder},
};

impl Validator {
    /// Validate one blob's `data` object against its (already healed) index.
    pub async fn validate_blob(&self, digest: &Digest) -> Result<(), Error> {
        let index = match self.metadata_store.read_blob_index(digest).await {
            Ok(index) => index,
            Err(RegistryError::NotFound) => {
                // No index at all: unreferenced bytes. The executor
                // re-verifies liveness under a gc run marker before deleting.
                return self.reclaim_orphan_blob(digest).await;
            }
            Err(e) => return Err(e.into()),
        };
        if index.namespace.is_empty() {
            return self.reclaim_orphan_blob(digest).await;
        }
        // Referenced: per-entry link probing is the shard pass's job, and
        // config-relative grant reclamation is prune's.
        Ok(())
    }

    /// Delete unreferenced bytes, unless this run force-deleted one of the
    /// blob's shards (the references vanished unrepaired, so reclaim waits for
    /// the next run's re-grant) or the shard walk read references the index
    /// read above did not.
    async fn reclaim_orphan_blob(&self, digest: &Digest) -> Result<(), Error> {
        if self.blob_gc_held(digest) {
            warn!(
                "scrub: blob '{digest}' lost a corrupt shard this run; leaving bytes for the next run"
            );
            return Ok(());
        }
        // The index read pages one directory listing; the shard walk reached
        // the same shards through a whole-store scan. Disagreement means a
        // listing dropped a key it holds, so the bytes may well be live.
        if self.shard_walk_saw_references(digest) {
            warn!(
                "scrub: blob '{digest}' reads as unreferenced but the shard walk found references for it; \
                 refusing to reclaim, the backend's listing is incomplete"
            );
            return Ok(());
        }
        // The executor re-checks this gate before deleting; testing it here
        // too keeps fresh bytes (an upload or push still in flight, or a
        // just-deleted blob inside its grace period) from being emitted and
        // counted as repairs on every walk.
        let meta = match self
            .blob_store
            .object_store()
            .head(&path_builder::blob_path(digest))
            .await
        {
            Ok(meta) => meta,
            Err(StorageError::NotFound) => return Ok(()),
            Err(e) => return Err(RegistryError::from(e).into()),
        };
        let grace = i64::try_from(self.metadata_store.gc_grace_secs()).unwrap_or(i64::MAX);
        let fresh = meta.last_modified.is_none_or(|modified| {
            Utc::now().signed_duration_since(modified).num_seconds() < grace
        });
        if fresh {
            return Ok(());
        }
        self.emit(Action::DeleteOrphanBlob(digest.clone())).await
    }

    /// One upload-session artifact seen by the blob walk. Session aging and
    /// orphan-namespace clearing are prune's job; scrub validates the
    /// `startedat` marker's content and reclaims invalid-name upload
    /// directories (deduped per name), which no angos API can address.
    pub async fn validate_upload_artifact(
        &self,
        key: &str,
        namespace_raw: &str,
        artifact: UploadArtifact,
    ) -> Result<(), Error> {
        if Namespace::new(namespace_raw).is_err() {
            if !self.claim(format!("invalid-upload-ns:{namespace_raw}")) {
                return Ok(());
            }
            warn!("scrub: reclaiming invalid upload namespace directory '{namespace_raw}'");
            return self
                .emit(Action::DeleteInvalidUploadNamespace {
                    name: namespace_raw.to_string(),
                })
                .await;
        }
        if artifact == UploadArtifact::StartedAt {
            self.validate_started_at(key).await?;
        }
        Ok(())
    }

    /// An unreadable `startedat` marker is deleted; the session then reads
    /// as broken and prune's upload sweep reaps it.
    async fn validate_started_at(&self, key: &str) -> Result<(), Error> {
        let raw = match self.blob_store.object_store().get(key).await {
            Ok(raw) => raw,
            Err(StorageError::NotFound) => return Ok(()),
            Err(e) => return Err(RegistryError::from(e).into()),
        };
        let parses = std::str::from_utf8(&raw)
            .ok()
            .and_then(|text| DateTime::parse_from_rfc3339(text.trim()).ok())
            .is_some();
        if !parses {
            warn!("scrub: upload marker '{key}' does not parse as RFC3339; deleting");
            self.delete_corrupt(WalkedStore::Blob, key).await?;
        }
        Ok(())
    }
}
