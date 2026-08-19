//! Orphan multipart-upload detection and cleanup orchestration.
//!
//! This is registry-domain logic layered on the storage backend's raw upload
//! *primitives* ([`ObjectStore::list_multipart_uploads`](angos_storage::ObjectStore::list_multipart_uploads)
//! and the keyed [`ObjectStore::abort_upload`](angos_storage::ObjectStore::abort_upload)):
//! it walks in-flight multipart uploads, applies an age threshold, and skips
//! any upload that still has a live session (its `session.json` record, or
//! the legacy `startedat` marker, exists).
//! The engine stays oblivious to upload-session semantics; the policy lives
//! here. An orphan is cleaned with `abort_upload(key)`, which aborts every
//! in-flight multipart at the key and removes any staged remainder.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use futures_util::stream::{self, StreamExt};
use tracing::warn;

use angos_oci::{Namespace, UploadSessionId};
use angos_storage::Error as StorageError;

use crate::registry::{Error, blob_store::BlobStore, path_builder};

/// Fan-out for the per-upload session-marker probes: each aged upload needs
/// one independent `head`, so a page's probes run concurrently.
const ORPHAN_PROBE_CONCURRENCY: usize = 16;

/// A multipart upload with no live session, eligible to be aborted.
pub struct OrphanMultipartUpload {
    pub key: String,
    pub upload_id: String,
}

/// Inverse of [`path_builder::upload_path`]: parses
/// `v2/repositories/{namespace}/_uploads/{uuid}/data` into `(namespace, uuid)`.
/// Also parses the coalesce scratch key
/// `v2/repositories/{namespace}/_uploads/{uuid}/staged/coalesce`, so a scratch
/// multipart stranded by a crash maps to the same session and can be reclaimed.
///
/// Returns slices borrowed from `key` so cleanup passes don't allocate per upload.
pub fn parse_upload_key(key: &str) -> Option<(&str, &str)> {
    let rest = key
        .strip_prefix(path_builder::REPOS_ROOT)?
        .strip_prefix('/')?;
    rest.strip_suffix("/data")
        .or_else(|| rest.strip_suffix("/staged/coalesce"))?
        .rsplit_once("/_uploads/")
}

/// Returns `true` when a multipart upload initiated at `initiated` should be
/// considered orphaned, i.e. its age as of `now` meets or exceeds `timeout`.
///
/// A negative age (clock skew where `initiated` is in the future) is never
/// considered orphaned.
pub fn is_orphan(initiated: DateTime<Utc>, now: DateTime<Utc>, timeout: Duration) -> bool {
    now.signed_duration_since(initiated) >= timeout
}

/// Orphan multipart-upload cleanup. Discovery and abort are split so a dry-run
/// caller (e.g. scrub without `--commit`) can list without mutating state.
#[async_trait]
pub trait MultipartCleanup: Send + Sync {
    /// Lists multipart uploads that have exceeded `timeout` and are not
    /// associated with a live upload session (i.e., neither the `session.json`
    /// record nor the legacy `startedat` marker exists). Pure discovery: does
    /// not modify any state.
    async fn list_orphan_multipart_uploads(
        &self,
        timeout: Duration,
    ) -> Result<Vec<OrphanMultipartUpload>, Error>;

    /// Aborts a single orphan upload previously returned by
    /// [`Self::list_orphan_multipart_uploads`].
    async fn abort_orphan_multipart_upload(
        &self,
        upload: &OrphanMultipartUpload,
    ) -> Result<(), Error>;
}

#[async_trait]
impl MultipartCleanup for BlobStore {
    async fn list_orphan_multipart_uploads(
        &self,
        timeout: Duration,
    ) -> Result<Vec<OrphanMultipartUpload>, Error> {
        let mut orphans = Vec::new();
        let now = Utc::now();
        let mut key_marker: Option<String> = None;
        let mut upload_id_marker: Option<String> = None;

        // The dual key/upload-id markers keep this loop bespoke; within each
        // page the session-marker probes fan out concurrently.
        loop {
            let page = self
                .object
                .list_multipart_uploads(key_marker.as_deref(), upload_id_marker.as_deref())
                .await?;

            let candidates = page.uploads.into_iter().filter_map(|upload| {
                if !is_orphan(upload.initiated_at, now, timeout) {
                    return None;
                }
                let (namespace, session_id) = parse_upload_key(&upload.key)?;
                let namespace = Namespace::new(namespace).ok()?;
                // A key naming no session was never opened by angos, so it has
                // no marker to probe and no session of ours to abort.
                let session_id: UploadSessionId = session_id.parse().ok()?;
                let session_path = path_builder::upload_session_path(&namespace, &session_id);
                let legacy_path = path_builder::upload_start_date_path(&namespace, &session_id);
                Some((upload, session_path, legacy_path))
            });
            let page_orphans = stream::iter(candidates)
                .map(|(upload, session_path, legacy_path)| async move {
                    // A live session (its `session.json` record, or the legacy
                    // `startedat` marker, exists) is not an orphan. Only proven
                    // absence of both condemns it: aborting on a transient
                    // failure destroys a progressing upload's parts.
                    let alive = match self.object.head(&session_path).await {
                        Ok(_) => Ok(true),
                        Err(StorageError::NotFound) => match self.object.head(&legacy_path).await {
                            Ok(_) => Ok(true),
                            Err(StorageError::NotFound) => Ok(false),
                            Err(e) => Err(e),
                        },
                        Err(e) => Err(e),
                    };
                    match alive {
                        Ok(true) => None,
                        Ok(false) => Some(OrphanMultipartUpload {
                            key: upload.key,
                            upload_id: upload.upload_id,
                        }),
                        Err(e) => {
                            warn!(
                                "Leaving multipart upload at {} for a later pass: its liveness \
                                 probe failed: {e}",
                                upload.key
                            );
                            None
                        }
                    }
                })
                .buffer_unordered(ORPHAN_PROBE_CONCURRENCY)
                .collect::<Vec<_>>()
                .await;
            orphans.extend(page_orphans.into_iter().flatten());

            if page.next_key_marker.is_none() {
                break;
            }
            key_marker = page.next_key_marker;
            upload_id_marker = page.next_upload_id_marker;
        }

        Ok(orphans)
    }

    async fn abort_orphan_multipart_upload(
        &self,
        upload: &OrphanMultipartUpload,
    ) -> Result<(), Error> {
        // `abort_upload` is keyed: it aborts every in-flight multipart at the
        // key and removes any staged remainder, subsuming the per-upload-id
        // abort.
        self.object
            .abort_upload(&upload.key)
            .await
            .map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;

    use angos_storage::{
        BoxedReader, ByteStream, ChildrenPage, MultipartUploadPage, ObjectMeta, ObjectStore, Page,
        PendingMultipartUpload,
    };

    use crate::registry::blob_store::multipart_cleanup::*;

    #[test]
    fn test_is_orphan_recent_upload_is_not_orphan() {
        let now = Utc::now();
        let initiated = now - Duration::minutes(5);
        let timeout = Duration::hours(1);
        assert!(!is_orphan(initiated, now, timeout));
    }

    #[test]
    fn test_is_orphan_old_upload_is_orphan() {
        let now = Utc::now();
        let initiated = now - Duration::hours(2);
        let timeout = Duration::hours(1);
        assert!(is_orphan(initiated, now, timeout));
    }

    /// At the exact boundary (age == timeout), the upload is considered orphaned
    /// because the check uses `>=`.
    #[test]
    fn test_is_orphan_at_exact_timeout_boundary() {
        let now = Utc::now();
        let timeout = Duration::hours(1);
        let initiated = now - timeout;
        assert!(is_orphan(initiated, now, timeout));
    }

    /// An upload whose `initiated` timestamp is in the future (clock skew) must
    /// never be treated as orphaned.
    #[test]
    fn test_is_orphan_future_initiated_is_not_orphan() {
        let now = Utc::now();
        let initiated = now + Duration::minutes(10);
        let timeout = Duration::hours(1);
        assert!(!is_orphan(initiated, now, timeout));
    }

    #[test]
    fn test_parse_upload_key_valid() {
        let result = parse_upload_key("v2/repositories/my-repo/_uploads/abc-123-def/data");
        assert_eq!(result, Some(("my-repo", "abc-123-def")));
    }

    #[test]
    fn test_parse_upload_key_coalesce_scratch() {
        let result =
            parse_upload_key("v2/repositories/my-repo/_uploads/abc-123-def/staged/coalesce");
        assert_eq!(result, Some(("my-repo", "abc-123-def")));
    }

    #[test]
    fn test_parse_upload_key_nested_namespace() {
        let result = parse_upload_key("v2/repositories/org/project/image/_uploads/uuid-here/data");
        assert_eq!(result, Some(("org/project/image", "uuid-here")));
    }

    #[test]
    fn test_parse_upload_key_invalid_prefix() {
        let result = parse_upload_key("invalid/prefix/_uploads/uuid/data");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_upload_key_invalid_suffix() {
        let result = parse_upload_key("v2/repositories/repo/_uploads/uuid/staged");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_upload_key_missing_uploads() {
        let result = parse_upload_key("v2/repositories/repo/blobs/sha256/abc/data");
        assert_eq!(result, None);
    }

    /// Reports one long-abandoned multipart upload and answers every `head`
    /// with `head_result`, so a test can pin what each probe outcome means.
    #[derive(Debug)]
    struct OneStaleUpload {
        key: String,
        head_error: StorageError,
    }

    #[async_trait]
    impl ObjectStore for OneStaleUpload {
        async fn list_multipart_uploads(
            &self,
            _key_marker: Option<&str>,
            _upload_id_marker: Option<&str>,
        ) -> Result<MultipartUploadPage, StorageError> {
            Ok(MultipartUploadPage {
                uploads: vec![PendingMultipartUpload {
                    key: self.key.clone(),
                    upload_id: "upload-1".to_string(),
                    initiated_at: Utc::now() - Duration::days(1),
                }],
                next_key_marker: None,
                next_upload_id_marker: None,
            })
        }

        async fn head(&self, _key: &str) -> Result<ObjectMeta, StorageError> {
            Err(match &self.head_error {
                StorageError::NotFound => StorageError::NotFound,
                other => StorageError::Backend(other.to_string()),
            })
        }

        async fn get(&self, _key: &str) -> Result<Vec<u8>, StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn get_stream(
            &self,
            _key: &str,
            _offset: Option<u64>,
        ) -> Result<(BoxedReader, u64), StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn put(&self, _key: &str, _data: Bytes) -> Result<(), StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn delete(&self, _key: &str) -> Result<(), StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn delete_prefix(&self, _prefix: &str) -> Result<(), StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn list(
            &self,
            _prefix: &str,
            _n: u16,
            _token: Option<String>,
        ) -> Result<Page<String>, StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn create_if_absent(&self, _key: &str, _data: Bytes) -> Result<bool, StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn list_after(
            &self,
            _prefix: &str,
            _n: u16,
            _token: Option<String>,
            _start_after: Option<String>,
        ) -> Result<Page<String>, StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn list_children(
            &self,
            _prefix: &str,
            _n: u16,
            _token: Option<String>,
            _start_after: Option<String>,
        ) -> Result<ChildrenPage, StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn copy(&self, _source: &str, _destination: &str) -> Result<(), StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn create_upload(&self, _key: &str) -> Result<(), StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn write_upload(
            &self,
            _key: &str,
            _body: ByteStream,
            _len: Option<u64>,
        ) -> Result<u64, StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn complete_upload(&self, _key: &str) -> Result<(), StorageError> {
            unimplemented!("not reached by orphan listing")
        }
        async fn abort_upload(&self, _key: &str) -> Result<(), StorageError> {
            unimplemented!("not reached by orphan listing")
        }
    }

    /// The abort is keyed and destroys every committed part, so a probe that
    /// merely failed must not condemn the upload: only a missing marker proves
    /// the session is gone.
    #[tokio::test]
    async fn a_failed_liveness_probe_does_not_orphan_a_live_upload() {
        let namespace = Namespace::new("test-repo").unwrap();
        let key = path_builder::upload_path(&namespace, &UploadSessionId::generate());
        let store = BlobStore::new(
            Arc::new(OneStaleUpload {
                key,
                head_error: StorageError::Backend("upstream is unavailable".to_string()),
            }),
            None,
        );

        let orphans = store
            .list_orphan_multipart_uploads(Duration::hours(1))
            .await
            .expect("a failed probe must not fail the sweep");

        assert!(
            orphans.is_empty(),
            "a transient probe failure must not condemn an upload, got {} orphan(s)",
            orphans.len()
        );
    }

    /// The counterpart: an absent marker still proves the session is gone, so
    /// cleanup must not have been disabled along with the false positives.
    #[tokio::test]
    async fn an_absent_marker_still_orphans_a_stale_upload() {
        let namespace = Namespace::new("test-repo").unwrap();
        let key = path_builder::upload_path(&namespace, &UploadSessionId::generate());
        let store = BlobStore::new(
            Arc::new(OneStaleUpload {
                key: key.clone(),
                head_error: StorageError::NotFound,
            }),
            None,
        );

        let orphans = store
            .list_orphan_multipart_uploads(Duration::hours(1))
            .await
            .expect("listing must succeed");

        assert_eq!(orphans.len(), 1, "an absent marker must still be cleaned");
        assert_eq!(orphans[0].key, key);
    }
}
