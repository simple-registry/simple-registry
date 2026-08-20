//! The `-u` window sweeps: upload sessions, orphan S3 multiparts, and byteless
//! blob-index shard entries. Grant-only blob ownership is a retention subject
//! instead; see `checker::sweep_orphan_grants`.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use futures_util::TryStreamExt;
use tracing::{debug, error, info, warn};

use angos_oci::{Digest, Namespace, UploadSessionId};
use angos_storage::Error as StorageError;

use crate::registry::keys::DigestKeys;
use crate::{
    command::maintenance::{
        Error,
        action::Action,
        categorize::{KeyCategory, categorize},
        executor::ActionSink,
        walk,
    },
    registry::{
        Error as RegistryError,
        blob_store::{BlobStore, MultipartCleanup, UploadSummary},
        metadata_store::MetadataStore,
        path_builder,
    },
};

enum UploadVerdict {
    /// Missing summary or corrupted data.
    DeleteInconsistent,
    /// Age exceeds the window.
    DeleteObsolete,
    Keep,
}

#[allow(clippy::match_same_arms)]
fn classify_upload(
    summary: Result<&UploadSummary, &RegistryError>,
    window: Duration,
    now: DateTime<Utc>,
) -> UploadVerdict {
    match summary {
        Ok(s) if now.signed_duration_since(s.started_at) > window => UploadVerdict::DeleteObsolete,
        Ok(_) => UploadVerdict::Keep,
        // A corrupt record never decodes on a retry, so the session can never
        // complete and is safe to reap at any age.
        Err(
            RegistryError::BlobUploadUnknown
            | RegistryError::NotFound
            | RegistryError::BlobUnknown
            | RegistryError::Corrupt(_),
        ) => UploadVerdict::DeleteInconsistent,
        // Deleting on a transient read failure would destroy a live upload.
        Err(_) => UploadVerdict::Keep,
    }
}

/// Delete every upload session older than the window or with broken state.
/// Sessions of one namespace are checked up to `concurrency` at a time.
pub async fn sweep_upload_sessions(
    blob_store: &Arc<BlobStore>,
    window: Duration,
    sink: &dyn ActionSink,
    concurrency: usize,
) -> Result<(), Error> {
    for namespace in blob_store.collect_upload_namespaces(None).await? {
        let namespace = &namespace;
        blob_store
            .stream_uploads(namespace)
            .err_into::<Error>()
            .try_for_each_concurrent(concurrency, |session_id| async move {
                if let Err(e) =
                    sweep_one_upload(blob_store, namespace, &session_id, window, sink).await
                {
                    error!("prune: failed to check upload '{namespace}/{session_id}': {e}");
                }
                Ok(())
            })
            .await?;
    }
    Ok(())
}

async fn sweep_one_upload(
    blob_store: &Arc<BlobStore>,
    namespace: &Namespace,
    session_id: &UploadSessionId,
    window: Duration,
    sink: &dyn ActionSink,
) -> Result<(), Error> {
    let summary = blob_store.upload_summary(namespace, session_id).await;
    match classify_upload(summary.as_ref(), window, Utc::now()) {
        UploadVerdict::DeleteInconsistent | UploadVerdict::DeleteObsolete => {
            debug!("prune: reaping upload '{namespace}/{session_id}'");
            sink.apply(Action::DeleteExpiredUpload {
                namespace: namespace.clone(),
                session_id: session_id.clone(),
            })
            .await
        }
        UploadVerdict::Keep => Ok(()),
    }
}

/// Abort every in-flight S3 multipart upload older than the window whose
/// session marker is gone (a crash between opening the multipart and writing
/// the marker leaves exactly this).
pub async fn sweep_orphan_multiparts(
    cleanup: &(dyn MultipartCleanup + Send + Sync),
    window: Duration,
    sink: &dyn ActionSink,
) -> Result<(), Error> {
    let orphans = cleanup
        .list_orphan_multipart_uploads(window)
        .await
        .map_err(Error::from)?;
    let count = orphans.len();
    for orphan in orphans {
        sink.apply(Action::AbortMultipartUpload { upload: orphan })
            .await?;
    }
    info!("prune: found {count} orphan multipart upload(s)");
    Ok(())
}

/// Remove blob-index entries referencing byteless blobs once the shard is
/// older than the window: a grant whose bytes never landed or were reclaimed
/// out-of-band. A pull-through grant is purged too, since the next pull
/// re-fills and re-grants.
pub async fn sweep_byteless_shards(
    blob_store: &Arc<BlobStore>,
    metadata_store: &Arc<MetadataStore>,
    window: Duration,
    sink: &dyn ActionSink,
    concurrency: usize,
) -> Result<(), Error> {
    let objects = metadata_store.object_store();
    let ctx = ShardSweep {
        blob_store,
        metadata_store,
        window,
        now: Utc::now(),
        sink,
    };
    let ctx = &ctx;
    // Legacy shards live under the blobs root, reference keys under their own.
    for root in [path_builder::BLOBS_ROOT, path_builder::REF_ROOT] {
        walk::for_each_key(objects, root, concurrency, |key| async move {
            let (KeyCategory::BlobIndexShard { digest, namespace }
            | KeyCategory::BlobRef {
                digest, namespace, ..
            }) = categorize(&key)
            else {
                return;
            };
            if let Err(e) = sweep_one_shard(ctx, &key, &digest, &namespace).await {
                error!("prune: failed to check index entry '{key}': {e}");
            }
        })
        .await?;
    }
    Ok(())
}

struct ShardSweep<'a> {
    blob_store: &'a Arc<BlobStore>,
    metadata_store: &'a Arc<MetadataStore>,
    window: Duration,
    now: DateTime<Utc>,
    sink: &'a dyn ActionSink,
}

async fn sweep_one_shard(
    ctx: &ShardSweep<'_>,
    key: &str,
    blob: &Digest,
    namespace_raw: &str,
) -> Result<(), Error> {
    match ctx.blob_store.size(blob).await {
        Ok(_) => return Ok(()),
        Err(RegistryError::BlobUnknown | RegistryError::NotFound) => {}
        Err(e) => return Err(e.into()),
    }
    let Ok(namespace) = Namespace::new(namespace_raw) else {
        return Ok(());
    };
    let meta = match ctx.metadata_store.object_store().head(key).await {
        Ok(meta) => meta,
        Err(StorageError::NotFound) => return Ok(()),
        Err(e) => return Err(RegistryError::from(e).into()),
    };
    let Some(last_modified) = meta.last_modified else {
        // No timestamp to gate on, so keep rather than race an upload that
        // granted before its bytes landed.
        return Ok(());
    };
    if ctx.now.signed_duration_since(last_modified) < ctx.window {
        return Ok(());
    }

    warn!("prune: purging index entries for byteless blob '{blob}' in '{namespace}'");
    let links = ctx
        .metadata_store
        .read_blob_index_namespace(&namespace, blob)
        .await?;
    for link in links {
        // The walked key's age gate does not cover its siblings: a fresh
        // `_own` granted before its bytes land is normal, so each entry is
        // gated on its own reference key.
        if entry_is_young(ctx, &blob.blob_ref_path(&namespace, &link)).await? {
            continue;
        }
        ctx.sink
            .apply(Action::RemoveBlobIndexLink {
                namespace: namespace.clone(),
                blob: blob.clone(),
                link,
            })
            .await?;
    }
    Ok(())
}

/// Whether an entry's reference key is younger than the sweep window. A
/// missing timestamp reads as young; an absent key reads as old, its only
/// record being the already-gated legacy shard.
async fn entry_is_young(ctx: &ShardSweep<'_>, ref_key: &str) -> Result<bool, Error> {
    let meta = match ctx.metadata_store.object_store().head(ref_key).await {
        Ok(meta) => meta,
        Err(StorageError::NotFound) => return Ok(false),
        Err(e) => return Err(RegistryError::from(e).into()),
    };
    Ok(meta
        .last_modified
        .is_none_or(|modified| ctx.now.signed_duration_since(modified) < ctx.window))
}

#[cfg(test)]
mod tests {
    use crate::registry::keys::NamespaceKeys;
    use chrono::TimeZone;

    use crate::command::prune::uploads::*;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 6, 1, 12, 0, 0).unwrap()
    }

    fn summary_started_at(offset_secs: i64) -> UploadSummary {
        UploadSummary {
            size: 0,
            started_at: fixed_now() - Duration::seconds(offset_secs),
        }
    }

    #[test]
    fn classify_upload_keeps_recent_upload() {
        let verdict = classify_upload(
            Ok(&summary_started_at(1800)),
            Duration::hours(1),
            fixed_now(),
        );
        assert!(matches!(verdict, UploadVerdict::Keep));
    }

    #[test]
    fn classify_upload_keeps_exactly_at_window() {
        let verdict = classify_upload(
            Ok(&summary_started_at(3600)),
            Duration::hours(1),
            fixed_now(),
        );
        assert!(matches!(verdict, UploadVerdict::Keep));
    }

    #[test]
    fn classify_upload_deletes_past_window() {
        let verdict = classify_upload(
            Ok(&summary_started_at(3601)),
            Duration::hours(1),
            fixed_now(),
        );
        assert!(matches!(verdict, UploadVerdict::DeleteObsolete));
    }

    #[test]
    fn classify_upload_deletes_broken_state() {
        for error in [
            RegistryError::BlobUploadUnknown,
            RegistryError::NotFound,
            RegistryError::BlobUnknown,
            RegistryError::Corrupt("hash state deserialization error".to_string()),
        ] {
            let verdict = classify_upload(Err(&error), Duration::hours(1), fixed_now());
            assert!(matches!(verdict, UploadVerdict::DeleteInconsistent));
        }
    }

    #[test]
    fn classify_upload_keeps_on_transient_error() {
        let error = RegistryError::Internal("transient backend error".to_string());
        let verdict = classify_upload(Err(&error), Duration::hours(1), fixed_now());
        assert!(matches!(verdict, UploadVerdict::Keep));
    }

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    use std::time::Duration as StdDuration;

    use async_trait::async_trait;
    use bytes::Bytes;
    use tokio::time::sleep;

    use angos_oci::{Digest, Namespace};

    use crate::{
        command::maintenance::executor::Executor,
        registry::{
            blob_store::OrphanMultipartUpload,
            metadata_store::{BlobIndexOperation, LinkKind},
            test_utils::for_each_backend,
        },
    };

    #[tokio::test]
    async fn sweep_reaps_obsolete_upload_and_keeps_recent() {
        for_each_backend(async |test_case| {
            let namespace = Namespace::new("test-repo/app").unwrap();
            let blob_store = test_case.blob_store();

            let old_uuid = UploadSessionId::generate();
            blob_store
                .create_upload(&namespace, &old_uuid, None)
                .await
                .unwrap();

            let executor = Executor::new_for_test(blob_store.clone(), test_case.metadata_store());

            // Zero window: the just-created upload is already past it.
            sweep_upload_sessions(&blob_store, Duration::zero(), &executor, 4)
                .await
                .unwrap();
            assert!(
                blob_store
                    .upload_summary(&namespace, &old_uuid)
                    .await
                    .is_err(),
                "an upload past the window must be reaped"
            );

            let fresh_uuid = UploadSessionId::generate();
            blob_store
                .create_upload(&namespace, &fresh_uuid, None)
                .await
                .unwrap();
            sweep_upload_sessions(&blob_store, Duration::days(1), &executor, 4)
                .await
                .unwrap();
            assert!(
                blob_store
                    .upload_summary(&namespace, &fresh_uuid)
                    .await
                    .is_ok(),
                "an upload within the window must be kept"
            );
        })
        .await;
    }

    /// The sweep ages both session shapes on their own record: a backdated
    /// `session.json` and a backdated legacy `startedat` are reaped, a fresh
    /// legacy session is not.
    #[tokio::test]
    async fn sweep_ages_both_session_shapes() {
        for_each_backend(async |test_case| {
            let namespace = Namespace::new("test-repo/shapes").unwrap();
            let blob_store = test_case.blob_store();
            let objects = blob_store.object_store();
            let old_ts = Utc::now() - Duration::hours(2);

            // New shape, backdated by rewriting `session.json` in place.
            let new_shape = UploadSessionId::generate();
            blob_store
                .create_upload(&namespace, &new_shape, None)
                .await
                .unwrap();
            let record = format!(
                r#"{{"last_activity":"{}","committed_offset":0,"hash_state":""}}"#,
                old_ts.to_rfc3339()
            );
            objects
                .put(
                    &namespace.upload_session_path(&new_shape),
                    Bytes::from(record),
                )
                .await
                .unwrap();

            // Legacy shapes seeded raw: one backdated, one fresh.
            let old_legacy = UploadSessionId::generate();
            let fresh_legacy = UploadSessionId::generate();
            for (id, ts) in [(&old_legacy, old_ts), (&fresh_legacy, Utc::now())] {
                objects
                    .put(
                        &path_builder::upload_start_date_path(&namespace, id),
                        Bytes::from(ts.to_rfc3339()),
                    )
                    .await
                    .unwrap();
                objects
                    .put(
                        &path_builder::upload_hash_context_path(&namespace, id, 4),
                        Bytes::from_static(b"raw checkpoint bytes"),
                    )
                    .await
                    .unwrap();
            }

            let executor = Executor::new_for_test(blob_store.clone(), test_case.metadata_store());
            sweep_upload_sessions(&blob_store, Duration::hours(1), &executor, 4)
                .await
                .unwrap();

            assert!(
                blob_store
                    .upload_summary(&namespace, &new_shape)
                    .await
                    .is_err(),
                "an aged session.json session must be reaped"
            );
            assert!(
                blob_store
                    .upload_summary(&namespace, &old_legacy)
                    .await
                    .is_err(),
                "an aged legacy session must be reaped"
            );
            assert!(
                blob_store
                    .upload_summary(&namespace, &fresh_legacy)
                    .await
                    .is_ok(),
                "a fresh legacy session must be kept"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn sweep_dry_run_captures_without_deleting() {
        for_each_backend(async |test_case| {
            let namespace = Namespace::new("test-repo/app").unwrap();
            let blob_store = test_case.blob_store();

            let session_id = UploadSessionId::generate();
            blob_store
                .create_upload(&namespace, &session_id, None)
                .await
                .unwrap();

            let sink: Mutex<Vec<Action>> = Mutex::new(Vec::new());
            sweep_upload_sessions(&blob_store, Duration::zero(), &sink, 4)
                .await
                .unwrap();

            assert!(
                sink.lock()
                    .unwrap()
                    .iter()
                    .any(|a| matches!(a, Action::DeleteExpiredUpload { .. })),
                "the capture sink must record the delete"
            );
            assert!(
                blob_store
                    .upload_summary(&namespace, &session_id)
                    .await
                    .is_ok(),
                "a capture sink must not delete"
            );
        })
        .await;
    }

    struct SpyCleanup {
        list_called_timeout_secs: AtomicI64,
        abort_call_count: AtomicUsize,
        orphans: Vec<String>,
    }

    impl SpyCleanup {
        fn new(orphan_keys: Vec<&str>) -> Self {
            Self {
                list_called_timeout_secs: AtomicI64::new(-1),
                abort_call_count: AtomicUsize::new(0),
                orphans: orphan_keys.into_iter().map(str::to_owned).collect(),
            }
        }
    }

    #[async_trait]
    impl MultipartCleanup for SpyCleanup {
        async fn list_orphan_multipart_uploads(
            &self,
            timeout: Duration,
        ) -> Result<Vec<OrphanMultipartUpload>, RegistryError> {
            self.list_called_timeout_secs
                .store(timeout.num_seconds(), Ordering::SeqCst);
            Ok(self
                .orphans
                .iter()
                .map(|k| OrphanMultipartUpload {
                    key: k.clone(),
                    upload_id: "spy-upload-id".to_string(),
                })
                .collect())
        }

        async fn abort_orphan_multipart_upload(
            &self,
            _upload: &OrphanMultipartUpload,
        ) -> Result<(), RegistryError> {
            self.abort_call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn multipart_sweep_forwards_timeout_and_captures_orphans() {
        let spy = SpyCleanup::new(vec!["ns/_uploads/uuid1/data", "ns/_uploads/uuid2/data"]);
        let sink: Mutex<Vec<Action>> = Mutex::new(Vec::new());

        sweep_orphan_multiparts(&spy, Duration::hours(2), &sink)
            .await
            .unwrap();

        assert_eq!(
            spy.list_called_timeout_secs.load(Ordering::SeqCst),
            7200,
            "timeout forwarded as 2 h = 7200 s"
        );
        assert_eq!(
            spy.abort_call_count.load(Ordering::SeqCst),
            0,
            "a capture sink must not invoke abort"
        );
        let sink = sink.into_inner().unwrap();
        assert_eq!(sink.len(), 2, "two orphans produce two actions");
        assert!(
            sink.iter()
                .all(|a| matches!(a, Action::AbortMultipartUpload { .. }))
        );
    }

    /// An `_own` grant landed after the sweep's cutoff must survive the purge
    /// its old sibling entry triggers.
    #[tokio::test]
    async fn byteless_purge_keeps_young_sibling_own_key() {
        for_each_backend(async |test_case| {
            let namespace = Namespace::new("test-repo/byteless-own").unwrap();
            let blob_store = test_case.blob_store();
            let metadata_store = test_case.metadata_store();

            let ghost = Digest::sha256_of_bytes(b"byteless with fresh own");
            let stale = LinkKind::Layer(ghost.clone());
            metadata_store
                .update_blob_index(
                    &namespace,
                    &ghost,
                    BlobIndexOperation::Insert(stale.clone()),
                )
                .await
                .unwrap();
            // A cutoff between the two puts: the layer entry reads old, the
            // later `_own` grant young. The sleeps keep both clear of the
            // cutoff on second-granularity store timestamps.
            sleep(StdDuration::from_millis(1500)).await;
            let window = Duration::hours(1);
            let now = Utc::now() + window;
            sleep(StdDuration::from_millis(1500)).await;
            metadata_store
                .update_blob_index(
                    &namespace,
                    &ghost,
                    BlobIndexOperation::Insert(LinkKind::Blob(ghost.clone())),
                )
                .await
                .unwrap();

            let sink: Mutex<Vec<Action>> = Mutex::new(Vec::new());
            let ctx = ShardSweep {
                blob_store: &blob_store,
                metadata_store: &metadata_store,
                window,
                now,
                sink: &sink,
            };
            let walked = ghost.blob_ref_path(&namespace, &stale);
            sweep_one_shard(&ctx, &walked, &ghost, namespace.as_ref())
                .await
                .unwrap();

            let actions = sink.into_inner().unwrap();
            assert!(
                actions.iter().any(
                    |a| matches!(a, Action::RemoveBlobIndexLink { link, .. } if link == &stale)
                ),
                "the old byteless entry must still be purged"
            );
            assert!(
                !actions.iter().any(|a| matches!(
                    a,
                    Action::RemoveBlobIndexLink {
                        link: LinkKind::Blob(_),
                        ..
                    }
                )),
                "a young sibling `_own` grant must survive the purge"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn byteless_shard_entries_are_purged_past_the_window() {
        for_each_backend(async |test_case| {
            let namespace = Namespace::new("test-repo/byteless").unwrap();
            let blob_store = test_case.blob_store();
            let metadata_store = test_case.metadata_store();

            // An index entry whose blob bytes never landed.
            let ghost = Digest::sha256_of_bytes(b"bytes-never-landed");
            metadata_store
                .update_blob_index(
                    &namespace,
                    &ghost,
                    BlobIndexOperation::Insert(LinkKind::Blob(ghost.clone())),
                )
                .await
                .unwrap();

            let executor = Executor::new_for_test(blob_store.clone(), metadata_store.clone());

            sweep_byteless_shards(
                &blob_store,
                &metadata_store,
                Duration::days(1),
                &executor,
                4,
            )
            .await
            .unwrap();
            assert!(
                metadata_store
                    .read_blob_index_namespace(&namespace, &ghost)
                    .await
                    .is_ok(),
                "a byteless entry within the window must be kept"
            );

            sweep_byteless_shards(&blob_store, &metadata_store, Duration::zero(), &executor, 4)
                .await
                .unwrap();
            assert!(
                metadata_store
                    .read_blob_index_namespace(&namespace, &ghost)
                    .await
                    .is_err(),
                "a byteless entry past the window must be purged"
            );
        })
        .await;
    }
}
