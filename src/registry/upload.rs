use hyper::{HeaderMap, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, copy, sink};
use tracing::{instrument, warn};

use angos_oci::request::{
    BlobMount, CompleteUploadRequest, DeleteUploadRequest, GetUploadRequest, MountBlobRequest,
    PatchUploadRequest, StartUploadRequest,
};
use angos_oci::server;
use angos_oci::{Algorithm, Digest, Namespace, UploadSessionId};

use crate::{
    event_webhook::event::{Event, EventActor},
    http_response::{ResponseBody, build_response},
    registry::{
        Error, Registry,
        blob_ownership::promote_and_grant,
        blob_store::{hashing_reader::HashingReader, resumable_hasher::Hasher},
    },
};

/// Caps the namespaces CEL-evaluated for a from-less mount, bounding an
/// attacker-influenceable fan-out. Candidates beyond the cap fall back to a
/// normal upload session, so no access is over-granted.
const MAX_FROM_LESS_MOUNT_CANDIDATES: usize = 32;

/// Default cap on a blob's cumulative uploaded size, mirroring
/// [`manifest::DEFAULT_MAX_MANIFEST_SIZE_BYTES`](crate::registry::manifest::DEFAULT_MAX_MANIFEST_SIZE_BYTES).
pub const DEFAULT_MAX_BLOB_SIZE_BYTES: u64 = 100 * 1024 * 1024 * 1024;

impl Registry {
    async fn complete_existing_upload<S>(
        &self,
        namespace: &Namespace,
        digest: &Digest,
        content_length: Option<u64>,
        stream: &mut S,
    ) -> Result<bool, Error>
    where
        S: AsyncRead + Unpin,
    {
        {
            if self.blob_store.size(digest).await.is_err() {
                return Ok(false);
            }

            // The blob already exists, so there is nothing to store: hash the
            // body into a sink under the target algorithm alone, purely to
            // confirm it matches. With a declared length, drain at most one byte
            // past it so an over-long body is rejected as soon as the surplus
            // appears rather than after the whole `bound_blob_stream`-capped
            // body is read.
            let mut reader =
                HashingReader::new(&mut *stream, Hasher::for_algorithm(digest.algorithm()));
            match content_length {
                Some(expected) => {
                    // Draining faults are I/O (surface the source); only the
                    // read-vs-declared comparison is a length mismatch (416).
                    let read = copy(
                        &mut (&mut reader).take(expected.saturating_add(1)),
                        &mut sink(),
                    )
                    .await?;
                    if read != expected {
                        return Err(Error::RangeNotSatisfiable);
                    }
                }
                None => {
                    copy(&mut reader, &mut sink()).await?;
                }
            }

            let upload_digest = reader.into_hasher().digest(digest.algorithm())?;
            if &upload_digest != digest {
                warn!("Expected digest '{digest}', got '{upload_digest}'");
                return Err(Error::DigestInvalid);
            }

            // The bytes pre-exist and may be old: the guarded grant
            // catches a mid-flight reclaim, falling back to a fresh
            // upload of the streamed body.
            self.blob_ownership()
                .grant_existing(&self.blob_store, namespace, digest)
                .await
        }
    }

    async fn finish_completed_upload(
        &self,
        namespace: &Namespace,
        session_id: &UploadSessionId,
        digest: &Digest,
    ) -> Result<Response<ResponseBody>, Error> {
        if let Err(error) = self.blob_store.delete_upload(namespace, session_id).await {
            warn!("Failed to delete completed upload state: {error}");
        }

        Ok(build_response(
            StatusCode::CREATED,
            server::blob_location_headers(namespace, digest)?,
            ResponseBody::empty(),
        )?)
    }

    /// Grants `namespace` a reference to `mount.digest`, re-checked against
    /// the authorized `source`, returning `Ok(None)` when the source no
    /// longer holds the blob or its bytes are gone (including a reclaim
    /// caught mid-flight by the guarded grant), which falls back to a
    /// regular upload session per the spec.
    async fn try_cross_repo_mount(
        &self,
        namespace: &Namespace,
        mount: &BlobMount,
        source: &Namespace,
    ) -> Result<Option<Digest>, Error> {
        (async {
            if self.blob_store.size(&mount.digest).await.is_err()
                || !self
                    .blob_ownership()
                    .can_read(source, &mount.digest)
                    .await?
            {
                return Ok(None);
            }

            if !self
                .blob_ownership()
                .grant_existing(&self.blob_store, namespace, &mount.digest)
                .await?
            {
                return Ok(None);
            }
            Ok(Some(mount.digest.clone()))
        })
        .await
    }

    /// Source namespaces whose read policy must permit the caller: `[from]`
    /// when set and owning the blob, else every namespace referencing it.
    /// Empty when the mount cannot be satisfied.
    pub async fn mount_source_candidates(
        &self,
        mount: &BlobMount,
    ) -> Result<Vec<Namespace>, Error> {
        if self.blob_store.size(&mount.digest).await.is_err() {
            return Ok(Vec::new());
        }

        if let Some(from) = &mount.from {
            let readable = self.blob_ownership().can_read(from, &mount.digest).await?;
            return Ok(if readable {
                vec![from.clone()]
            } else {
                Vec::new()
            });
        }

        let mut candidates = self
            .blob_ownership()
            .referencing_namespaces(&mount.digest)
            .await?;
        // Sort before truncating so the kept candidates are deterministic.
        candidates.sort();
        candidates.truncate(MAX_FROM_LESS_MOUNT_CANDIDATES);
        Ok(candidates)
    }

    /// Opens a fresh resumable upload session and returns its `202` headers.
    /// `digest_algorithm` is the client's `?digest-algorithm=` hint, which fixes
    /// what each chunk is hashed under.
    async fn open_upload_session(
        &self,
        namespace: &Namespace,
        digest_algorithm: Option<Algorithm>,
    ) -> Result<Response<ResponseBody>, Error> {
        let session_id = UploadSessionId::generate();
        self.blob_store
            .create_upload(namespace, &session_id, digest_algorithm)
            .await?;

        Ok(build_response(
            StatusCode::ACCEPTED,
            server::upload_session_headers(namespace, &session_id)?,
            ResponseBody::empty(),
        )?)
    }

    /// Starts a blob upload: `201` when the namespace already owns `digest` or
    /// when a `?digest=` POST carries the whole blob, otherwise a new session
    /// (`202`).
    #[instrument(skip(request, stream), fields(namespace = %request.namespace))]
    pub async fn start_upload<S>(
        &self,
        actor: Option<EventActor>,
        request: StartUploadRequest,
        stream: S,
    ) -> Result<Response<ResponseBody>, Error>
    where
        S: AsyncRead + Unpin + Send + Sync + 'static,
    {
        let Some(target) = request.target else {
            return self
                .open_upload_session(&request.namespace, request.digest_algorithm)
                .await;
        };
        let digest = target.digest;

        if self.blob_store.size(&digest).await.is_ok()
            && self
                .blob_ownership()
                .can_read(&request.namespace, &digest)
                .await?
        {
            return Ok(build_response(
                StatusCode::CREATED,
                server::blob_location_headers(&request.namespace, &digest)?,
                ResponseBody::empty(),
            )?);
        }

        // A `?digest=` POST carrying the blob is the single-request upload, a
        // declared zero being the empty blob. Only an undeclared length falls
        // back to a session, which hashes the target's algorithm alone.
        let Some(content_length) = target.content_length else {
            return self
                .open_upload_session(&request.namespace, Some(digest.algorithm()))
                .await;
        };

        let session_id = UploadSessionId::generate();
        self.blob_store
            .create_upload(&request.namespace, &session_id, Some(digest.algorithm()))
            .await?;

        self.complete_upload(
            actor,
            CompleteUploadRequest {
                namespace: request.namespace.clone(),
                session_id: session_id.clone(),
                digest: digest.clone(),
                content_range: None,
                content_length: Some(content_length),
            },
            stream,
        )
        .await
    }

    /// Starts a cross-repository blob mount from `source`, the namespace the
    /// caller was authorized to read the blob from, which is resolved by the
    /// serving side rather than named on the wire. A mount that cannot be
    /// satisfied falls back to an ordinary upload session.
    ///
    /// The `blob.push` intent event fires before the mount attempt, so a mounted
    /// blob is as visible to webhook consumers as an uploaded one; the session
    /// fallback leaves a false-positive event behind and its eventual upload
    /// completion emits one of its own.
    #[instrument(skip(request))]
    pub async fn mount_blob(
        &self,
        actor: Option<EventActor>,
        request: MountBlobRequest,
        source: Option<Namespace>,
    ) -> Result<Response<ResponseBody>, Error> {
        let repository = self.repository_name_for(&request.namespace);
        let event = Event::push_blob(
            &request.namespace,
            &repository,
            &request.mount.digest,
            actor.as_ref(),
        );
        self.dispatch_events(&[event]).await?;

        // An unsatisfiable mount degrades to an ordinary upload session, so the
        // caller is never told whether the blob exists.
        let Some(source) = &source else {
            return self.open_upload_session(&request.namespace, None).await;
        };

        if let Some(digest) = self
            .try_cross_repo_mount(&request.namespace, &request.mount, source)
            .await?
        {
            return Ok(build_response(
                StatusCode::CREATED,
                server::blob_location_headers(&request.namespace, &digest)?,
                ResponseBody::empty(),
            )?);
        }

        self.open_upload_session(&request.namespace, None).await
    }

    /// Early-reject a known-length body whose declared length would push the
    /// session's cumulative size past `max_blob_size_bytes`, aborting the
    /// session first so its staged bytes are reclaimed.
    async fn reject_oversized_known_length(
        &self,
        namespace: &Namespace,
        session_id: &UploadSessionId,
        committed: u64,
        content_length: Option<u64>,
    ) -> Result<(), Error> {
        let limit = self.max_blob_size_bytes;
        if let Some(len) = content_length
            && committed.checked_add(len).is_none_or(|total| total > limit)
        {
            self.abort_upload_quietly(namespace, session_id).await;
            return Err(Error::BlobBodyTooLarge {
                limit: usize::try_from(limit).unwrap_or(usize::MAX),
            });
        }
        Ok(())
    }

    /// Bound a chunked (`None` content-length) body to `remaining + 1` bytes so
    /// it can never grow the session past `max_blob_size_bytes` without the
    /// extra byte tripping the overflow check after the write. `remaining` is
    /// the headroom left before the cap; a `Some(_)` content-length is passed
    /// through unbounded because [`Self::reject_oversized_known_length`] already
    /// vetted it.
    fn bound_blob_stream<S>(
        &self,
        committed: u64,
        content_length: Option<u64>,
        stream: S,
    ) -> tokio::io::Take<S>
    where
        S: AsyncRead + Unpin,
    {
        if content_length.is_some() {
            // A vetted known length never trips the guard; cap at exactly the
            // limit so a deceptive Content-Length cannot smuggle extra bytes.
            return stream.take(self.max_blob_size_bytes.saturating_add(1));
        }
        let remaining = self.max_blob_size_bytes.saturating_sub(committed);
        stream.take(remaining.saturating_add(1))
    }

    /// After a write, reject (and abort) when the session's cumulative size has
    /// exceeded `max_blob_size_bytes`, i.e. the chunked guard byte was consumed.
    async fn reject_if_oversized(
        &self,
        namespace: &Namespace,
        session_id: &UploadSessionId,
        new_total: u64,
    ) -> Result<(), Error> {
        let limit = self.max_blob_size_bytes;
        if new_total > limit {
            self.abort_upload_quietly(namespace, session_id).await;
            return Err(Error::BlobBodyTooLarge {
                limit: usize::try_from(limit).unwrap_or(usize::MAX),
            });
        }
        Ok(())
    }

    /// Best-effort abort of an upload session that can never complete (its body
    /// breached the size cap, or hashed to the wrong digest); a cleanup failure
    /// is logged, not surfaced, since the caller already has a terminal error to
    /// return.
    async fn abort_upload_quietly(&self, namespace: &Namespace, session_id: &UploadSessionId) {
        if let Err(error) = self.blob_store.delete_upload(namespace, session_id).await {
            warn!("Failed to abort upload session: {error}");
        }
    }

    #[instrument(skip(stream))]
    pub async fn patch_upload<S>(
        &self,
        request: PatchUploadRequest,
        stream: S,
    ) -> Result<Response<ResponseBody>, Error>
    where
        S: AsyncRead + Unpin + Send + Sync + 'static,
    {
        let summary = self
            .blob_store
            .upload_summary(&request.namespace, &request.session_id)
            .await?;

        // Refused before a byte is committed: a chunk must resume where the
        // session stands, and a declared length must match the window it
        // announced.
        if let Some(range) = request.content_range
            && (!range.starts_at(summary.size)
                || request
                    .content_length
                    .is_some_and(|length| !range.covers(length)))
        {
            return Err(Error::RangeNotSatisfiable);
        }

        self.reject_oversized_known_length(
            &request.namespace,
            &request.session_id,
            summary.size,
            request.content_length,
        )
        .await?;

        let bounded = self.bound_blob_stream(summary.size, request.content_length, stream);
        // PATCH only needs the running size; the digest is finalized at the PUT.
        // Concurrent PATCHes on one session are unserialized (the backends call
        // them unsupported); the PUT's digest check catches any interleaving.
        let (_, size) = self
            .blob_store
            .append_upload(
                &request.namespace,
                &request.session_id,
                Box::new(bounded),
                request.content_length,
            )
            .await?;

        self.reject_if_oversized(&request.namespace, &request.session_id, size)
            .await?;

        // A chunked body's length is only known once read, so its window can
        // only be checked here. The session now holds bytes the client will
        // never account for and the 416 cannot say so, hence the abort.
        if request.content_length.is_none()
            && let Some(range) = request.content_range
            && !range.covers(size.saturating_sub(summary.size))
        {
            self.abort_upload_quietly(&request.namespace, &request.session_id)
                .await;
            return Err(Error::RangeNotSatisfiable);
        }

        Ok(build_response(
            StatusCode::ACCEPTED,
            server::upload_progress_headers(
                &request.namespace,
                &request.session_id,
                size,
                Some(0),
            )?,
            ResponseBody::empty(),
        )?)
    }

    #[instrument(
        skip(stream, request),
        fields(
            namespace = %request.namespace,
            session_id = %request.session_id,
            digest = %request.digest,
        )
    )]
    pub async fn complete_upload<S>(
        &self,
        actor: Option<EventActor>,
        request: CompleteUploadRequest,
        stream: S,
    ) -> Result<Response<ResponseBody>, Error>
    where
        S: AsyncRead + Unpin + Send + Sync + 'static,
    {
        let CompleteUploadRequest {
            namespace,
            session_id,
            digest,
            content_range,
            content_length,
        } = request;
        let (namespace, session_id, digest) = (&namespace, &session_id, &digest);

        // Intent-first emission: the event fires before the finalize, so a
        // completed blob can never go unnotified; a completion that fails
        // past this point leaves a false-positive notification instead.
        let repository = self.repository_name_for(namespace);
        let event = Event::push_blob(namespace, &repository, digest, actor.as_ref());
        self.dispatch_events(&[event]).await?;

        // An unknown session reads as empty only so the blob-exists path below
        // can answer a retry whose 201 was lost; anything else it reaches 404s.
        let (committed, session_known) =
            match self.blob_store.upload_summary(namespace, session_id).await {
                Ok(summary) => (summary.size, true),
                Err(Error::BlobUploadUnknown) => (0, false),
                Err(e) => return Err(e),
            };
        let has_prior_writes = committed > 0;

        // A final-chunk PUT carrying a Content-Range must resume from the
        // committed offset and, when it declares a length, carry the window it
        // announced: both are out-of-order chunks (416), not digest mismatches,
        // and both are refused before a byte is committed.
        if let Some(range) = content_range
            && (!range.starts_at(committed)
                || content_length.is_some_and(|length| !range.covers(length)))
        {
            return Err(Error::RangeNotSatisfiable);
        }

        self.reject_oversized_known_length(namespace, session_id, committed, content_length)
            .await?;

        // Bound the final chunk so a chunked (`None` content-length) PUT that
        // carries the whole body cannot grow the session past the cap.
        let mut stream = self.bound_blob_stream(committed, content_length, stream);
        if !has_prior_writes
            && self
                .complete_existing_upload(namespace, digest, content_length, &mut stream)
                .await?
        {
            return self
                .finish_completed_upload(namespace, session_id, digest)
                .await;
        }

        if !session_known {
            return Err(Error::BlobUploadUnknown);
        }

        // A monolithic PUT (no prior chunked writes) knows its algorithm up
        // front, so hash only the target; a chunked finalize must resume the
        // both-algorithm checkpoint left by its PATCHes.
        let (upload_digest, new_total) = if has_prior_writes {
            self.blob_store
                .write_upload(
                    namespace,
                    session_id,
                    Box::new(stream),
                    content_length,
                    digest.algorithm(),
                )
                .await?
        } else {
            self.blob_store
                .write_monolithic_upload(
                    namespace,
                    session_id,
                    Box::new(stream),
                    content_length,
                    digest.algorithm(),
                )
                .await?
        };

        self.reject_if_oversized(namespace, session_id, new_total)
            .await?;

        // A chunked body's length is only known once read, so its window can
        // only be checked here. The session now holds bytes the client will
        // never account for and the 416 cannot say so, hence the abort.
        if content_length.is_none()
            && let Some(range) = content_range
            && !range.covers(new_total.saturating_sub(committed))
        {
            self.abort_upload_quietly(namespace, session_id).await;
            return Err(Error::RangeNotSatisfiable);
        }

        if &upload_digest != digest {
            warn!("Expected digest '{digest}', got '{upload_digest}'");
            // The session can never complete now: its bytes hash to something
            // the client did not ask for, so reclaim them here rather than
            // leaving a full upload for scrub.
            self.abort_upload_quietly(namespace, session_id).await;
            return Err(Error::DigestInvalid);
        }

        promote_and_grant(
            &self.blob_store,
            self.metadata_store.as_ref(),
            namespace,
            session_id,
            digest,
            new_total,
        )
        .await?;

        self.finish_completed_upload(namespace, session_id, digest)
            .await
    }

    #[instrument]
    pub async fn delete_upload(
        &self,
        request: DeleteUploadRequest,
    ) -> Result<Response<ResponseBody>, Error> {
        self.blob_store
            .delete_upload(&request.namespace, &request.session_id)
            .await?;

        Ok(build_response(
            StatusCode::NO_CONTENT,
            HeaderMap::new(),
            ResponseBody::empty(),
        )?)
    }

    #[instrument]
    pub async fn get_upload_status(
        &self,
        request: GetUploadRequest,
    ) -> Result<Response<ResponseBody>, Error> {
        let summary = self
            .blob_store
            .upload_summary(&request.namespace, &request.session_id)
            .await?;

        Ok(build_response(
            StatusCode::NO_CONTENT,
            server::upload_progress_headers(
                &request.namespace,
                &request.session_id,
                summary.size,
                None,
            )?,
            ResponseBody::empty(),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, str::FromStr, sync::Arc};

    use async_trait::async_trait;
    use hyper::{
        StatusCode,
        header::{LOCATION, RANGE},
    };

    use angos_oci::http_range::ByteWindow;
    use angos_oci::request::{
        BlobMount, CompleteUploadRequest, DeleteUploadRequest, GetUploadRequest, MountBlobRequest,
        PatchUploadRequest, StartUploadRequest, StartUploadTarget,
    };
    use angos_oci::{Algorithm, Digest, Namespace, UploadSessionId};
    use angos_storage::{
        Error as StorageError,
        test_util::{HookedStore, StoreHook, StoreOp},
    };

    use crate::registry::{
        Error, Registry, RegistryConfig,
        blob_store::BlobStore,
        metadata_store::LinkKind,
        path_builder,
        repository_resolver::RepositoryResolver,
        test_utils::{
            FSRegistryTestCase, RegistryTestCase, create_test_registry, create_test_repositories,
            for_each_backend, put_blob_direct, response_digest, response_header,
            response_session_id,
        },
    };

    /// Which storage operation the failing hook turns into a hard error.
    /// Everything else delegates to the inner backend untouched.
    #[derive(Clone, Copy)]
    enum FailOp {
        /// Fail the best-effort container sweep at the end of promotion.
        DeletePrefix,
        /// Fail `complete_upload`: must never run on the existing-blob path.
        CompleteUpload,
        /// Fail `write_upload`: must never run on the monolithic existing-blob
        /// path.
        WriteUpload,
    }

    #[async_trait]
    impl StoreHook for FailOp {
        async fn before(&self, op: StoreOp<'_>) -> Result<(), StorageError> {
            let message = match (self, op) {
                (FailOp::DeletePrefix, StoreOp::DeletePrefix { .. }) => "delete_prefix failed",
                (FailOp::CompleteUpload, StoreOp::CompleteUpload { .. }) => {
                    "complete should not be called for existing blob data"
                }
                (FailOp::WriteUpload, StoreOp::WriteUpload { .. }) => {
                    "write should not be called for monolithic existing blob upload"
                }
                _ => return Ok(()),
            };
            Err(StorageError::Backend(message.to_string()))
        }
    }

    /// Rebuild `inner` with its object store wrapped so `fail` errors out,
    /// reusing the same upload backend.
    fn failing_blob_store(inner: &Arc<BlobStore>, fail: FailOp) -> Arc<BlobStore> {
        let failing = Arc::new(HookedStore::new(inner.object_store().clone(), fail));
        Arc::new(BlobStore::new(failing, None))
    }

    #[tokio::test]
    async fn test_start_upload() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"test upload content";

            let response = registry
                .start_upload(
                    None,
                    StartUploadRequest {
                        namespace: namespace.clone(),
                        digest_algorithm: None,
                        target: None,
                    },
                    Cursor::new(Vec::new()),
                )
                .await
                .unwrap();
            // A fresh session answers `202` with its location.
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            assert_eq!(
                *response_header(&response, &LOCATION),
                format!(
                    "/v2/{namespace}/blobs/uploads/{}",
                    response_session_id(&response)
                )
            );

            let digest = put_blob_direct(registry.metadata_store.store(), content).await;
            let response = registry
                .start_upload(
                    None,
                    StartUploadRequest {
                        namespace: namespace.clone(),
                        digest_algorithm: None,
                        target: Some(StartUploadTarget {
                            digest: digest.clone(),
                            content_length: None,
                        }),
                    },
                    Cursor::new(Vec::new()),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::ACCEPTED,
                "an unowned blob must start a new session"
            );

            registry
                .blob_ownership()
                .grant(namespace, &digest)
                .await
                .unwrap();

            let response = registry
                .start_upload(
                    None,
                    StartUploadRequest {
                        namespace: namespace.clone(),
                        digest_algorithm: None,
                        target: Some(StartUploadTarget {
                            digest: digest.clone(),
                            content_length: None,
                        }),
                    },
                    Cursor::new(Vec::new()),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
            assert_eq!(response_digest(&response), digest);
            assert_eq!(
                *response_header(&response, &LOCATION),
                format!("/v2/{namespace}/blobs/{digest}")
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_mount_blob_grants_and_returns_existing() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let source = &Namespace::new("test-repo/source").unwrap();
            let target = &Namespace::new("test-repo/target").unwrap();
            let content = b"cross-repo mountable blob";

            let digest = put_blob_direct(registry.metadata_store.store(), content).await;
            registry
                .blob_ownership()
                .grant(source, &digest)
                .await
                .unwrap();

            let mount = BlobMount {
                digest: digest.clone(),
                from: Some(source.clone()),
            };
            let response = registry
                .mount_blob(
                    None,
                    MountBlobRequest {
                        namespace: target.clone(),
                        mount,
                    },
                    Some(source.clone()),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::CREATED);
            assert_eq!(response_digest(&response), digest);
            assert_eq!(
                *response_header(&response, &LOCATION),
                format!("/v2/{target}/blobs/{digest}")
            );

            assert!(
                registry
                    .blob_ownership()
                    .can_read(target, &digest)
                    .await
                    .unwrap(),
                "mount must grant the target namespace a reference"
            );
        })
        .await;
    }

    // Mount event emission is covered by
    // `event_emission_tests::mount_emits_blob_push_event` and
    // `event_emission_tests::mount_fallback_still_emits_intent_event` (the
    // intent-first event stays even when the mount falls back to a session).

    #[tokio::test]
    async fn test_mount_blob_falls_back_when_source_lacks_blob() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let source = &Namespace::new("test-repo/source").unwrap();
            let target = &Namespace::new("test-repo/target").unwrap();
            let content = b"blob present but not owned by source";

            let digest = put_blob_direct(registry.metadata_store.store(), content).await;

            let mount = BlobMount {
                digest: digest.clone(),
                from: Some(source.clone()),
            };
            let response = registry
                .mount_blob(
                    None,
                    MountBlobRequest {
                        namespace: target.clone(),
                        mount,
                    },
                    Some(source.clone()),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::ACCEPTED,
                "Expected a fall-back session when the source does not own the blob"
            );
            assert_eq!(
                *response_header(&response, &LOCATION),
                format!(
                    "/v2/{}/blobs/uploads/{}",
                    target,
                    response_session_id(&response)
                )
            );

            assert!(
                !registry
                    .blob_ownership()
                    .can_read(target, &digest)
                    .await
                    .unwrap(),
                "a failed mount must not grant the target namespace a reference"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_mount_blob_falls_back_when_blob_absent() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let source = &Namespace::new("test-repo/source").unwrap();
            let target = &Namespace::new("test-repo/target").unwrap();

            let absent = Digest::from_str(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();
            let mount = BlobMount {
                digest: absent,
                from: Some(source.clone()),
            };
            let response = registry
                .mount_blob(
                    None,
                    MountBlobRequest {
                        namespace: target.clone(),
                        mount,
                    },
                    Some(source.clone()),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::ACCEPTED,
                "an absent blob must fall back to a normal upload session"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_mount_blob_automatic_grants_referenced_blob() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let owner = &Namespace::new("test-repo/owner").unwrap();
            let target = &Namespace::new("test-repo/target").unwrap();
            let content = b"automatically discoverable blob";

            let digest = put_blob_direct(registry.metadata_store.store(), content).await;
            registry
                .blob_ownership()
                .grant(owner, &digest)
                .await
                .unwrap();

            let mount = BlobMount {
                digest: digest.clone(),
                from: None,
            };
            let response = registry
                .mount_blob(
                    None,
                    MountBlobRequest {
                        namespace: target.clone(),
                        mount,
                    },
                    Some(owner.clone()),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::CREATED,
                "automatic discovery must mount a referenced blob"
            );
            assert_eq!(response_digest(&response), digest);
            assert!(
                registry
                    .blob_ownership()
                    .can_read(target, &digest)
                    .await
                    .unwrap(),
                "automatic mount must grant the target namespace a reference"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_mount_blob_automatic_falls_back_for_unreferenced_blob() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let target = &Namespace::new("test-repo/target").unwrap();
            let source = &Namespace::new("test-repo/source").unwrap();
            let content = b"orphan blob present but unreferenced";

            let digest = put_blob_direct(registry.metadata_store.store(), content).await;

            let mount = BlobMount {
                digest: digest.clone(),
                from: None,
            };
            let response = registry
                .mount_blob(
                    None,
                    MountBlobRequest {
                        namespace: target.clone(),
                        mount,
                    },
                    Some(source.clone()),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::ACCEPTED,
                "an unreferenced (orphan) blob must not be auto-mounted"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_mount_blob_grants_only_from_the_authorized_source() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let owner = &Namespace::new("test-repo/owner").unwrap();
            let authorized = &Namespace::new("test-repo/authorized").unwrap();
            let target = &Namespace::new("test-repo/target").unwrap();
            let content = b"held by owner, not by the authorized source";

            // Guards the authorize-then-grant TOCTOU: the grant is conditioned
            // on the authorized source, not on `owner`.
            let digest = put_blob_direct(registry.metadata_store.store(), content).await;
            registry
                .blob_ownership()
                .grant(owner, &digest)
                .await
                .unwrap();

            let mount = BlobMount {
                digest: digest.clone(),
                from: None,
            };
            let response = registry
                .mount_blob(
                    None,
                    MountBlobRequest {
                        namespace: target.clone(),
                        mount,
                    },
                    Some(authorized.clone()),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::ACCEPTED,
                "mount must fall back when the authorized source does not hold the blob"
            );
            assert!(
                !registry
                    .blob_ownership()
                    .can_read(target, &digest)
                    .await
                    .unwrap(),
                "target must not be granted a reference from an unauthorized source"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn mount_source_candidates_resolves_from_and_discovery() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let source = &Namespace::new("test-repo/source").unwrap();
            let other = &Namespace::new("test-repo/other").unwrap();
            let target = &Namespace::new("test-repo/target").unwrap();
            let content = b"candidate resolution blob";

            let digest = put_blob_direct(registry.metadata_store.store(), content).await;
            let ownership = registry.blob_ownership();
            ownership.grant(source, &digest).await.unwrap();
            ownership.grant(other, &digest).await.unwrap();

            let candidates = registry
                .mount_source_candidates(&BlobMount {
                    digest: digest.clone(),
                    from: Some(source.clone()),
                })
                .await
                .unwrap();
            assert_eq!(candidates, vec![source.clone()]);

            let candidates = registry
                .mount_source_candidates(&BlobMount {
                    digest: digest.clone(),
                    from: Some(target.clone()),
                })
                .await
                .unwrap();
            assert!(candidates.is_empty());

            // Lexicographic order guards the sort-before-truncate determinism.
            let candidates = registry
                .mount_source_candidates(&BlobMount {
                    digest: digest.clone(),
                    from: None,
                })
                .await
                .unwrap();
            assert_eq!(candidates, vec![other.clone(), source.clone()]);

            let absent = Digest::from_str(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();
            let candidates = registry
                .mount_source_candidates(&BlobMount {
                    digest: absent,
                    from: None,
                })
                .await
                .unwrap();
            assert!(candidates.is_empty());
        })
        .await;
    }

    #[tokio::test]
    async fn test_patch_upload() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"test patch content";
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            let stream = Cursor::new(content);
            let response = registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: None,
                        content_length: Some(content.len() as u64),
                    },
                    stream,
                )
                .await
                .unwrap();
            assert_eq!(
                *response_header(&response, &RANGE),
                format!("0-{}", content.len() as u64 - 1)
            );

            let additional_content = b" additional";
            let stream = Cursor::new(additional_content);
            let response = registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: Some(ByteWindow {
                            start: content.len() as u64,
                            end: None,
                        }),
                        content_length: Some(additional_content.len() as u64),
                    },
                    stream,
                )
                .await
                .unwrap();
            assert_eq!(
                *response_header(&response, &RANGE),
                format!("0-{}", content.len() + additional_content.len() - 1)
            );

            let summary = registry
                .blob_store
                .upload_summary(namespace, &session_id)
                .await
                .unwrap();
            assert_eq!(
                summary.size,
                (content.len() + additional_content.len()) as u64
            );
        })
        .await;
    }

    // A chunked request (`Transfer-Encoding: chunked`, no `Content-Length`) is
    // authorized with `content_length = None`: the body streams to EOF and the
    // blob is stored with the digest derived from the bytes actually read. This
    // is the `docker push` path.
    #[tokio::test]
    async fn patch_upload_without_content_length_streams_to_eof() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"chunked upload with no declared length";
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: None,
                        content_length: None,
                    },
                    Cursor::new(content),
                )
                .await
                .expect("a chunked PATCH (no Content-Length) must be accepted");

            let expected_digest = Digest::sha256_of_bytes(content);
            registry
                .complete_upload(
                    None,
                    CompleteUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        digest: expected_digest.clone(),
                        content_range: None,
                        content_length: None,
                    },
                    Cursor::new(Vec::new()),
                )
                .await
                .expect("completing a chunked upload must succeed");

            assert_eq!(
                registry.blob_store.read(&expected_digest).await.unwrap(),
                content
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_complete_upload() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"test complete content";
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            let stream = Cursor::new(content);
            registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: None,
                        content_length: Some(content.len() as u64),
                    },
                    stream,
                )
                .await
                .unwrap();

            let expected_digest = Digest::sha256_of_bytes(content);

            let empty_stream = Cursor::new(Vec::new());
            let response = registry
                .complete_upload(
                    None,
                    CompleteUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        digest: expected_digest.clone(),
                        content_range: None,
                        content_length: Some(0),
                    },
                    empty_stream,
                )
                .await
                .unwrap();

            assert_eq!(response_digest(&response), expected_digest);

            let stored_content = registry.blob_store.read(&expected_digest).await.unwrap();
            assert_eq!(stored_content, content);

            let blob_index = registry
                .metadata_store
                .read_blob_index(&expected_digest)
                .await
                .unwrap();
            let namespace_links = blob_index.namespace.get(namespace).unwrap();
            assert!(namespace_links.contains(&LinkKind::Blob(expected_digest.clone())));
        })
        .await;
    }

    #[tokio::test]
    async fn test_monolithic_complete_upload_without_prior_patch() {
        for_each_backend(async |test_case| {
            // The whole body arrives in the final PUT with no prior PATCH, so
            // completion takes the monolithic path that hashes only the target
            // algorithm; verify it produces the correct digest for both.
            for algorithm in [Algorithm::Sha256, Algorithm::Sha512] {
                let registry = test_case.registry();
                let namespace = &Namespace::new("test-repo").unwrap();
                let content = b"monolithic upload body";
                let session_id = UploadSessionId::generate();

                registry
                    .blob_store
                    .create_upload(namespace, &session_id, None)
                    .await
                    .unwrap();

                let expected_digest = Digest::from_bytes(algorithm, content);
                let response = registry
                    .complete_upload(
                        None,
                        CompleteUploadRequest {
                            namespace: namespace.clone(),
                            session_id: session_id.clone(),
                            digest: expected_digest.clone(),
                            content_range: None,
                            content_length: Some(content.len() as u64),
                        },
                        Cursor::new(content.to_vec()),
                    )
                    .await
                    .unwrap();

                assert_eq!(response_digest(&response), expected_digest);
                let stored = registry.blob_store.read(&expected_digest).await.unwrap();
                assert_eq!(stored, content);

                test_case.cleanup().await;
            }
        })
        .await;
    }

    /// The spec answers a PUT naming a session the registry does not hold with
    /// `BLOB_UPLOAD_UNKNOWN`, not a 201.
    #[tokio::test]
    async fn completing_an_unknown_session_is_rejected() {
        let test_case = FSRegistryTestCase::new();
        let registry = test_case.registry();
        let namespace = &Namespace::new("test-repo").unwrap();
        let content = b"body for a session that was never opened";
        let digest = Digest::sha256_of_bytes(content);

        let error = registry
            .complete_upload(
                None,
                CompleteUploadRequest {
                    namespace: namespace.clone(),
                    session_id: UploadSessionId::generate(),
                    digest: digest.clone(),
                    content_range: None,
                    content_length: Some(content.len() as u64),
                },
                Cursor::new(content.to_vec()),
            )
            .await
            .expect_err("a PUT naming an unknown session must not store the blob");

        assert!(matches!(error, Error::BlobUploadUnknown), "got {error:?}");
        assert!(
            registry.blob_store.read(&digest).await.is_err(),
            "the rejected PUT must not have stored the blob"
        );
    }

    /// The one case it still succeeds: a retry of a PUT whose 201 was lost.
    #[tokio::test]
    async fn completing_an_unknown_session_succeeds_once_the_blob_exists() {
        let test_case = FSRegistryTestCase::new();
        let registry = test_case.registry();
        let namespace = &Namespace::new("test-repo").unwrap();
        let content = b"body whose 201 never reached the client";
        let digest = put_blob_direct(test_case.metadata_store().store(), content).await;

        let response = registry
            .complete_upload(
                None,
                CompleteUploadRequest {
                    namespace: namespace.clone(),
                    session_id: UploadSessionId::generate(),
                    digest: digest.clone(),
                    content_range: None,
                    content_length: Some(content.len() as u64),
                },
                Cursor::new(content.to_vec()),
            )
            .await
            .expect("retrying a completed PUT must stay idempotent");

        assert_eq!(response_digest(&response), digest);
    }

    #[tokio::test]
    async fn test_sha512_patch_then_complete_upload_lifecycle() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let full_content = b"sha512 upload driven through PATCH then PUT";
            let (first_chunk, second_chunk) = full_content.split_at(20);
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: None,
                        content_length: Some(first_chunk.len() as u64),
                    },
                    Cursor::new(first_chunk.to_vec()),
                )
                .await
                .unwrap();
            registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: Some(ByteWindow {
                            start: first_chunk.len() as u64,
                            end: None,
                        }),
                        content_length: Some(second_chunk.len() as u64),
                    },
                    Cursor::new(second_chunk.to_vec()),
                )
                .await
                .unwrap();

            let expected_digest = Digest::from_bytes(Algorithm::Sha512, full_content);
            let response = registry
                .complete_upload(
                    None,
                    CompleteUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        digest: expected_digest.clone(),
                        content_range: None,
                        content_length: Some(0),
                    },
                    Cursor::new(Vec::new()),
                )
                .await
                .unwrap();

            assert_eq!(response_digest(&response), expected_digest);
            assert_eq!(expected_digest.algorithm(), Algorithm::Sha512);
            assert_eq!(
                registry.blob_store.read(&expected_digest).await.unwrap(),
                full_content
            );
        })
        .await;
    }

    /// A chunk declaring its last byte must carry exactly that many: a body
    /// shorter or longer than the window it announced is refused rather than
    /// committed as whatever arrived.
    #[tokio::test]
    async fn a_chunk_shorter_than_its_content_range_is_refused() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"ten bytes!";
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            let result = registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        // Declares 0-99 while carrying ten bytes.
                        content_range: Some(ByteWindow {
                            start: 0,
                            end: Some(99),
                        }),
                        content_length: None,
                    },
                    Cursor::new(content.to_vec()),
                )
                .await;

            assert!(
                matches!(result, Err(Error::RangeNotSatisfiable)),
                "a chunk that undershoots its window must be refused, got {result:?}"
            );
            assert!(
                registry
                    .blob_store
                    .upload_summary(namespace, &session_id)
                    .await
                    .is_err(),
                "a chunked chunk refused after its write must reclaim the session"
            );
        })
        .await;
    }

    /// A declared length disagreeing with the window is refused before anything
    /// is written, so the session keeps standing where it stood.
    #[tokio::test]
    async fn a_known_length_contradicting_its_content_range_keeps_the_session() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let committed = b"first chunk";
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();
            registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: None,
                        content_length: Some(committed.len() as u64),
                    },
                    Cursor::new(committed.to_vec()),
                )
                .await
                .unwrap();

            let offset = committed.len() as u64;
            let result = registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        // Declares a hundred bytes while announcing ten.
                        content_range: Some(ByteWindow {
                            start: offset,
                            end: Some(offset + 99),
                        }),
                        content_length: Some(10),
                    },
                    Cursor::new(b"ten bytes!".to_vec()),
                )
                .await;

            assert!(
                matches!(result, Err(Error::RangeNotSatisfiable)),
                "a declared length outside its window must be refused, got {result:?}"
            );
            let summary = registry
                .blob_store
                .upload_summary(namespace, &session_id)
                .await
                .expect("a chunk refused before its write must leave the session open");
            assert_eq!(
                summary.size, offset,
                "the refused chunk must not have been committed"
            );
        })
        .await;
    }

    /// The declared window and the bytes agreeing is the ordinary case, and
    /// still commits.
    #[tokio::test]
    async fn a_chunk_matching_its_content_range_is_committed() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"ten bytes!";
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            let response = registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: Some(ByteWindow {
                            start: 0,
                            end: Some(content.len() as u64 - 1),
                        }),
                        content_length: Some(content.len() as u64),
                    },
                    Cursor::new(content.to_vec()),
                )
                .await
                .expect("a chunk matching its window must commit");

            assert_eq!(response.status(), StatusCode::ACCEPTED);
        })
        .await;
    }

    /// The empty blob is pushed in one request like any other: a declared zero
    /// is the whole body, not an absent one.
    #[tokio::test]
    async fn single_post_upload_stores_the_empty_blob() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let digest = Digest::sha256_of_bytes(b"");

            let response = registry
                .start_upload(
                    None,
                    StartUploadRequest {
                        namespace: namespace.clone(),
                        digest_algorithm: None,
                        target: Some(StartUploadTarget {
                            digest: digest.clone(),
                            content_length: Some(0),
                        }),
                    },
                    Cursor::new(Vec::new()),
                )
                .await
                .expect("an empty single-POST body must close the upload");

            assert_eq!(response.status(), StatusCode::CREATED);
            assert!(registry.blob_store.read(&digest).await.unwrap().is_empty());
        })
        .await;
    }

    /// A `?digest=` POST carrying the blob completes in that one request, so the
    /// client never sends the bytes twice.
    #[tokio::test]
    async fn single_post_upload_completes_in_one_request() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"blob pushed in a single POST";
            let digest = Digest::sha256_of_bytes(content);

            let response = registry
                .start_upload(
                    None,
                    StartUploadRequest {
                        namespace: namespace.clone(),
                        digest_algorithm: None,
                        target: Some(StartUploadTarget {
                            digest: digest.clone(),
                            content_length: Some(content.len() as u64),
                        }),
                    },
                    Cursor::new(content.to_vec()),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::CREATED);
            assert_eq!(
                *response_header(&response, &LOCATION),
                format!("/v2/{namespace}/blobs/{digest}")
            );
            assert_eq!(registry.blob_store.read(&digest).await.unwrap(), content);
        })
        .await;
    }

    /// A single-POST body that does not hash to the digest it claims is refused,
    /// like the same body closing a session.
    #[tokio::test]
    async fn single_post_upload_rejects_a_mismatched_digest() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"body that will not match";
            let claimed = Digest::sha256_of_bytes(b"something else entirely");

            let result = registry
                .start_upload(
                    None,
                    StartUploadRequest {
                        namespace: namespace.clone(),
                        digest_algorithm: None,
                        target: Some(StartUploadTarget {
                            digest: claimed.clone(),
                            content_length: Some(content.len() as u64),
                        }),
                    },
                    Cursor::new(content.to_vec()),
                )
                .await;

            assert!(
                matches!(result, Err(Error::DigestInvalid)),
                "a body that hashes to something else must be refused, got {result:?}"
            );
            assert!(registry.blob_store.read(&claimed).await.is_err());
        })
        .await;
    }

    /// The `?digest-algorithm=` hint makes a chunked session hash under that one
    /// algorithm alone, which the closing PUT must still be able to finalize.
    #[tokio::test]
    async fn hinted_algorithm_completes_a_chunked_upload() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"chunked upload hinted as sha512";
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, Some(Algorithm::Sha512))
                .await
                .unwrap();
            registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: None,
                        content_length: Some(content.len() as u64),
                    },
                    Cursor::new(content.to_vec()),
                )
                .await
                .unwrap();

            let expected_digest = Digest::from_bytes(Algorithm::Sha512, content);
            let response = registry
                .complete_upload(
                    None,
                    CompleteUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        digest: expected_digest.clone(),
                        content_range: None,
                        content_length: Some(0),
                    },
                    Cursor::new(Vec::new()),
                )
                .await
                .unwrap();

            assert_eq!(response_digest(&response), expected_digest);
        })
        .await;
    }

    /// Closing a hinted session under a different algorithm is refused: the
    /// session never hashed the one the client finally asked for.
    #[tokio::test]
    async fn a_digest_outside_the_hinted_algorithm_is_refused() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"chunked upload hinted as sha512";
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, Some(Algorithm::Sha512))
                .await
                .unwrap();
            registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: None,
                        content_length: Some(content.len() as u64),
                    },
                    Cursor::new(content.to_vec()),
                )
                .await
                .unwrap();

            let result = registry
                .complete_upload(
                    None,
                    CompleteUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        digest: Digest::sha256_of_bytes(content),
                        content_range: None,
                        content_length: Some(0),
                    },
                    Cursor::new(Vec::new()),
                )
                .await;

            assert!(
                matches!(result, Err(Error::DigestInvalid)),
                "a digest the session never hashed must be refused, got {result:?}"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_sha512_complete_upload_wrong_digest_rejected() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let full_content = b"sha512 body that will not match the claimed digest";
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: None,
                        content_length: Some(full_content.len() as u64),
                    },
                    Cursor::new(full_content.to_vec()),
                )
                .await
                .unwrap();

            let wrong_digest = Digest::from_bytes(Algorithm::Sha512, b"different content");
            let result = registry
                .complete_upload(
                    None,
                    CompleteUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        digest: wrong_digest.clone(),
                        content_range: None,
                        content_length: Some(0),
                    },
                    Cursor::new(Vec::new()),
                )
                .await;

            assert!(matches!(result, Err(Error::DigestInvalid)));
        })
        .await;
    }

    #[tokio::test]
    async fn test_complete_upload_succeeds_when_container_sweep_fails() {
        let test_case = FSRegistryTestCase::new();
        let registry = create_test_registry(
            failing_blob_store(
                &RegistryTestCase::blob_store(&test_case),
                FailOp::DeletePrefix,
            ),
            test_case.metadata_store(),
        );
        let namespace = &Namespace::new("test-repo").unwrap();
        let content = b"test complete content despite cleanup failure";
        let session_id = UploadSessionId::generate();

        registry
            .blob_store
            .create_upload(namespace, &session_id, None)
            .await
            .unwrap();

        registry
            .patch_upload(
                PatchUploadRequest {
                    namespace: namespace.clone(),
                    session_id: session_id.clone(),
                    content_range: None,
                    content_length: Some(content.len() as u64),
                },
                Cursor::new(content),
            )
            .await
            .unwrap();

        let expected_digest = Digest::sha256_of_bytes(content);
        let response = registry
            .complete_upload(
                None,
                CompleteUploadRequest {
                    namespace: namespace.clone(),
                    session_id: session_id.clone(),
                    digest: expected_digest.clone(),
                    content_range: None,
                    content_length: Some(0),
                },
                Cursor::new(Vec::new()),
            )
            .await
            .unwrap();

        assert_eq!(response_digest(&response), expected_digest);
        assert_eq!(
            registry.blob_store.read(&expected_digest).await.unwrap(),
            content
        );
    }

    #[tokio::test]
    async fn test_complete_upload_reuses_existing_blob_data() {
        let test_case = FSRegistryTestCase::new();
        let registry = create_test_registry(
            failing_blob_store(
                &RegistryTestCase::blob_store(&test_case),
                FailOp::CompleteUpload,
            ),
            test_case.metadata_store(),
        );
        let first_namespace = &Namespace::new("test-repo/first").unwrap();
        let second_namespace = &Namespace::new("test-repo/second").unwrap();
        let content = b"shared upload content";
        let digest = put_blob_direct(registry.metadata_store.store(), content).await;

        registry
            .blob_ownership()
            .grant(first_namespace, &digest)
            .await
            .unwrap();

        let session_id = UploadSessionId::generate();
        registry
            .blob_store
            .create_upload(second_namespace, &session_id, None)
            .await
            .unwrap();
        registry
            .patch_upload(
                PatchUploadRequest {
                    namespace: second_namespace.clone(),
                    session_id: session_id.clone(),
                    content_range: None,
                    content_length: Some(content.len() as u64),
                },
                Cursor::new(content),
            )
            .await
            .unwrap();

        registry
            .complete_upload(
                None,
                CompleteUploadRequest {
                    namespace: second_namespace.clone(),
                    session_id: session_id.clone(),
                    digest: digest.clone(),
                    content_range: None,
                    content_length: Some(0),
                },
                Cursor::new(Vec::new()),
            )
            .await
            .unwrap();

        assert_eq!(registry.blob_store.read(&digest).await.unwrap(), content);
        assert!(
            registry
                .blob_ownership()
                .can_read(second_namespace, &digest)
                .await
                .unwrap()
        );
        assert!(
            registry
                .blob_store
                .upload_summary(second_namespace, &session_id)
                .await
                .is_err()
        );

        test_case.cleanup().await;
    }

    #[tokio::test]
    async fn test_complete_upload_hashes_existing_blob_without_upload_storage_write() {
        let test_case = FSRegistryTestCase::new();
        let registry = create_test_registry(
            failing_blob_store(
                &RegistryTestCase::blob_store(&test_case),
                FailOp::WriteUpload,
            ),
            test_case.metadata_store(),
        );
        let first_namespace = &Namespace::new("test-repo/first").unwrap();
        let second_namespace = &Namespace::new("test-repo/second").unwrap();
        let content = b"shared monolithic upload content";
        let digest = put_blob_direct(registry.metadata_store.store(), content).await;

        registry
            .blob_ownership()
            .grant(first_namespace, &digest)
            .await
            .unwrap();

        let session_id = UploadSessionId::generate();
        registry
            .blob_store
            .create_upload(second_namespace, &session_id, None)
            .await
            .unwrap();

        registry
            .complete_upload(
                None,
                CompleteUploadRequest {
                    namespace: second_namespace.clone(),
                    session_id: session_id.clone(),
                    digest: digest.clone(),
                    content_range: None,
                    content_length: Some(content.len() as u64),
                },
                Cursor::new(content),
            )
            .await
            .unwrap();

        assert!(
            registry
                .blob_ownership()
                .can_read(second_namespace, &digest)
                .await
                .unwrap()
        );
        assert!(
            registry
                .blob_store
                .upload_summary(second_namespace, &session_id)
                .await
                .is_err()
        );

        test_case.cleanup().await;
    }

    #[tokio::test]
    async fn test_delete_upload() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            assert!(
                registry
                    .blob_store
                    .upload_summary(namespace, &session_id)
                    .await
                    .is_ok()
            );

            registry
                .delete_upload(DeleteUploadRequest {
                    namespace: namespace.clone(),
                    session_id: session_id.clone(),
                })
                .await
                .unwrap();

            assert!(
                registry
                    .blob_store
                    .upload_summary(namespace, &session_id)
                    .await
                    .is_err()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_upload_status() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"test range content";
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            let response = registry
                .get_upload_status(GetUploadRequest {
                    namespace: namespace.clone(),
                    session_id: session_id.clone(),
                })
                .await
                .unwrap();
            assert_eq!(*response_header(&response, &RANGE), "0-0");

            let stream = Cursor::new(content);
            registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: None,
                        content_length: Some(content.len() as u64),
                    },
                    stream,
                )
                .await
                .unwrap();

            let response = registry
                .get_upload_status(GetUploadRequest {
                    namespace: namespace.clone(),
                    session_id: session_id.clone(),
                })
                .await
                .unwrap();
            assert_eq!(
                *response_header(&response, &RANGE),
                format!("0-{}", content.len() as u64 - 1)
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_patch_upload_offset_validation_still_works() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            let stream = Cursor::new(b"some data".to_vec());
            registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: None,
                        content_length: Some(9),
                    },
                    stream,
                )
                .await
                .unwrap();

            let stream = Cursor::new(b"more data".to_vec());
            let result = registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: Some(ByteWindow {
                            start: 0,
                            end: None,
                        }),
                        content_length: Some(9),
                    },
                    stream,
                )
                .await;

            assert!(matches!(result, Err(Error::RangeNotSatisfiable)));
        })
        .await;
    }

    #[tokio::test]
    async fn test_complete_upload_digest_mismatch_still_rejected() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let session_id = UploadSessionId::generate();

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            let stream = Cursor::new(b"test content".to_vec());
            registry
                .patch_upload(
                    PatchUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        content_range: None,
                        content_length: Some(12),
                    },
                    stream,
                )
                .await
                .unwrap();

            let wrong_digest = Digest::from_str(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();

            let empty_stream = Cursor::new(Vec::new());
            let result = registry
                .complete_upload(
                    None,
                    CompleteUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        digest: wrong_digest.clone(),
                        content_range: None,
                        content_length: Some(0),
                    },
                    empty_stream,
                )
                .await;

            assert!(matches!(result, Err(Error::DigestInvalid)));
            assert!(
                registry
                    .blob_store
                    .upload_summary(namespace, &session_id)
                    .await
                    .is_err(),
                "a completion whose bytes hash to the wrong digest must abort its session"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_complete_upload_existing_blob_rejects_oversized_body() {
        for_each_backend(async |test_case| {
            // A re-PUT of an already-present blob whose body exceeds its declared
            // length is rejected on size, as soon as the surplus byte is read.
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = vec![b'x'; 100];
            let digest = put_blob_direct(registry.metadata_store.store(), &content).await;

            let session_id = UploadSessionId::generate();
            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            // Declare far fewer bytes than the body actually carries.
            let result = registry
                .complete_upload(
                    None,
                    CompleteUploadRequest {
                        namespace: namespace.clone(),
                        session_id: session_id.clone(),
                        digest: digest.clone(),
                        content_range: None,
                        content_length: Some(10),
                    },
                    Cursor::new(content),
                )
                .await;

            assert!(matches!(result, Err(Error::RangeNotSatisfiable)));
        })
        .await;
    }

    #[tokio::test]
    async fn test_write_upload_returns_digest_and_size() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let session_id = UploadSessionId::generate();
            let content = b"hello world upload";

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            let stream: Box<dyn tokio::io::AsyncRead + Unpin + Send + Sync> =
                Box::new(Cursor::new(content.to_vec()));
            let (digest, size) = registry
                .blob_store
                .write_upload(
                    namespace,
                    &session_id,
                    stream,
                    Some(content.len() as u64),
                    Algorithm::Sha256,
                )
                .await
                .unwrap();

            assert_eq!(size, content.len() as u64);
            assert_eq!(digest, Digest::sha256_of_bytes(content));

            let summary = registry
                .blob_store
                .upload_summary(namespace, &session_id)
                .await
                .unwrap();

            assert_eq!(size, summary.size);
        })
        .await;
    }

    #[tokio::test]
    async fn test_upload_summary_size_accumulates() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let session_id = UploadSessionId::generate();
            let content = b"size check content";

            registry
                .blob_store
                .create_upload(namespace, &session_id, None)
                .await
                .unwrap();

            let summary = registry
                .blob_store
                .upload_summary(namespace, &session_id)
                .await
                .unwrap();
            assert_eq!(summary.size, 0);

            let stream: Box<dyn tokio::io::AsyncRead + Unpin + Send + Sync> =
                Box::new(Cursor::new(content.to_vec()));
            registry
                .blob_store
                .write_upload(
                    namespace,
                    &session_id,
                    stream,
                    Some(content.len() as u64),
                    Algorithm::Sha256,
                )
                .await
                .unwrap();

            let summary = registry
                .blob_store
                .upload_summary(namespace, &session_id)
                .await
                .unwrap();
            assert_eq!(summary.size, content.len() as u64);
        })
        .await;
    }

    #[tokio::test]
    async fn test_complete_upload_with_corrupted_hash_state_returns_error() {
        let test_case = FSRegistryTestCase::new();
        let registry = test_case.registry();
        let namespace = &Namespace::new("test-repo").unwrap();
        let content = b"test content that should not be lost";
        let session_id = UploadSessionId::generate();

        registry
            .blob_store
            .create_upload(namespace, &session_id, None)
            .await
            .unwrap();

        let stream = Cursor::new(content);
        registry
            .patch_upload(
                PatchUploadRequest {
                    namespace: namespace.clone(),
                    session_id: session_id.clone(),
                    content_range: None,
                    content_length: Some(content.len() as u64),
                },
                stream,
            )
            .await
            .unwrap();

        let summary = registry
            .blob_store
            .upload_summary(namespace, &session_id)
            .await
            .unwrap();

        assert_eq!(summary.size, content.len() as u64);

        // Corrupt every `hashstates/<offset>` checkpoint so that
        // `complete_upload` cannot reconstruct the final digest from the
        // persisted hasher state.
        let hashstates_dir =
            test_case
                .temp_dir()
                .path()
                .join(path_builder::upload_hash_context_dir(
                    namespace,
                    &session_id,
                ));
        for entry in std::fs::read_dir(&hashstates_dir).unwrap() {
            let checkpoint = entry.unwrap().path();
            std::fs::write(&checkpoint, b"not-a-valid-hasher-state").unwrap();
        }

        let empty_stream = Cursor::new(Vec::new());
        let result = registry
            .complete_upload(
                None,
                CompleteUploadRequest {
                    namespace: namespace.clone(),
                    session_id: session_id.clone(),
                    digest: Digest::sha256_of_bytes(content),
                    content_range: None,
                    content_length: Some(0),
                },
                empty_stream,
            )
            .await;

        assert!(
            result.is_err(),
            "complete_upload should return error when hash state is corrupted"
        );

        let upload_path = path_builder::upload_path(namespace, &session_id);
        let upload_file_path = test_case.temp_dir().path().join(&upload_path);
        assert!(
            upload_file_path.exists(),
            "upload data should NOT be deleted when hash state is corrupted"
        );

        let preserved_content = std::fs::read(&upload_file_path).unwrap();
        assert_eq!(
            preserved_content, content,
            "original upload content should be preserved"
        );
    }

    /// Build a registry over an `FSRegistryTestCase`'s stores but with a tiny
    /// `max_blob_size_bytes`, so the blob-size cap can be exercised end-to-end.
    fn tiny_blob_cap_registry(
        test_case: &FSRegistryTestCase,
        max_blob_size_bytes: u64,
    ) -> Arc<Registry> {
        let resolver = Arc::new(
            RepositoryResolver::new(create_test_repositories())
                .expect("test repositories must not have overlapping prefixes"),
        );
        let config = RegistryConfig {
            max_blob_size_bytes,
            ..RegistryConfig::default()
        };
        Registry::new(
            test_case.blob_store(),
            test_case.metadata_store(),
            resolver,
            config,
        )
    }

    #[tokio::test]
    async fn patch_upload_known_length_over_cap_is_rejected_and_aborts_session() {
        let test_case = FSRegistryTestCase::new();
        let registry = tiny_blob_cap_registry(&test_case, 8);
        let namespace = &Namespace::new("test-repo").unwrap();
        let session_id = UploadSessionId::generate();

        registry
            .blob_store
            .create_upload(namespace, &session_id, None)
            .await
            .unwrap();

        let content = b"way past the eight byte cap";
        let result = registry
            .patch_upload(
                PatchUploadRequest {
                    namespace: namespace.clone(),
                    session_id: session_id.clone(),
                    content_range: None,
                    content_length: Some(content.len() as u64),
                },
                Cursor::new(content.to_vec()),
            )
            .await;

        assert!(
            matches!(result, Err(Error::BlobBodyTooLarge { limit: 8 })),
            "a known-length body over the cap must be rejected with BlobBodyTooLarge"
        );
        assert!(
            registry
                .blob_store
                .upload_summary(namespace, &session_id)
                .await
                .is_err(),
            "the oversized upload session must be aborted, not committed"
        );
    }

    #[tokio::test]
    async fn patch_upload_chunked_over_cap_is_rejected_and_aborts_session() {
        let test_case = FSRegistryTestCase::new();
        let registry = tiny_blob_cap_registry(&test_case, 8);
        let namespace = &Namespace::new("test-repo").unwrap();
        let session_id = UploadSessionId::generate();

        registry
            .blob_store
            .create_upload(namespace, &session_id, None)
            .await
            .unwrap();

        // No Content-Length (chunked): the body must be bounded mid-stream and
        // the overflow detected after the write.
        let content = b"way past the eight byte cap";
        let result = registry
            .patch_upload(
                PatchUploadRequest {
                    namespace: namespace.clone(),
                    session_id: session_id.clone(),
                    content_range: None,
                    content_length: None,
                },
                Cursor::new(content.to_vec()),
            )
            .await;

        assert!(
            matches!(result, Err(Error::BlobBodyTooLarge { limit: 8 })),
            "a chunked body over the cap must be rejected with BlobBodyTooLarge"
        );
        assert!(
            registry
                .blob_store
                .upload_summary(namespace, &session_id)
                .await
                .is_err(),
            "the oversized chunked upload session must be aborted, not committed"
        );
    }

    #[tokio::test]
    async fn complete_upload_chunked_over_cap_is_rejected_and_aborts_session() {
        let test_case = FSRegistryTestCase::new();
        let registry = tiny_blob_cap_registry(&test_case, 8);
        let namespace = &Namespace::new("test-repo").unwrap();
        let session_id = UploadSessionId::generate();

        registry
            .blob_store
            .create_upload(namespace, &session_id, None)
            .await
            .unwrap();

        // A single chunked PUT carrying the whole body must also be bounded.
        let content = b"single chunked PUT over the cap";
        let digest = Digest::sha256_of_bytes(content);
        let result = registry
            .complete_upload(
                None,
                CompleteUploadRequest {
                    namespace: namespace.clone(),
                    session_id: session_id.clone(),
                    digest: digest.clone(),
                    content_range: None,
                    content_length: None,
                },
                Cursor::new(content.to_vec()),
            )
            .await;

        assert!(
            matches!(result, Err(Error::BlobBodyTooLarge { limit: 8 })),
            "a chunked PUT over the cap must be rejected with BlobBodyTooLarge"
        );
        assert!(
            registry
                .blob_store
                .upload_summary(namespace, &session_id)
                .await
                .is_err(),
            "the oversized chunked PUT session must be aborted, not committed"
        );
    }

    #[tokio::test]
    async fn patch_upload_at_cap_is_accepted() {
        let test_case = FSRegistryTestCase::new();
        let registry = tiny_blob_cap_registry(&test_case, 8);
        let namespace = &Namespace::new("test-repo").unwrap();
        let session_id = UploadSessionId::generate();

        registry
            .blob_store
            .create_upload(namespace, &session_id, None)
            .await
            .unwrap();

        // Exactly at the cap, via both the known-length and chunked paths.
        registry
            .patch_upload(
                PatchUploadRequest {
                    namespace: namespace.clone(),
                    session_id: session_id.clone(),
                    content_range: None,
                    content_length: Some(4),
                },
                Cursor::new(b"abcd".to_vec()),
            )
            .await
            .expect("a body within the cap must be accepted");
        registry
            .patch_upload(
                PatchUploadRequest {
                    namespace: namespace.clone(),
                    session_id: session_id.clone(),
                    content_range: Some(ByteWindow {
                        start: 4,
                        end: None,
                    }),
                    content_length: None,
                },
                Cursor::new(b"efgh".to_vec()),
            )
            .await
            .expect("a chunked body that fills the cap exactly must be accepted");

        let summary = registry
            .blob_store
            .upload_summary(namespace, &session_id)
            .await
            .unwrap();
        assert_eq!(
            summary.size, 8,
            "cumulative size must reach the cap exactly"
        );
    }
}
