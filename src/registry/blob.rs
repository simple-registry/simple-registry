use std::collections::HashSet;

use hyper::{HeaderMap, Response, StatusCode};
use tokio::io::AsyncReadExt;
use tracing::{debug, info, instrument, warn};

use angos_oci::http_range::RequestRange;
use angos_oci::request::{DeleteBlobRequest, GetBlobRequest, HeadBlobRequest};
use angos_oci::server;
use angos_oci::{Digest, MediaRange, Namespace, UploadSessionId};

use crate::{
    cache_fill::build_envelope,
    event_webhook::event::{Event, EventActor},
    http_response::{ResponseBody, build_response},
    jobs::Queue,
    metrics_provider::metrics_provider,
    registry::{
        Error, Registry, Repository,
        blob_ownership::promote_and_grant,
        blob_store::{BlobStore, BoxedReader},
        metadata_store::{LinkKind, MetadataStore},
        repository_name,
    },
};

/// `200 OK` serving a blob in full, whether read locally or streamed from an
/// upstream.
fn whole_blob_response(
    digest: &Digest,
    total_length: u64,
    body: BoxedReader,
) -> Result<Response<ResponseBody>, Error> {
    Ok(build_response(
        StatusCode::OK,
        server::blob_headers(digest, total_length)?,
        ResponseBody::streaming(body),
    )?)
}

fn has_non_ownership_reference(links: &HashSet<LinkKind>, digest: &Digest) -> bool {
    links
        .iter()
        .any(|link| !matches!(link, LinkKind::Blob(link_digest) if link_digest == digest))
}

/// Cache a pull-through blob: stage and finalize its bytes through the blob
/// store, then grant `namespace` a reference through the metadata store.
///
/// Each write commits on its own store's executor, so the blob bytes and the
/// blob-index grant can live on separate backends without one being routed
/// through the other's executor. Byte presence is the dedup gate and the grant
/// is idempotent, so a retry after a partial fill re-grants without re-fetching;
/// a crash before the grant leaves the blob-data for scrub to reclaim.
pub async fn cache_blob(
    blob_store: &BlobStore,
    metadata_store: &MetadataStore,
    namespace: &Namespace,
    digest: &Digest,
    stream: BoxedReader,
    content_length: u64,
) -> Result<(), Error> {
    debug!("Fetching blob: {digest}");
    let session_id = UploadSessionId::generate();
    // The fill knows what it is fetching, so the session hashes that alone.
    blob_store
        .create_upload(namespace, &session_id, Some(digest.algorithm()))
        .await?;

    let result = fill_cache_session(
        blob_store,
        metadata_store,
        namespace,
        digest,
        stream,
        content_length,
        &session_id,
    )
    .await;

    // Reclaim the session whatever the outcome. A fill that fails partway
    // otherwise strands a layer-sized staging directory until scrub runs, and
    // repeated failures (a flaky upstream, a poisoning attempt) would fill the
    // disk. On success the bytes have been promoted and the session is spent;
    // so has a racer's session whose bytes this one found already promoted.
    if let Err(error) = blob_store.delete_upload(namespace, &session_id).await {
        warn!("Failed to delete cache-fill upload state: {error}");
    }
    result?;

    info!("Caching of {digest} completed");
    Ok(())
}

/// Stream the upstream bytes into the staged session and promote them. The
/// caller owns the session's lifetime and reclaims it on every outcome.
async fn fill_cache_session(
    blob_store: &BlobStore,
    metadata_store: &MetadataStore,
    namespace: &Namespace,
    digest: &Digest,
    stream: BoxedReader,
    content_length: u64,
    session_key: &UploadSessionId,
) -> Result<(), Error> {
    // A single-shot copy of a known blob: hash only the target algorithm.
    let (computed_digest, hashed_size) = blob_store
        .write_monolithic_upload(
            namespace,
            session_key,
            stream,
            Some(content_length),
            digest.algorithm(),
        )
        .await?;
    // Reject a pull-through blob whose bytes do not hash to the requested
    // digest: a compromised or man-in-the-middle upstream must not poison the
    // cache under a trusted digest. They are never promoted or granted, so no
    // client can read them.
    if &computed_digest != digest {
        warn!("Pull-through blob digest mismatch: expected {digest}, got {computed_digest}");
        return Err(Error::DigestInvalid);
    }
    // Promotion and grant share the coarse lock `delete_blob` holds while
    // reclaiming, mirroring the manifest path's bytes-then-link order.
    promote_and_grant(
        blob_store,
        metadata_store,
        namespace,
        session_key,
        digest,
        hashed_size,
    )
    .await
}

impl Registry {
    #[instrument]
    pub async fn head_blob(
        &self,
        request: HeadBlobRequest,
    ) -> Result<Response<ResponseBody>, Error> {
        let has_access = self
            .blob_ownership()
            .can_read(&request.namespace, &request.digest)
            .await?;
        // A namespace no `[repository]` entry matches has no upstream, so it
        // serves what it owns and nothing else.
        let upstream = self
            .get_repository_for_namespace(&request.namespace)
            .ok()
            .filter(|repository| repository.is_pull_through());

        if upstream.is_none() && !has_access {
            return Err(Error::BlobUnknown);
        }

        if has_access {
            match self.blob_store.size(&request.digest).await {
                Ok(size) => {
                    return Ok(build_response(
                        StatusCode::OK,
                        server::blob_headers(&request.digest, size)?,
                        ResponseBody::empty(),
                    )?);
                }
                // Mirror GET: a genuine miss on a pull-through repo re-heads
                // upstream; every other error (a transient or internal fault)
                // propagates instead of masquerading as a 404.
                Err(Error::BlobUnknown) if upstream.is_some() => {}
                Err(error) => return Err(error),
            }
        }

        let Some(repository) = upstream else {
            return Err(Error::BlobUnknown);
        };
        let (digest, size) = repository
            .head_blob(&request.accepted_types, &request.namespace, &request.digest)
            .await?;

        Ok(build_response(
            StatusCode::OK,
            server::blob_headers(&digest, size)?,
            ResponseBody::empty(),
        )?)
    }

    /// Serve the blob locally when `has_access`, else fall back to the
    /// pull-through upstream. `has_access` is the namespace's ownership
    /// verdict, resolved once by the caller so the hot GET path does not pay
    /// for the blob-index read twice.
    pub async fn get_blob_with_access(
        &self,
        repository: Option<&Repository>,
        accepted_types: &[MediaRange],
        namespace: &Namespace,
        digest: &Digest,
        range: Option<RequestRange>,
        has_access: bool,
    ) -> Result<Response<ResponseBody>, Error> {
        let upstream = repository.filter(|repository| repository.is_pull_through());

        if has_access {
            match self.get_local_blob(digest, range).await {
                Ok(response) => return Ok(response),
                // Owned but the bytes are gone: a pull-through repo re-fetches.
                Err(Error::BlobUnknown) if upstream.is_some() => {}
                Err(error) => return Err(error),
            }
        } else if upstream.is_none() {
            return Err(Error::BlobUnknown);
        }

        let Some(repository) = upstream else {
            return Err(Error::BlobUnknown);
        };
        let fetched = repository
            .get_blob(accepted_types, namespace, digest, range)
            .await?;

        self.dispatch_cache_fill(namespace, digest).await;

        // An upstream is free to ignore `Range` and answer the whole blob,
        // which stays a valid answer; only its `206` becomes partial content.
        let Some(content_range) = fetched.content_range else {
            return whole_blob_response(digest, fetched.length, fetched.reader);
        };

        Ok(build_response(
            StatusCode::PARTIAL_CONTENT,
            server::partial_blob_headers(digest, fetched.length, content_range)?,
            ResponseBody::streaming(fetched.reader),
        )?)
    }

    /// Fire-and-forget enqueue of a pull-through cache-fill job. A failure is
    /// logged and counted on `angos_job_queue_enqueue_failures_total` but never
    /// bubbles up, so a scheduling glitch cannot degrade the client response.
    async fn dispatch_cache_fill(&self, namespace: &Namespace, digest: &Digest) {
        let envelope = match build_envelope(namespace, digest) {
            Ok(envelope) => envelope,
            Err(e) => {
                warn!("Failed to build cache job envelope for {digest}: {e}");
                metrics_provider()
                    .job_queue_enqueue_failures_total
                    .with_label_values(&[Queue::Cache.as_str()])
                    .inc();
                return;
            }
        };
        if let Err(e) = self.job_queue.enqueue(envelope).await {
            warn!("Failed to enqueue cache job for {digest}: {e}");
            metrics_provider()
                .job_queue_enqueue_failures_total
                .with_label_values(&[Queue::Cache.as_str()])
                .inc();
        }
    }

    async fn get_local_blob(
        &self,
        digest: &Digest,
        range: Option<RequestRange>,
    ) -> Result<Response<ResponseBody>, Error> {
        let Some(requested_range) = range else {
            let (reader, total_length) = self.blob_store.reader(digest, None).await?;
            return whole_blob_response(digest, total_length, reader);
        };

        let total_length = self.blob_store.size(digest).await?;
        let Some(served) = requested_range.resolve(total_length)? else {
            let (reader, _) = self.blob_store.reader(digest, None).await?;
            return whole_blob_response(digest, total_length, reader);
        };
        let (reader, _) = self.blob_store.reader(digest, Some(served.start)).await?;
        let reader = Box::new(reader.take(served.length()));

        Ok(build_response(
            StatusCode::PARTIAL_CONTENT,
            server::partial_blob_headers(digest, served.length(), served)?,
            ResponseBody::streaming(reader),
        )?)
    }

    #[instrument]
    pub async fn delete_blob(
        &self,
        request: DeleteBlobRequest,
    ) -> Result<Response<ResponseBody>, Error> {
        let ownership = self.blob_ownership();
        let links = ownership
            .references(&request.namespace, &request.digest)
            .await?;

        if links.is_empty() {
            return Err(Error::BlobUnknown);
        }

        if has_non_ownership_reference(&links, &request.digest) {
            return Err(Error::BlobReferenced);
        }

        // Hold the coarse `blob-data:{digest}` lock across the revoke + reclaim.
        // The revoke transaction is crash-atomic on its own, but the lock is what
        // serialises it against the upload `grant` path (which records ownership
        // in the shard without a transactional coarse lock), so a concurrent
        // reference grant cannot be missed during the unreferenced check, and the
        // blob-store reclaim cannot race a concurrent push of the same digest.
        self.metadata_store
            .with_blob_data_lock(&request.digest, async {
                if self
                    .metadata_store
                    .revoke_blob_ownership(&request.namespace, &request.digest)
                    .await?
                {
                    self.blob_store.delete_blob(&request.digest).await?;
                }
                Ok::<_, Error>(())
            })
            .await?;

        Ok(build_response(
            StatusCode::ACCEPTED,
            HeaderMap::new(),
            ResponseBody::empty(),
        )?)
    }

    /// Resolves a blob GET request to either a presigned redirect URL or a
    /// stream, then emits a `blob.pull` event for the served digest.
    ///
    /// The redirect fast-path is only taken when `enable_blob_redirect` is set, the
    /// range is absent, and the blob is locally available (for pull-through repos).
    #[instrument(skip(self, request))]
    pub async fn resolve_get_blob(
        &self,
        actor: Option<EventActor>,
        request: GetBlobRequest,
    ) -> Result<Response<ResponseBody>, Error> {
        let repository = self.get_repository_for_namespace(&request.namespace).ok();

        let has_access = self
            .blob_ownership()
            .can_read(&request.namespace, &request.digest)
            .await?;

        if !repository.is_some_and(Repository::is_pull_through) && !has_access {
            return Err(Error::BlobUnknown);
        }

        let repository_name = repository_name(repository);
        let response = if request.range.is_none()
            && request.allow_redirect
            && self.enable_blob_redirect
            && has_access
            && self.blob_store.size(&request.digest).await.is_ok()
            && let Ok(Some(presigned_url)) =
                self.blob_store.presigned_url(&request.digest, None).await
        {
            build_response(
                StatusCode::TEMPORARY_REDIRECT,
                server::blob_redirect_headers(&presigned_url, &request.digest)?,
                ResponseBody::empty(),
            )?
        } else {
            self.get_blob_with_access(
                repository,
                &request.accepted_types,
                &request.namespace,
                &request.digest,
                request.range,
                has_access,
            )
            .await?
        };

        let event = Event::pull_blob(
            &request.namespace,
            &repository_name,
            &request.digest,
            actor.as_ref(),
        );
        self.dispatch_events(&[event]).await?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use hyper::header::{CONTENT_LENGTH, CONTENT_RANGE};

    use std::{io::Cursor, sync::Arc, time::Duration};

    use async_trait::async_trait;
    use tempfile::TempDir;
    use tokio::time::sleep;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use angos_oci::http_range::ByteWindow;
    use angos_oci::{Namespace, Tag};
    use angos_storage::{
        Error as StorageError, MemoryObjectStore, ObjectStore,
        fs::Backend as StorageFsBackend,
        test_util::{HookedStore, StoreHook, StoreOp},
    };

    use crate::metrics_provider::init_for_tests;
    use crate::registry::blob::*;
    use crate::{
        cache,
        registry::{
            manifest::DEFAULT_MAX_MANIFEST_SIZE_BYTES,
            metadata_store::{BlobIndexOperation, LinkOperation},
            path_builder,
            repository::Config,
            test_utils::{
                RegistryTestCase, create_test_blob, create_test_registry, for_each_backend,
                get_blob, metadata_store_over, put_blob_direct, response_body, response_digest,
                response_header,
            },
        },
        test_fixtures::client::test_client_config,
    };

    /// `delete_blob` must hold the `blob-data:{digest}` coarse lock across its
    /// revoke-and-reclaim transaction, so a concurrent reference grant cannot be
    /// missed while the unreferenced check and the blob-data delete are decided.
    /// Regression guard for the conformance `MANIFEST_BLOB_UNKNOWN` failure
    /// caused by dropping that lock during the transactional-engine migration.
    #[tokio::test]
    async fn delete_blob_waits_for_blob_data_lock_before_reclaiming_data() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let first = &Namespace::new("test-repo/first").unwrap();
            let second = &Namespace::new("test-repo/second").unwrap();
            let content = b"shared blob content";
            let digest = put_blob_direct(registry.metadata_store.store(), content).await;
            let ownership = registry.blob_ownership();

            ownership.grant(first, &digest).await.unwrap();

            // Hold the blob-data lock, then start a delete: it must block on
            // the lock rather than reclaim the bytes.
            let session = registry
                .metadata_store
                .acquire_blob_data_lock(&digest)
                .await
                .unwrap();
            let delete = registry.delete_blob(DeleteBlobRequest {
                namespace: first.clone(),
                digest: digest.clone(),
            });
            tokio::pin!(delete);

            tokio::select! {
                result = &mut delete => {
                    panic!("delete completed while blob-data lock was held: {result:?}");
                }
                () = sleep(Duration::from_millis(25)) => {}
            }

            // A second namespace grabs a reference while the delete is parked.
            ownership.grant(second, &digest).await.unwrap();
            session.release().await;
            delete.await.unwrap();

            // The data survives (still referenced by `second`); `first` lost its
            // reference, `second` keeps it.
            assert_eq!(registry.blob_store.read(&digest).await.unwrap(), content);
            assert!(!ownership.can_read(first, &digest).await.unwrap());
            assert!(ownership.can_read(second, &digest).await.unwrap());
        })
        .await;
    }

    #[tokio::test]
    async fn test_head_blob() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"test blob content";

            let (digest, _) = create_test_blob(registry, namespace, content).await;
            let response = registry
                .head_blob(HeadBlobRequest {
                    namespace: namespace.clone(),
                    digest: digest.clone(),
                    accepted_types: Vec::new(),
                })
                .await
                .unwrap();

            assert_eq!(response_digest(&response), digest);
            assert_eq!(
                *response_header(&response, &CONTENT_LENGTH),
                content.len().to_string()
            );
        })
        .await;
    }

    /// Fails the `head` of one key, modelling a transient backend fault on the
    /// blob-size probe while leaving every other operation intact.
    struct FailHeadOf {
        key: String,
    }

    #[async_trait]
    impl StoreHook for FailHeadOf {
        async fn before(&self, op: StoreOp<'_>) -> Result<(), StorageError> {
            match op {
                StoreOp::Head { key } if key == self.key => {
                    Err(StorageError::Backend("injected head failure".to_string()))
                }
                _ => Ok(()),
            }
        }
    }

    #[tokio::test]
    async fn head_blob_propagates_transient_error_instead_of_404() {
        let namespace = &Namespace::new("test-repo").unwrap();
        let digest = Digest::sha256_of_bytes(b"transient-head-blob");

        // The blob-size `head` fails transiently; the grant and repository reads
        // still succeed, so the request reaches the size probe with access.
        let inner: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
        let object: Arc<dyn ObjectStore> = Arc::new(HookedStore::new(
            inner,
            FailHeadOf {
                key: path_builder::blob_path(&digest),
            },
        ));
        let blob_store = Arc::new(BlobStore::new(object.clone(), None));
        let registry = create_test_registry(blob_store, metadata_store_over(object));

        registry
            .blob_ownership()
            .grant(namespace, &digest)
            .await
            .unwrap();

        // A transient fault must surface (500), not masquerade as a missing blob
        // (404) the way GET already avoids.
        let result = registry
            .head_blob(HeadBlobRequest {
                namespace: namespace.clone(),
                digest: digest.clone(),
                accepted_types: Vec::new(),
            })
            .await;
        assert!(
            matches!(result, Err(Error::Internal(_))),
            "a transient size() error must propagate, not map to BlobUnknown; got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_get_blob() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"test blob content";

            let (digest, repository) = create_test_blob(registry, namespace, content).await;
            let response = get_blob(registry, &repository, &[], namespace, &digest, None)
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response_digest(&response), digest);
            assert_eq!(
                *response_header(&response, &CONTENT_LENGTH),
                content.len().to_string()
            );
            assert_eq!(response_body(response).await, content);
        })
        .await;
    }

    #[tokio::test]
    async fn get_blob_rejects_local_blob_without_namespace_ownership() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"unowned blob content";
            let digest = put_blob_direct(registry.metadata_store.store(), content).await;
            let repository = registry.get_repository_for_namespace(namespace).unwrap();

            let head_result = registry
                .head_blob(HeadBlobRequest {
                    namespace: namespace.clone(),
                    digest: digest.clone(),
                    accepted_types: Vec::new(),
                })
                .await;
            assert!(matches!(head_result, Err(Error::BlobUnknown)));

            let get_result = get_blob(registry, repository, &[], namespace, &digest, None).await;
            assert!(matches!(get_result, Err(Error::BlobUnknown)));
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_blob_with_range() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"test blob content";

            let (digest, repository) = create_test_blob(registry, namespace, content).await;
            let range = Some(RequestRange::FromTo(ByteWindow {
                start: 5,
                end: Some(10),
            }));
            let response = get_blob(registry, &repository, &[], namespace, &digest, range)
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(response_digest(&response), digest);
            assert_eq!(
                *response_header(&response, &CONTENT_RANGE),
                format!("bytes 5-10/{}", content.len())
            );
            assert_eq!(*response_header(&response, &CONTENT_LENGTH), "6");
            assert_eq!(response_body(response).await, &content[5..=10]);
        })
        .await;
    }

    #[tokio::test]
    async fn test_delete_blob() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"test blob content";

            let digest = put_blob_direct(registry.metadata_store.store(), content).await;
            registry
                .blob_ownership()
                .grant(namespace, &digest)
                .await
                .unwrap();

            let blob_index = registry
                .metadata_store
                .read_blob_index(&digest)
                .await
                .unwrap();
            assert!(blob_index.namespace.contains_key(namespace));
            let namespace_links = blob_index.namespace.get(namespace).unwrap();
            assert!(namespace_links.contains(&LinkKind::Blob(digest.clone())));

            registry
                .delete_blob(DeleteBlobRequest {
                    namespace: namespace.clone(),
                    digest: digest.clone(),
                })
                .await
                .unwrap();

            assert!(registry.blob_store.read(&digest).await.is_err());
            assert!(
                registry
                    .metadata_store
                    .read_blob_index(&digest)
                    .await
                    .is_err()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn delete_blob_rejects_manifest_referenced_blob() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"referenced blob content";
            let digest = put_blob_direct(registry.metadata_store.store(), content).await;
            let link = LinkKind::Config(digest.clone());

            registry
                .metadata_store
                .update_links(
                    namespace,
                    &[LinkOperation::create_with_referrer(
                        link.clone(),
                        digest.clone(),
                        Digest::sha256_of_bytes(b"manifest"),
                    )],
                )
                .await
                .unwrap();

            let result = registry
                .delete_blob(DeleteBlobRequest {
                    namespace: namespace.clone(),
                    digest: digest.clone(),
                })
                .await;
            assert!(matches!(result, Err(Error::BlobReferenced)));

            let stored_content = registry.blob_store.read(&digest).await.unwrap();
            assert_eq!(stored_content, content);
            assert!(
                registry
                    .metadata_store
                    .read_link(namespace, &link)
                    .await
                    .is_ok()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn delete_blob_rejects_all_metadata_references() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let parent = Digest::sha256_of_bytes(b"index manifest");
            let subject = Digest::sha256_of_bytes(b"subject manifest");

            let cases = [
                LinkKind::Digest(Digest::sha256_of_bytes(b"digest reference")),
                LinkKind::Tag(Tag::new("latest").unwrap()),
                LinkKind::Layer(Digest::sha256_of_bytes(b"layer reference")),
                LinkKind::Config(Digest::sha256_of_bytes(b"config reference")),
                LinkKind::Manifest {
                    index: parent.clone(),
                    child: Digest::sha256_of_bytes(b"child manifest"),
                },
                LinkKind::Referrer {
                    subject,
                    referrer: Digest::sha256_of_bytes(b"referrer manifest"),
                },
            ];

            for link in cases {
                let content = format!("content for {link}").into_bytes();
                let digest = put_blob_direct(registry.metadata_store.store(), &content).await;
                registry
                    .blob_ownership()
                    .grant(namespace, &digest)
                    .await
                    .unwrap();

                let retargeted = retarget_link(&link, &digest);
                let op = if let LinkKind::Manifest {
                    index: parent,
                    child: _,
                } = &link
                {
                    LinkOperation::create_with_referrer(retargeted, digest.clone(), parent.clone())
                } else {
                    LinkOperation::create(retargeted, digest.clone())
                };
                registry
                    .metadata_store
                    .update_links(namespace, &[op])
                    .await
                    .unwrap();

                let result = registry
                    .delete_blob(DeleteBlobRequest {
                        namespace: namespace.clone(),
                        digest: digest.clone(),
                    })
                    .await;
                assert!(matches!(result, Err(Error::BlobReferenced)));
                assert_eq!(registry.blob_store.read(&digest).await.unwrap(), content);
            }
        })
        .await;
    }

    fn retarget_link(link: &LinkKind, digest: &Digest) -> LinkKind {
        match link {
            LinkKind::Digest(_) => LinkKind::Digest(digest.clone()),
            LinkKind::Layer(_) => LinkKind::Layer(digest.clone()),
            LinkKind::Config(_) => LinkKind::Config(digest.clone()),
            LinkKind::Manifest {
                index: parent,
                child: _,
            } => LinkKind::Manifest {
                index: parent.clone(),
                child: digest.clone(),
            },
            LinkKind::Referrer {
                subject,
                referrer: _,
            } => LinkKind::Referrer {
                subject: subject.clone(),
                referrer: digest.clone(),
            },
            LinkKind::Blob(_) | LinkKind::Tag(_) => link.clone(),
        }
    }

    #[tokio::test]
    async fn delete_blob_keeps_data_owned_by_other_namespace() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let first = &Namespace::new("test-repo/first").unwrap();
            let second = &Namespace::new("test-repo/second").unwrap();
            let content = b"shared blob content";
            let digest = put_blob_direct(registry.metadata_store.store(), content).await;
            let ownership = registry.blob_ownership();

            ownership.grant(first, &digest).await.unwrap();
            ownership.grant(second, &digest).await.unwrap();

            registry
                .delete_blob(DeleteBlobRequest {
                    namespace: first.clone(),
                    digest: digest.clone(),
                })
                .await
                .unwrap();

            assert_eq!(registry.blob_store.read(&digest).await.unwrap(), content);
            assert!(!ownership.can_read(first, &digest).await.unwrap());
            assert!(ownership.can_read(second, &digest).await.unwrap());

            registry
                .delete_blob(DeleteBlobRequest {
                    namespace: second.clone(),
                    digest: digest.clone(),
                })
                .await
                .unwrap();

            assert!(registry.blob_store.read(&digest).await.is_err());
        })
        .await;
    }

    #[tokio::test]
    async fn delete_blob_rejects_unowned_blob() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"unowned delete content";
            let digest = put_blob_direct(registry.metadata_store.store(), content).await;

            let result = registry
                .delete_blob(DeleteBlobRequest {
                    namespace: namespace.clone(),
                    digest: digest.clone(),
                })
                .await;
            assert!(matches!(result, Err(Error::BlobUnknown)));

            let stored_content = registry.blob_store.read(&digest).await.unwrap();
            assert_eq!(stored_content, content);
        })
        .await;
    }

    #[tokio::test]
    async fn cache_blob_updates_namespace_blob_index() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = Namespace::new("test-repo").unwrap();
            let content = b"cached pull-through blob content";
            let digest = Digest::sha256_of_bytes(content);
            let stream = Box::new(Cursor::new(content.to_vec()));

            cache_blob(
                &registry.blob_store,
                &registry.metadata_store,
                &namespace,
                &digest,
                stream,
                content.len() as u64,
            )
            .await
            .unwrap();

            let blob_index = registry
                .metadata_store
                .read_blob_index(&digest)
                .await
                .unwrap();
            let namespace_links = blob_index.namespace.get(&namespace).unwrap();
            assert!(namespace_links.contains(&LinkKind::Blob(digest.clone())));

            let repository = registry.get_repository_for_namespace(&namespace).unwrap();
            let response = get_blob(registry, repository, &[], &namespace, &digest, None)
                .await
                .unwrap();

            assert_eq!(response_body(response).await, content);
        })
        .await;
    }

    /// Regression: a range over a blob the cache does not hold yet is forwarded
    /// to the upstream and answered `206`. It used to be refused with `416`, so
    /// one URL answered differently depending on cache state.
    #[tokio::test]
    async fn ranged_get_of_an_uncached_pull_through_blob_serves_partial_content() {
        let content = b"pull-through ranged blob content";
        let digest = Digest::sha256_of_bytes(content);
        let content_range = format!("bytes 5-10/{}", content.len());

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/repo/blobs/{digest}")))
            .and(header("range", "bytes=5-10"))
            .respond_with(
                ResponseTemplate::new(206)
                    .insert_header("content-range", content_range.as_str())
                    .set_body_bytes(&content[5..=10]),
            )
            .mount(&mock_server)
            .await;

        let config = Config {
            upstream: vec![test_client_config(mock_server.uri())],
            ..Default::default()
        };
        let cache_backend = cache::Config::Memory.to_backend().unwrap();
        let repository = Repository::new(
            "local",
            &config,
            &cache_backend,
            DEFAULT_MAX_MANIFEST_SIZE_BYTES,
        )
        .await
        .unwrap();

        let object: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
        let registry = create_test_registry(
            Arc::new(BlobStore::new(object.clone(), None)),
            metadata_store_over(object),
        );
        let namespace = &Namespace::new("local/repo").unwrap();
        let range = Some(RequestRange::FromTo(ByteWindow {
            start: 5,
            end: Some(10),
        }));

        let response = registry
            .get_blob_with_access(Some(&repository), &[], namespace, &digest, range, false)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(*response_header(&response, &CONTENT_RANGE), content_range);
        assert_eq!(response_body(response).await, &content[5..=10]);
    }

    /// Upload-session directories still staged under `namespace`.
    async fn staged_session_count(
        test_case: &dyn RegistryTestCase,
        namespace: &Namespace,
    ) -> usize {
        test_case
            .blob_store()
            .object_store()
            .list_all_children(&path_builder::uploads_root_dir(namespace))
            .await
            .expect("list upload sessions")
            .sub_prefixes
            .len()
    }

    /// A reader that fails on its first poll, standing in for an upstream
    /// connection dropping mid-fill.
    struct FailingReader;

    impl tokio::io::AsyncRead for FailingReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::other("upstream dropped mid-fill")))
        }
    }

    /// Regression: a fill that fails partway must not strand its staged session.
    /// The bytes are layer-sized, so leaving them for scrub turns an ordinary
    /// upstream fault into disk pressure.
    #[tokio::test]
    async fn cache_blob_reclaims_its_session_when_the_fill_fails() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = Namespace::new("test-repo").unwrap();
            let digest = Digest::sha256_of_bytes(b"bytes that never arrive");

            let result = cache_blob(
                &registry.blob_store,
                &registry.metadata_store,
                &namespace,
                &digest,
                Box::new(FailingReader),
                64,
            )
            .await;

            assert!(result.is_err(), "a fill whose upstream drops must fail");
            assert_eq!(
                staged_session_count(test_case, &namespace).await,
                0,
                "a failed fill must not strand its staged upload session"
            );
        })
        .await;
    }

    /// Pull-through cache poisoning guard: an upstream serving bytes that do not
    /// hash to the requested digest must be rejected, and the poisoned bytes
    /// must never be cached under the trusted digest.
    #[tokio::test]
    async fn cache_blob_rejects_content_not_matching_requested_digest() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = Namespace::new("test-repo").unwrap();
            let poisoned = b"bytes an upstream served for the wrong digest";
            let requested = Digest::sha256_of_bytes(b"what the client actually asked for");

            let result = cache_blob(
                &registry.blob_store,
                &registry.metadata_store,
                &namespace,
                &requested,
                Box::new(Cursor::new(poisoned.to_vec())),
                poisoned.len() as u64,
            )
            .await;

            assert!(
                matches!(result, Err(Error::DigestInvalid)),
                "mismatched pull-through content must be rejected; got: {result:?}"
            );
            assert!(
                registry.blob_store.read(&requested).await.is_err(),
                "poisoned bytes must not be cached under the requested digest"
            );
            assert_eq!(
                staged_session_count(test_case, &namespace).await,
                0,
                "the rejected fill must not leave its staged bytes behind"
            );
        })
        .await;
    }

    /// Regression guard for the split-backend pull-through cache-fill failure:
    /// with the blob store and metadata store on separate backends, `cache_blob`
    /// must store the bytes in the blob store and grant the reference in the
    /// metadata store as independent idempotent work. The previous design folded
    /// both into one transaction and conflicted on every layer because the
    /// blob-index read was verified against the wrong backend.
    #[tokio::test]
    async fn cache_blob_grants_reference_with_split_blob_and_metadata_backends() {
        init_for_tests();
        let blob_dir = TempDir::new().unwrap();
        let meta_dir = TempDir::new().unwrap();

        let blob_obj: Arc<dyn ObjectStore> =
            Arc::new(StorageFsBackend::builder(blob_dir.path().to_str().unwrap()).build());
        let blob_store = Arc::new(BlobStore::new(blob_obj.clone(), None));

        let meta_obj: Arc<dyn ObjectStore> =
            Arc::new(StorageFsBackend::builder(meta_dir.path().to_str().unwrap()).build());
        let metadata_store = metadata_store_over(meta_obj);

        let namespace = Namespace::new("kubernetes.io/kube-apiserver").unwrap();
        let content = b"layer bytes";
        let digest = Digest::sha256_of_bytes(content);

        // A prior manifest pull recorded the layer's ownership link in the
        // metadata store, which is what made the old design conflict.
        metadata_store
            .update_blob_index(
                &namespace,
                &digest,
                BlobIndexOperation::Insert(LinkKind::Layer(digest.clone())),
            )
            .await
            .unwrap();

        cache_blob(
            &blob_store,
            &metadata_store,
            &namespace,
            &digest,
            Box::new(Cursor::new(content.to_vec())),
            content.len() as u64,
        )
        .await
        .unwrap();

        assert_eq!(
            blob_store.read(&digest).await.unwrap(),
            content,
            "the blob bytes must land in the blob store"
        );
        let blob_index = metadata_store.read_blob_index(&digest).await.unwrap();
        let links = blob_index.namespace.get(&namespace).unwrap();
        assert!(
            links.contains(&LinkKind::Blob(digest.clone())),
            "the namespace must hold a blob ownership reference after caching"
        );
    }

    #[tokio::test]
    async fn test_get_local_blob_returns_correct_size() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"regression test blob content";

            let (digest, _) = create_test_blob(registry, namespace, content).await;

            let response = registry.get_local_blob(&digest, None).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                *response_header(&response, &CONTENT_LENGTH),
                content.len().to_string()
            );
            assert_eq!(response_body(response).await, content);

            let range = Some(RequestRange::FromTo(ByteWindow {
                start: 5,
                end: Some(15),
            }));
            let response = registry.get_local_blob(&digest, range).await.unwrap();
            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                *response_header(&response, &CONTENT_RANGE),
                format!("bytes 5-15/{}", content.len())
            );
            assert_eq!(*response_header(&response, &CONTENT_LENGTH), "11");
            assert_eq!(response_body(response).await, &content[5..=15]);
        })
        .await;
    }

    #[tokio::test]
    async fn get_local_blob_open_ended_range_returns_partial_content() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"open ended range content";

            let (digest, _) = create_test_blob(registry, namespace, content).await;
            let response = registry
                .get_local_blob(
                    &digest,
                    Some(RequestRange::FromTo(ByteWindow {
                        start: 0,
                        end: None,
                    })),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                *response_header(&response, &CONTENT_RANGE),
                format!(
                    "bytes {}-{}/{}",
                    0,
                    content.len() as u64 - 1,
                    content.len() as u64
                )
            );
            assert_eq!(
                *response_header(&response, &CONTENT_LENGTH),
                (content.len() as u64).to_string()
            );
            assert_eq!(response_body(response).await, content);
        })
        .await;
    }

    #[tokio::test]
    async fn get_local_blob_suffix_range_returns_tail() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"suffix range content";
            let suffix_length = 7;
            let start = content.len() - suffix_length;

            let (digest, _) = create_test_blob(registry, namespace, content).await;
            let response = registry
                .get_local_blob(&digest, Some(RequestRange::Suffix(suffix_length as u64)))
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                *response_header(&response, &CONTENT_RANGE),
                format!(
                    "bytes {}-{}/{}",
                    start as u64,
                    content.len() as u64 - 1,
                    content.len() as u64
                )
            );
            assert_eq!(
                *response_header(&response, &CONTENT_LENGTH),
                (suffix_length as u64).to_string()
            );
            assert_eq!(response_body(response).await, &content[start..]);
        })
        .await;
    }

    #[tokio::test]
    async fn get_local_blob_suffix_range_longer_than_blob_returns_full_blob() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"short suffix";

            let (digest, _) = create_test_blob(registry, namespace, content).await;
            let response = registry
                .get_local_blob(&digest, Some(RequestRange::Suffix(10_000)))
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                *response_header(&response, &CONTENT_RANGE),
                format!(
                    "bytes {}-{}/{}",
                    0,
                    content.len() as u64 - 1,
                    content.len() as u64
                )
            );
            assert_eq!(
                *response_header(&response, &CONTENT_LENGTH),
                (content.len() as u64).to_string()
            );
            assert_eq!(response_body(response).await, content);
        })
        .await;
    }

    #[tokio::test]
    async fn get_local_blob_clamps_range_end_to_blob_length() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"clamped range content";

            let (digest, _) = create_test_blob(registry, namespace, content).await;
            let response = registry
                .get_local_blob(
                    &digest,
                    Some(RequestRange::FromTo(ByteWindow {
                        start: 8,
                        end: Some(10_000),
                    })),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                *response_header(&response, &CONTENT_RANGE),
                format!(
                    "bytes {}-{}/{}",
                    8,
                    content.len() as u64 - 1,
                    content.len() as u64
                )
            );
            assert_eq!(
                *response_header(&response, &CONTENT_LENGTH),
                (content.len() as u64 - 8).to_string()
            );
            assert_eq!(response_body(response).await, &content[8..]);
        })
        .await;
    }

    #[tokio::test]
    async fn get_local_blob_rejects_range_start_at_blob_length() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"range boundary";

            let (digest, _) = create_test_blob(registry, namespace, content).await;
            let result = registry
                .get_local_blob(
                    &digest,
                    Some(RequestRange::FromTo(ByteWindow {
                        start: content.len() as u64,
                        end: None,
                    })),
                )
                .await;

            assert!(matches!(result, Err(Error::RangeNotSatisfiable)));
        })
        .await;
    }

    #[tokio::test]
    async fn get_local_blob_ignores_ranges_for_empty_blobs() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();

            let (digest, _) = create_test_blob(registry, namespace, b"").await;
            let response = registry
                .get_local_blob(
                    &digest,
                    Some(RequestRange::FromTo(ByteWindow {
                        start: 0,
                        end: None,
                    })),
                )
                .await
                .unwrap();

            // An empty blob has no satisfiable window, so the range is ignored
            // and the whole (empty) body is served.
            assert_eq!(response.status(), StatusCode::OK);
            assert!(response_body(response).await.is_empty());
        })
        .await;
    }

    #[tokio::test]
    async fn test_head_blob_independent_of_get() {
        for_each_backend(async |test_case| {
            let registry = test_case.registry();
            let namespace = &Namespace::new("test-repo").unwrap();
            let content = b"head blob independence test";

            let (digest, repository) = create_test_blob(registry, namespace, content).await;

            let head_response = registry
                .head_blob(HeadBlobRequest {
                    namespace: namespace.clone(),
                    digest: digest.clone(),
                    accepted_types: Vec::new(),
                })
                .await
                .unwrap();
            assert_eq!(response_digest(&head_response), digest);
            let head_length = response_header(&head_response, &CONTENT_LENGTH);
            assert_eq!(*head_length, content.len().to_string());

            // HEAD and GET must agree on what they say the blob is.
            let get_response = get_blob(registry, &repository, &[], namespace, &digest, None)
                .await
                .unwrap();
            assert_eq!(
                *response_header(&get_response, &CONTENT_LENGTH),
                head_length
            );
        })
        .await;
    }
}
