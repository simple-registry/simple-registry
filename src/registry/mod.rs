use std::{fmt, num::NonZeroUsize, sync::Arc, time::Duration};

use http::{
    Response, StatusCode,
    header::{HeaderName, HeaderValue},
};
use tokio::{select, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

pub mod admin;
pub mod blob;
pub mod blob_ownership;
pub mod blob_store;
pub mod content_discovery;
mod error;
#[cfg(test)]
mod event_emission_tests;
pub mod keys;
pub mod manifest;
pub mod metadata_store;
pub mod pagination;
pub mod path_builder;
pub mod repository;
pub mod repository_resolver;
pub mod s3_connection;
#[cfg(test)]
pub mod test_utils;
pub mod upload;

use angos_oci::server;
use angos_oci::{Namespace, Reference, Tag};

use crate::{
    cache,
    cache_fill::CacheFillJobHandler,
    configuration::{
        RegexPattern,
        global::{DEFAULT_MAX_CONCURRENT_CACHE_JOBS, DEFAULT_MAX_CONCURRENT_REPLICATION_JOBS},
    },
    event_webhook::{dispatcher::EventDispatcher, event::Event},
    http_response::{ResponseBody, build_response},
    jobs::Queue,
    jobs::{
        runner::execute_one,
        store::{ClaimMode, JobHandler, JobStore},
    },
    registry::{
        blob_store::BlobStore, metadata_store::MetadataStore,
        repository_resolver::RepositoryResolver,
    },
    replication::ReplicationJobHandler,
};
pub use admin::{
    DeleteJobRequest, ListJobsRequest, ListNamespacesRequest, ListRevisionsRequest,
    ListUploadsRequest, RetryJobRequest,
};
use blob_ownership::BlobOwnership;
pub use error::Error;
pub use repository::Repository;

/// Angos's own response header, alongside the distribution API's own names in
/// [`angos_oci::header`].
pub const X_POWERED_BY: HeaderName = HeaderName::from_static("x-powered-by");

#[allow(clippy::struct_excessive_bools)]
pub struct RegistryConfig {
    pub update_pull_time: bool,
    pub enable_blob_redirect: bool,
    pub enable_manifest_redirect: bool,
    pub global_immutable_tags: bool,
    pub global_immutable_tags_exclusions: Vec<RegexPattern>,
    pub max_manifest_size_bytes: usize,
    pub max_blob_size_bytes: u64,
    /// When `true`, a push is rejected with `MANIFEST_BLOB_UNKNOWN` if any
    /// referenced blob or child manifest is not owned by the target namespace;
    /// when `false` the unowned references are left dangling rather than
    /// granted, so a namespace never gains read access to content it did not
    /// push. `subject` references and pull-through cache-fill writes are exempt
    /// either way.
    pub validate_manifest_references: bool,
    /// Pre-built queue all cache-fill and replication jobs route through; when
    /// absent, an in-process queue is built at startup instead.
    pub job_queue: Option<Arc<JobStore>>,
    /// Parallel in-process cache-fill jobs, consulted only when `job_queue` is
    /// `None`.
    pub max_concurrent_cache_jobs: NonZeroUsize,
    /// Parallel in-process replication-push jobs, consulted only when
    /// `job_queue` is `None`.
    pub max_concurrent_replication_jobs: NonZeroUsize,
    /// Webhook dispatcher operations deliver their events through; `None`
    /// disables delivery entirely.
    pub event_dispatcher: Option<Arc<EventDispatcher>>,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            update_pull_time: false,
            enable_blob_redirect: true,
            enable_manifest_redirect: true,
            global_immutable_tags: false,
            global_immutable_tags_exclusions: Vec::new(),
            max_manifest_size_bytes: manifest::DEFAULT_MAX_MANIFEST_SIZE_BYTES,
            max_blob_size_bytes: upload::DEFAULT_MAX_BLOB_SIZE_BYTES,
            // Strict here so registries built from the default keep validating;
            // the server opts into the permissive production default via
            // `[global]`.
            validate_manifest_references: true,
            job_queue: None,
            max_concurrent_cache_jobs: DEFAULT_MAX_CONCURRENT_CACHE_JOBS,
            max_concurrent_replication_jobs: DEFAULT_MAX_CONCURRENT_REPLICATION_JOBS,
            event_dispatcher: None,
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
pub struct Registry {
    blob_store: Arc<BlobStore>,
    metadata_store: Arc<MetadataStore>,
    resolver: Arc<RepositoryResolver>,
    enable_blob_redirect: bool,
    enable_manifest_redirect: bool,
    update_pull_time: bool,
    job_queue: Arc<JobStore>,
    /// Cancels the in-process claim loops on drop; `None` when a durable
    /// `[global.job_queue]` is configured.
    in_process_shutdown: Option<CancellationToken>,
    global_immutable_tags: bool,
    global_immutable_tags_exclusions: Vec<RegexPattern>,
    max_manifest_size_bytes: usize,
    max_blob_size_bytes: u64,
    validate_manifest_references: bool,
    event_dispatcher: Option<Arc<EventDispatcher>>,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry").finish()
    }
}

/// The OCI API version this registry speaks, served on `/v2/`.
pub fn api_version() -> Result<Response<ResponseBody>, Error> {
    let mut headers = server::api_version_headers();
    headers.insert(X_POWERED_BY, HeaderValue::from_static("Angos"));

    Ok(build_response(
        StatusCode::OK,
        headers,
        ResponseBody::empty(),
    )?)
}

impl Registry {
    /// Whether `reference` names something that may not be overwritten; a
    /// digest is content-addressed, so it is never immutable in this sense.
    pub fn is_reference_immutable(
        &self,
        repository: Option<&Repository>,
        reference: &Reference,
    ) -> bool {
        match reference {
            Reference::Tag(tag) => self.is_tag_immutable(repository, tag),
            Reference::Digest(_) => false,
        }
    }

    /// A repository's own `immutable_tags` opts in on top of the global flag,
    /// and its own exclusions replace the global ones when it declares any.
    pub fn is_tag_immutable(&self, repository: Option<&Repository>, tag: &Tag) -> bool {
        let immutable =
            self.global_immutable_tags || repository.is_some_and(|repo| repo.immutable_tags);
        if !immutable {
            return false;
        }

        let exclusions = match repository {
            Some(repo) if !repo.immutable_tags_exclusions.is_empty() => {
                &repo.immutable_tags_exclusions
            }
            _ => &self.global_immutable_tags_exclusions,
        };

        !exclusions
            .iter()
            .any(|pattern| pattern.is_match(tag.as_ref()))
    }

    /// Ownership view over the metadata store's blob index.
    pub fn blob_ownership(&self) -> BlobOwnership<'_> {
        BlobOwnership::new(self.metadata_store.as_ref())
    }

    #[instrument(skip(blob_store, metadata_store, resolver, config))]
    pub fn new(
        blob_store: Arc<BlobStore>,
        metadata_store: Arc<MetadataStore>,
        resolver: Arc<RepositoryResolver>,
        config: RegistryConfig,
    ) -> Arc<Self> {
        let (job_queue, in_process_shutdown): (Arc<JobStore>, Option<CancellationToken>) =
            if let Some(q) = config.job_queue {
                (q, None)
            } else {
                let (q, shutdown) = build_in_process_queue(
                    &resolver,
                    &blob_store,
                    &metadata_store,
                    config.max_concurrent_cache_jobs,
                    config.max_concurrent_replication_jobs,
                    config.event_dispatcher.clone(),
                );
                (q, Some(shutdown))
            };

        Arc::new(Self {
            update_pull_time: config.update_pull_time,
            enable_blob_redirect: config.enable_blob_redirect,
            enable_manifest_redirect: config.enable_manifest_redirect,
            blob_store,
            metadata_store,
            resolver,
            job_queue,
            in_process_shutdown,
            global_immutable_tags: config.global_immutable_tags,
            global_immutable_tags_exclusions: config.global_immutable_tags_exclusions,
            max_manifest_size_bytes: config.max_manifest_size_bytes,
            max_blob_size_bytes: config.max_blob_size_bytes,
            validate_manifest_references: config.validate_manifest_references,
            event_dispatcher: config.event_dispatcher,
        })
    }

    /// The configured webhook dispatcher, shared so externally built handlers
    /// emit through the same instance [`Registry::shutdown`] drains.
    pub fn event_dispatcher(&self) -> Option<Arc<EventDispatcher>> {
        self.event_dispatcher.clone()
    }

    #[cfg(test)]
    pub fn has_event_dispatcher(&self) -> bool {
        self.event_dispatcher.is_some()
    }

    /// Delivers every event even when an earlier delivery fails, returning the
    /// first error. Operations call this before performing the action, so a
    /// performed action can never go unnotified (at-least-once) at the cost of
    /// a false-positive notification when the action then fails.
    pub async fn dispatch_events(&self, events: &[Event]) -> Result<(), Error> {
        let Some(dispatcher) = &self.event_dispatcher else {
            return Ok(());
        };
        let mut first_error: Option<Error> = None;
        for event in events {
            if let Err(error) = dispatcher.dispatch(event).await
                && first_error.is_none()
            {
                first_error = Some(Error::EventDelivery(error.to_string()));
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Drains in-flight async webhook deliveries to completion.
    pub async fn shutdown(&self) {
        if let Some(dispatcher) = &self.event_dispatcher {
            dispatcher.shutdown().await;
        }
    }

    /// Probes the metadata backend.
    pub async fn check_ready(&self) -> Result<(), Error> {
        self.metadata_store.check_ready().await
    }

    /// The repository mirroring the registry namespace a proxying client names
    /// in `?ns=`, or `None` when no repository claims it.
    pub fn repository_for_ns(&self, ns: &str) -> Option<&Repository> {
        self.resolver.resolve_ns(ns)
    }

    #[instrument]
    pub fn get_repository_for_namespace(
        &self,
        namespace: &Namespace,
    ) -> Result<&Repository, Error> {
        self.resolver.resolve(namespace).ok_or(Error::NameUnknown)
    }

    /// The event `repository` field for `namespace`, empty when none matches.
    /// Callers already holding the resolved repository use [`repository_name`]
    /// instead, so a request never resolves the same namespace twice.
    pub fn repository_name_for(&self, namespace: &Namespace) -> String {
        repository_name(self.get_repository_for_namespace(namespace).ok())
    }
}

/// The event `repository` field for an already-resolved repository, empty when
/// no `[repository]` entry matched.
pub fn repository_name(repository: Option<&Repository>) -> String {
    repository.map_or_else(String::new, |repository| repository.name.to_string())
}

/// Construct the in-process job queue used when `[global.job_queue]` is absent.
fn build_in_process_queue(
    resolver: &Arc<RepositoryResolver>,
    blob_store: &Arc<BlobStore>,
    metadata_store: &Arc<MetadataStore>,
    cache_concurrency: NonZeroUsize,
    replication_concurrency: NonZeroUsize,
    event_dispatcher: Option<Arc<EventDispatcher>>,
) -> (Arc<JobStore>, CancellationToken) {
    // Atomic mode: in-process draining runs no startup probe to pick one from.
    let job_store: Arc<JobStore> = Arc::new(JobStore::alongside(
        metadata_store,
        "in-process",
        ClaimMode::Atomic,
    ));

    let cache_handler: Arc<dyn JobHandler> = Arc::new(CacheFillJobHandler::new(
        resolver.clone(),
        blob_store.clone(),
        metadata_store.clone(),
        event_dispatcher,
    ));

    // Drain replication only when a downstream is configured: an always-empty
    // queue would just storm the object store with `LIST`s. Build the handler
    // before spawning any loop so an error cannot leak a cache loop.
    let any_downstream = resolver
        .keys()
        .filter_map(|name| resolver.get(name))
        .any(|repository| !repository.replication.is_empty());
    let replication_handler: Option<Arc<dyn JobHandler>> = if any_downstream {
        // Mesh cycles terminate: only state-changing writes dispatch, and
        // receiver-side no-op suppression stops any remaining replays.
        Some(Arc::new(ReplicationJobHandler::new(
            resolver.clone(),
            blob_store.clone(),
            metadata_store.clone(),
        )))
    } else {
        None
    };

    let shutdown = CancellationToken::new();

    for _ in 0..cache_concurrency.get() {
        tokio::spawn(in_process_claim_loop(
            job_store.clone(),
            cache_handler.clone(),
            Queue::Cache,
            shutdown.clone(),
        ));
    }

    if let Some(replication_handler) = replication_handler {
        for _ in 0..replication_concurrency.get() {
            tokio::spawn(in_process_claim_loop(
                job_store.clone(),
                replication_handler.clone(),
                Queue::Replication,
                shutdown.clone(),
            ));
        }
    }

    (job_store, shutdown)
}

/// Idle poll interval for the in-process claim loops; production polls once a
/// second so an empty queue does not storm the object store with `LIST`s.
#[cfg(not(test))]
const IN_PROCESS_IDLE_POLL: Duration = Duration::from_secs(1);
#[cfg(test)]
const IN_PROCESS_IDLE_POLL: Duration = Duration::from_millis(10);

/// Single claim-loop task for the in-process pool; `handler` must be the
/// handler bound to `queue`. Cancellation races only the claim, so an
/// already-claimed job runs to completion rather than being interrupted.
async fn in_process_claim_loop(
    consumer: Arc<JobStore>,
    handler: Arc<dyn JobHandler>,
    queue: Queue,
    shutdown: CancellationToken,
) {
    loop {
        select! {
            () = shutdown.cancelled() => return,
            outcome = consumer.claim_one(queue) => match outcome {
                // `claim_one` self-throttles on a backend error; nothing to do.
                Err(_) => {}
                Ok(claim_outcome) => match claim_outcome.claimed {
                    None => sleep(claim_outcome.idle_sleep(IN_PROCESS_IDLE_POLL)).await,
                    Some(claimed) => {
                        execute_one(consumer.as_ref(), handler.as_ref(), claimed).await;
                    }
                },
            },
        }
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        // Claim loops hold their own `Arc<JobStore>` clones, so only cancelling
        // the token stops them.
        if let Some(shutdown) = &self.in_process_shutdown {
            shutdown.cancel();
        }
    }
}

#[cfg(test)]
mod in_process_replication_tests {
    use std::{sync::Arc, time::Duration};

    use tempfile::TempDir;
    use tokio::time::{sleep, timeout};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use angos_oci::header::DOCKER_CONTENT_DIGEST;
    use angos_oci::{Namespace, Tag};

    use crate::metrics_provider::init_for_tests;
    use crate::registry::manifest::DispatchTarget;
    use crate::{
        jobs::{
            Queue,
            store::{ClaimMode, JobEnvelope, JobStore},
        },
        registry::{
            Registry, RegistryConfig, Repository,
            blob_store::BlobStore,
            metadata_store::MetadataStore,
            test_utils::{
                FsTestStack, downstream_client, fs_test_stack, repository_with_downstream,
                repository_with_replication, seed_manifest, single_repo_resolver,
            },
        },
        registry_client::RegistryClient,
        replication::REPLICATION_PUSH_MANIFEST_KIND,
    };

    const NAMESPACE: &str = "nginx";
    const REPO: &str = "nginx";

    fn repository_without_downstream() -> Repository {
        repository_with_replication(REPO, Vec::new())
    }

    /// A `Registry` with an automatic in-process queue over `repository`, plus
    /// the shared stores for seeding local state.
    fn build_registry_with(
        repository: Repository,
    ) -> (Arc<Registry>, Arc<BlobStore>, Arc<MetadataStore>, TempDir) {
        let FsTestStack {
            dir,
            store: _,
            metadata_store,
            blob_store,
        } = fs_test_stack();
        let resolver = single_repo_resolver(REPO, repository);

        let config = RegistryConfig::default();
        let registry = Registry::new(blob_store.clone(), metadata_store.clone(), resolver, config);

        (registry, blob_store, metadata_store, dir)
    }

    fn build_registry(
        client: Arc<RegistryClient>,
    ) -> (Arc<Registry>, Arc<BlobStore>, Arc<MetadataStore>, TempDir) {
        build_registry_with(repository_with_downstream(REPO, client))
    }

    /// The drained job runs the full push pipeline (HEAD-before-PUT blobs, PUT
    /// manifest) against a wiremock downstream.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn in_process_loop_drains_replication_push_job() {
        init_for_tests();
        let mock_server = MockServer::start().await;

        let client = downstream_client(&mock_server.uri());
        let (registry, _blob_store, metadata_store, _dir) = build_registry(client);
        let namespace = Namespace::new(NAMESPACE).unwrap();

        let (manifest_digest, config_digest, layer_digest) =
            seed_manifest(metadata_store.object_store(), &metadata_store, &namespace).await;

        for blob in [&config_digest, &layer_digest] {
            Mock::given(method("HEAD"))
                .and(path(format!("/v2/{NAMESPACE}/blobs/{blob}")))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock_server)
                .await;
        }
        Mock::given(method("POST"))
            .and(path(format!("/v2/{NAMESPACE}/blobs/uploads/")))
            .respond_with(
                ResponseTemplate::new(202)
                    .insert_header("Location", format!("/v2/{NAMESPACE}/blobs/uploads/s1")),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("/v2/{NAMESPACE}/blobs/uploads/s1")))
            .respond_with(
                ResponseTemplate::new(202)
                    .insert_header("Location", format!("/v2/{NAMESPACE}/blobs/uploads/s1")),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path(format!("/v2/{NAMESPACE}/blobs/uploads/s1")))
            .respond_with(ResponseTemplate::new(201))
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path(format!("/v2/{NAMESPACE}/manifests/v1")))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header(DOCKER_CONTENT_DIGEST, manifest_digest.to_string().as_str()),
            )
            .expect(1..)
            .mount(&mock_server)
            .await;

        let repository = registry.resolver.resolve(&namespace);
        let tag = Tag::new("v1").unwrap();
        registry
            .dispatch_replication(
                repository,
                &namespace,
                DispatchTarget::Push {
                    tag: Some(&tag),
                    digest: &manifest_digest,
                },
                None,
            )
            .await;

        let manifest_path = format!("/v2/{NAMESPACE}/manifests/v1");
        let saw_put = timeout(Duration::from_secs(10), async {
            loop {
                let received = mock_server.received_requests().await.unwrap_or_default();
                if received
                    .iter()
                    .any(|r| r.method.as_str() == "PUT" && r.url.path() == manifest_path)
                {
                    return true;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or(false);

        let inspector = JobStore::alongside(&metadata_store, "inspector", ClaimMode::Atomic);

        if !saw_put {
            let received = mock_server.received_requests().await.unwrap_or_default();
            let summary: Vec<String> = received
                .iter()
                .map(|r| format!("{} {}", r.method.as_str(), r.url.path()))
                .collect();
            let pending = inspector
                .count_pending(Queue::Replication, 0)
                .await
                .unwrap_or(u64::MAX);
            let failed = inspector
                .list_failed_page(Queue::Replication, 16, None)
                .await
                .map_or(usize::MAX, |page| page.items.len());
            panic!(
                "in-process replication loop must drain the job and PUT the manifest \
                 downstream; received requests: {summary:?}; pending={pending}; failed={failed}"
            );
        }

        // Zero pending proves the loop completed the job rather than retrying.
        let drained = timeout(Duration::from_secs(10), async {
            loop {
                let pending = inspector
                    .count_pending(Queue::Replication, 0)
                    .await
                    .unwrap_or(u64::MAX);
                if pending == 0 {
                    return true;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or(false);

        let failed = inspector
            .list_failed_page(Queue::Replication, 16, None)
            .await
            .map_or(usize::MAX, |page| page.items.len());
        assert!(
            drained,
            "the replication queue must drain to zero pending after a successful push"
        );
        assert_eq!(failed, 0, "a successful push must not dead-letter the job");
    }

    /// With no downstream configured no replication loop is spawned, so the
    /// job must stay pending rather than be drained.
    #[tokio::test]
    async fn no_replication_loop_when_no_downstream_configured() {
        init_for_tests();
        let (registry, _blob_store, _metadata_store, _dir) =
            build_registry_with(repository_without_downstream());

        registry
            .job_queue
            .enqueue(
                JobEnvelope::new(
                    Queue::Replication,
                    REPLICATION_PUSH_MANIFEST_KIND,
                    format!("{}.eu:nginx:v1", Queue::Replication),
                    &(),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        // A spawned loop idles at 10ms under cfg(test), so one would have
        // claimed the job many times over within 500ms.
        sleep(Duration::from_millis(500)).await;

        assert_eq!(
            registry
                .job_queue
                .count_pending(Queue::Replication, 0)
                .await
                .unwrap(),
            1,
            "no downstream means no replication loop, so the job must stay pending"
        );
    }
}

#[cfg(test)]
mod immutable_tag_tests {
    use std::{collections::HashMap, sync::Arc};

    use tempfile::TempDir;

    use angos_oci::{Namespace, Reference, Tag};
    use angos_storage::{ObjectStore, fs::Backend as StorageFsBackend};

    use crate::registry::{Registry, RegistryConfig};
    use crate::{
        configuration::RegexPattern,
        registry::{
            blob_store::BlobStore,
            repository::Repository,
            repository_resolver::RepositoryResolver,
            test_utils::{metadata_store_over, repository_with_replication},
        },
    };

    /// A registry whose sole `myrepo/*` repository carries the immutability
    /// settings under test, over the global ones.
    fn registry_with(
        global_immutable_tags: bool,
        global_exclusions: &[&str],
        repository_immutable_tags: bool,
        repository_exclusions: &[&str],
    ) -> (Arc<Registry>, TempDir) {
        let mut repository = repository_with_replication("myrepo", Vec::new());
        repository.immutable_tags = repository_immutable_tags;
        repository.immutable_tags_exclusions = patterns(repository_exclusions);

        let mut repositories = HashMap::new();
        repositories.insert("myrepo".to_string(), repository);

        let dir = TempDir::new().expect("temp dir");
        let object: Arc<dyn ObjectStore> = Arc::new(StorageFsBackend::builder(dir.path()).build());
        let registry = Registry::new(
            Arc::new(BlobStore::new(object.clone(), None)),
            metadata_store_over(object),
            Arc::new(RepositoryResolver::new(Arc::new(repositories)).expect("test resolver")),
            RegistryConfig {
                global_immutable_tags,
                global_immutable_tags_exclusions: patterns(global_exclusions),
                ..RegistryConfig::default()
            },
        );
        (registry, dir)
    }

    fn patterns(sources: &[&str]) -> Vec<RegexPattern> {
        sources
            .iter()
            .map(|source| RegexPattern::compile(*source).expect("test pattern must compile"))
            .collect()
    }

    fn namespace() -> Namespace {
        Namespace::new("myrepo/app").unwrap()
    }

    fn repository_of(registry: &Registry) -> Option<&Repository> {
        registry.get_repository_for_namespace(&namespace()).ok()
    }

    fn tag(name: &str) -> Tag {
        Tag::new(name).unwrap()
    }

    #[tokio::test]
    async fn the_global_flag_freezes_every_tag() {
        let (registry, _dir) = registry_with(true, &[], false, &[]);

        assert!(registry.is_tag_immutable(repository_of(&registry), &tag("v1.0.0")));
    }

    #[tokio::test]
    async fn global_exclusions_stay_mutable() {
        let (registry, _dir) = registry_with(true, &["^latest$", "^dev-.*"], false, &[]);

        assert!(!registry.is_tag_immutable(repository_of(&registry), &tag("latest")));
        assert!(!registry.is_tag_immutable(repository_of(&registry), &tag("dev-branch")));
        assert!(registry.is_tag_immutable(repository_of(&registry), &tag("v1.0.0")));
    }

    #[tokio::test]
    async fn a_repository_can_freeze_its_own_tags() {
        let (registry, _dir) = registry_with(false, &[], true, &[]);

        assert!(registry.is_tag_immutable(repository_of(&registry), &tag("v1.0.0")));
    }

    /// A repository declaring exclusions replaces the global list rather than
    /// adding to it, so `latest` is frozen here despite the global exclusion.
    #[tokio::test]
    async fn repository_exclusions_replace_the_global_ones() {
        let (registry, _dir) = registry_with(true, &["^latest$"], true, &["^test-.*"]);

        assert!(!registry.is_tag_immutable(repository_of(&registry), &tag("test-123")));
        assert!(registry.is_tag_immutable(repository_of(&registry), &tag("latest")));
    }

    #[tokio::test]
    async fn a_digest_reference_is_never_immutable() {
        let (registry, _dir) = registry_with(true, &[], true, &[]);
        let digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();

        assert!(
            !registry.is_reference_immutable(repository_of(&registry), &Reference::Digest(digest))
        );
        assert!(
            registry
                .is_reference_immutable(repository_of(&registry), &Reference::Tag(tag("v1.0.0")))
        );
    }
}

#[cfg(test)]
mod api_version_tests {
    use angos_oci::header::DOCKER_DISTRIBUTION_API_VERSION;

    use crate::registry::test_utils::response_header;
    use crate::registry::{X_POWERED_BY, api_version};

    #[test]
    fn api_version_announces_the_v2_protocol() {
        let response = api_version().unwrap();

        assert_eq!(
            *response_header(&response, &DOCKER_DISTRIBUTION_API_VERSION),
            "registry/2.0"
        );
        assert_eq!(*response_header(&response, &X_POWERED_BY), "Angos");
    }
}
