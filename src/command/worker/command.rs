use std::{collections::HashSet, num::NonZeroUsize, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use argh::FromArgs;
use async_trait::async_trait;
use humantime::Duration as HumanDuration;
use tokio::{
    select,
    time::{sleep, timeout},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, error, warn};
use uuid::Uuid;

use angos_storage::ObjectStore;

use crate::{
    cache_fill::CacheFillJobHandler,
    command::bootstrap::{self, Error},
    configuration::{Configuration, listeners::ServerTlsConfig, watcher::ConfigNotifier},
    jobs::Queue,
    jobs::runner::execute_one,
    jobs::store::{self as job_store, JobHandler, JobRetryPolicy, JobStore},
    registry::{
        Registry, blob_store::BlobStore, metadata_store::MetadataStore,
        repository_resolver::RepositoryResolver,
    },
    replication::ReplicationJobHandler,
};

/// Process durable background jobs.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(
    subcommand,
    name = "worker",
    description = "Process durable background jobs"
)]
pub struct Options {
    /// queue to drain; repeatable. Defaults to both "cache" and "replication",
    /// each on its own worker pool.
    #[argh(option)]
    pub queue: Vec<String>,
    /// idle poll interval when the queue is empty
    #[argh(option, default = "HumanDuration::from(Duration::from_secs(1))")]
    pub poll_interval: HumanDuration,
}

/// Hot-reloadable worker subcommand draining one or more queues, each on its
/// own worker pool. Components are swapped atomically on configuration reload;
/// in-flight jobs finish on the components they started with.
pub struct Command {
    queues: Vec<QueueRunner>,
    poll_interval: Duration,
    shutdown: CancellationToken,
    workers: TaskTracker,
}

struct QueueRunner {
    inner: Arc<ArcSwap<Components>>,
    queue: Queue,
    concurrency: NonZeroUsize,
}

struct Components {
    consumer: Arc<JobStore>,
    handler: Arc<dyn JobHandler>,
    registry: Arc<Registry>,
}

fn queue_concurrency(config: &Configuration, queue: Queue) -> NonZeroUsize {
    match queue {
        Queue::Replication => config.global.max_concurrent_replication_jobs,
        Queue::Cache => config.global.max_concurrent_cache_jobs,
    }
}

/// Parses and de-duplicates `--queue` values preserving command-line order;
/// defaults to both `cache` and `replication` when none are given. An unknown
/// queue name is rejected here (the bad name is reported in the error).
fn resolve_queues(requested: &[String]) -> Result<Vec<Queue>, Error> {
    if requested.is_empty() {
        return Ok(vec![Queue::Cache, Queue::Replication]);
    }
    let mut seen = HashSet::new();
    let mut queues = Vec::new();
    for name in requested {
        let queue: Queue = name
            .parse()
            .map_err(|e| Error::JobQueue(job_store::Error::Initialization(e)))?;
        if seen.insert(queue) {
            queues.push(queue);
        }
    }
    Ok(queues)
}

impl Command {
    pub async fn new(options: &Options, config: &Configuration) -> Result<Self, Error> {
        let context = WorkerContext::build(config).await?;

        let mut queues = Vec::new();
        for queue in resolve_queues(&options.queue)? {
            let concurrency = queue_concurrency(config, queue);
            let components = context.components_for(queue);
            queues.push(QueueRunner {
                inner: Arc::new(ArcSwap::from_pointee(components)),
                queue,
                concurrency,
            });
        }

        Ok(Self {
            queues,
            poll_interval: *options.poll_interval,
            shutdown: CancellationToken::new(),
            workers: TaskTracker::new(),
        })
    }

    /// Cancel the worker pool and wait up to `grace` for tasks to finish.
    /// Surviving tasks are dropped on process exit; the durable queue's lease
    /// TTL guarantees re-claim by another worker.
    pub async fn shutdown_with_timeout(&self, grace: Duration) {
        self.shutdown.cancel();
        self.workers.close();
        if timeout(grace, self.workers.wait()).await.is_err() {
            warn!("Worker pool did not drain within shutdown grace period");
        }
        // Drain in-flight async webhook deliveries to completion. Every queue
        // shares one registry per configuration generation, and a repeated
        // drain on the same registry is a no-op.
        for runner in &self.queues {
            runner.inner.load().registry.shutdown().await;
        }
    }

    /// Spawn `concurrency` claim-loop tasks per drained queue and wait for them
    /// to finish. Returns when every worker observes the shutdown signal and
    /// exits.
    pub async fn run(&self) {
        for runner in &self.queues {
            for _ in 0..runner.concurrency.get() {
                let inner = Arc::clone(&runner.inner);
                let queue = runner.queue;
                let poll_interval = self.poll_interval;
                let shutdown = self.shutdown.clone();
                self.workers.spawn(async move {
                    worker_loop(inner, queue, poll_interval, shutdown).await;
                });
            }
        }
        self.workers.close();
        self.workers.wait().await;
    }
}

/// Single claim-loop task. Claim-error backoff is handled inside the job queue
/// (`JobStore::claim_one`), so a broken backend is not hammered.
async fn worker_loop(
    inner: Arc<ArcSwap<Components>>,
    queue: Queue,
    poll_interval: Duration,
    shutdown: CancellationToken,
) {
    loop {
        let snapshot = inner.load_full();
        select! {
            () = shutdown.cancelled() => {
                debug!("Worker poll loop stopping");
                return;
            }
            result = snapshot.consumer.claim_one(queue) => match result {
                // `claim_one` self-throttles on a backend error; just log it.
                Err(e) => error!(error = %e, "claim_one failed; backing off"),
                Ok(outcome) => match outcome.claimed {
                    None => sleep(outcome.idle_sleep(poll_interval)).await,
                    Some(claimed) => {
                        execute_one(
                            snapshot.consumer.as_ref(),
                            snapshot.handler.as_ref(),
                            claimed,
                        )
                        .await;
                    }
                },
            }
        }
    }
}

#[async_trait]
impl ConfigNotifier for Command {
    async fn notify_config_change(&self, config: &Configuration) {
        let context = match WorkerContext::build(config).await {
            Ok(context) => context,
            Err(e) => {
                error!("Failed to rebuild worker context on reload: {e}");
                return;
            }
        };
        for runner in &self.queues {
            runner
                .inner
                .store(Arc::new(context.components_for(runner.queue)));
        }
    }

    fn notify_tls_config_change(&self, _tls: &ServerTlsConfig) {
        // The worker has no TLS listener.
    }
}

/// Queue-independent worker resources, built once and shared so draining N
/// queues does not rebuild storage and stores N times.
struct WorkerContext {
    storage: Arc<dyn ObjectStore>,
    blob_store: Arc<BlobStore>,
    metadata_store: Arc<MetadataStore>,
    repositories: Arc<RepositoryResolver>,
    registry: Arc<Registry>,
    retry_policy: JobRetryPolicy,
}

impl WorkerContext {
    async fn build(config: &Configuration) -> Result<Self, Error> {
        let bootstrap::MaintenanceContext {
            blob_store,
            metadata_store,
            repositories,
        } = bootstrap::maintenance_context(config).await?;

        let Some(job_queue) = config.global.job_queue.as_ref() else {
            return Err(bootstrap::Error::JobQueue(
                job_store::Error::Initialization(
                    "[global.job_queue] is required for the worker subcommand".to_string(),
                ),
            ));
        };
        let retry_policy = job_queue.retry_policy();

        // Share the metadata store's object store instead of wiring a
        // second backend over the same storage.
        let storage = metadata_store.object_store().clone();
        job_store::ensure_claim_support(&storage).await?;
        let registry = bootstrap::registry(
            config,
            blob_store.clone(),
            metadata_store.clone(),
            repositories.clone(),
            Arc::new(JobStore::with_retry_policy(
                storage.clone(),
                "worker",
                retry_policy,
            )),
        )?;

        Ok(Self {
            storage,
            blob_store,
            metadata_store,
            repositories,
            registry,
            retry_policy,
        })
    }

    /// Builds the [`Components`] for one queue: a fresh `JobStore` consumer
    /// over the shared storage plus the handler bound to that queue.
    fn components_for(&self, queue: Queue) -> Components {
        let consumer = Arc::new(JobStore::with_retry_policy(
            self.storage.clone(),
            Uuid::new_v4().to_string(),
            self.retry_policy,
        ));
        let handler: Arc<dyn JobHandler> = match queue {
            Queue::Replication => Arc::new(ReplicationJobHandler::new(
                self.repositories.clone(),
                self.blob_store.clone(),
                self.metadata_store.clone(),
            )),
            Queue::Cache => Arc::new(CacheFillJobHandler::new(
                self.repositories.clone(),
                self.blob_store.clone(),
                self.metadata_store.clone(),
                self.registry.event_dispatcher(),
            )),
        };

        Components {
            consumer,
            handler,
            registry: self.registry.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use tempfile::TempDir;

    use angos_storage::{ObjectStore, fs::Backend as StorageFsBackend};

    use super::{WorkerContext, resolve_queues};
    use crate::{
        cache_fill::CACHE_FETCH_BLOB_KIND,
        jobs::{
            Queue,
            store::{JobEnvelope, JobRetryPolicy, JobStore},
        },
        metrics_provider,
        registry::{
            Registry, RegistryConfig, blob_store::BlobStore, metadata_store::MetadataStore,
            repository_resolver::RepositoryResolver,
        },
        replication::REPLICATION_PUSH_MANIFEST_KIND,
    };

    #[test]
    fn resolve_queues_defaults_to_cache_and_replication() {
        assert_eq!(
            resolve_queues(&[]).unwrap(),
            vec![Queue::Cache, Queue::Replication]
        );
    }

    #[test]
    fn resolve_queues_dedups_preserving_command_line_order() {
        assert_eq!(
            resolve_queues(&[
                "replication".to_string(),
                "cache".to_string(),
                "replication".to_string(),
            ])
            .unwrap(),
            vec![Queue::Replication, Queue::Cache],
            "explicit --queue order must be preserved, duplicates dropped"
        );
    }

    #[test]
    fn resolve_queues_rejects_unknown_queue() {
        let Err(err) = resolve_queues(&["some-other-queue".to_string()]) else {
            panic!("an unknown queue must be rejected");
        };
        assert!(
            err.to_string().contains("some-other-queue"),
            "unknown-queue error did not name the bad queue: {err}"
        );
    }

    /// Constructs a `WorkerContext` literal directly, bypassing `build` and its
    /// `[global.job_queue]` requirement; the `TempDir` keeps the store alive.
    fn worker_context() -> (WorkerContext, TempDir) {
        metrics_provider::init_for_tests();
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_str().unwrap();

        let storage: Arc<dyn ObjectStore> = Arc::new(StorageFsBackend::builder(root).build());
        let metadata_store = Arc::new(
            MetadataStore::builder(storage.clone())
                .link_cache_ttl(0)
                .build(),
        );
        let blob_store = Arc::new(BlobStore::new(storage.clone(), None));
        let repositories = Arc::new(RepositoryResolver::new(Arc::new(HashMap::new())).unwrap());

        let registry = Registry::new(
            blob_store.clone(),
            metadata_store.clone(),
            repositories.clone(),
            RegistryConfig {
                job_queue: Some(Arc::new(JobStore::new(storage.clone(), "worker-test"))),
                ..RegistryConfig::default()
            },
        );
        let context = WorkerContext {
            retry_policy: JobRetryPolicy::default(),
            storage,
            blob_store,
            metadata_store,
            repositories,
            registry,
        };
        (context, dir)
    }

    /// The handler is an opaque `Arc<dyn JobHandler>`, so the binding is
    /// asserted via each handler rejecting a foreign job kind.
    #[tokio::test]
    async fn components_for_binds_replication_queue_to_replication_handler() {
        let (context, _dir) = worker_context();

        let cache_envelope = JobEnvelope::new(
            Queue::Cache,
            CACHE_FETCH_BLOB_KIND,
            "lock",
            &serde_json::json!({}),
        )
        .unwrap();
        let replication_handler = context.components_for(Queue::Replication).handler;
        let err = replication_handler
            .execute(&cache_envelope)
            .await
            .expect_err("replication handler must reject a cache job kind");
        assert!(
            err.to_string().contains("unsupported job kind"),
            "replication queue bound to the wrong handler: {err}"
        );
    }

    #[tokio::test]
    async fn components_for_binds_cache_queue_to_cache_handler() {
        let (context, _dir) = worker_context();

        let replication_envelope = JobEnvelope::new(
            Queue::Replication,
            REPLICATION_PUSH_MANIFEST_KIND,
            "lock",
            &serde_json::json!({}),
        )
        .unwrap();
        let cache_handler = context.components_for(Queue::Cache).handler;
        let err = cache_handler
            .execute(&replication_envelope)
            .await
            .expect_err("cache handler must reject a replication job kind");
        assert!(
            err.to_string().contains("unsupported job kind"),
            "cache queue bound to the wrong handler: {err}"
        );
    }

    #[tokio::test]
    async fn components_for_mints_a_fresh_consumer_per_call() {
        let (context, _dir) = worker_context();
        let a = context.components_for(Queue::Cache).consumer;
        let b = context.components_for(Queue::Replication).consumer;
        assert!(
            !Arc::ptr_eq(&a, &b),
            "each queue must get its own JobStore consumer"
        );
    }
}
