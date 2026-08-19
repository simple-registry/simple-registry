use std::{sync::Arc, time::Duration};
use tracing::info;

use crate::{
    cache::Cache,
    command::{bootstrap, server::error::Error},
    configuration::{Configuration, RegistryStorageConfig, ResolvedStorageConfig},
    event_webhook::dispatcher::EventDispatcher,
    jobs::store::{self as job_store, JobStore},
    registry::{Registry, RegistryConfig},
};

/// Handle on the durable job-store and the interval the server should refresh
/// the `angos_job_queue_pending` gauge at. `None` when `[global.job_queue]`
/// is absent (in-process queue; no pending gauge is needed).
pub struct PendingGaugeRefresh {
    pub store: Arc<JobStore>,
    pub interval: Duration,
    pub ready_horizon_secs: u64,
}

/// Resolve the registry-storage config once per (re)build.
fn resolve_storage_config(config: &Configuration) -> ResolvedStorageConfig {
    let storage_config = config.resolve_registry_storage();
    if matches!(config.registry_storage, RegistryStorageConfig::Inherit)
        && matches!(&storage_config, ResolvedStorageConfig::S3(_))
    {
        info!("Auto-configuring S3 metadata-store from blob-store");
    }
    storage_config
}

/// Build the runtime `Registry`. When `[global.job_queue]` selects a durable
/// backend the second element carries the `JobStore` and the configured
/// pending-gauge refresh interval; the server spawns its own ticker from it.
/// The server never drains the queue itself: that is `angos worker`'s job.
pub async fn build_registry(
    config: &Configuration,
    auth_cache: &Arc<Cache>,
) -> Result<(Arc<Registry>, Option<PendingGaugeRefresh>), Error> {
    let blob_backend = Arc::new(
        config
            .blob_store
            .build_backend()?
            .with_namespace_walk_concurrency(config.global.namespace_walk_concurrency),
    );
    let storage_config = resolve_storage_config(config);
    let metadata_store = bootstrap::metadata_store(
        &storage_config,
        auth_cache,
        config.global.namespace_walk_concurrency,
        config.global.gc_grace_secs,
    )
    .map_err(Error::from)?;
    let max_manifest_size_bytes = config.global.max_manifest_size_bytes();
    let repositories =
        bootstrap::repositories(&config.repository, auth_cache, max_manifest_size_bytes).await?;

    let mut registry_config = RegistryConfig {
        update_pull_time: config.global.update_pull_time,
        enable_blob_redirect: config.global.enable_blob_redirect,
        enable_manifest_redirect: config.global.enable_manifest_redirect,
        max_manifest_size_bytes,
        max_blob_size_bytes: config.global.max_blob_size_bytes(),
        validate_manifest_references: !config.global.allow_missing_manifest_references,
        global_immutable_tags: config.global.immutable_tags,
        global_immutable_tags_exclusions: config.global.immutable_tags_exclusions.clone(),
        max_concurrent_cache_jobs: config.global.max_concurrent_cache_jobs,
        max_concurrent_replication_jobs: config.global.max_concurrent_replication_jobs,
        event_dispatcher: EventDispatcher::from_config(&config.event_webhook)?,
        ..RegistryConfig::default()
    };

    // When [global.job_queue] is present, route cache-fill jobs through the
    // durable backend (so they survive restarts and let `angos worker` drain
    // them) and surface the pending count on this server's /metrics for
    // autoscaling. The job store shares the metadata store's object store,
    // so no second backend is wired.
    let pending = if let Some(jq_config) = &config.global.job_queue {
        let storage = metadata_store.object_store().clone();
        job_store::ensure_claim_support(&storage).await?;
        let job_store: Arc<JobStore> = Arc::new(JobStore::with_retry_policy(
            storage,
            "server",
            jq_config.retry_policy(),
        ));
        registry_config.job_queue = Some(job_store.clone());
        Some(PendingGaugeRefresh {
            store: job_store,
            interval: Duration::from_secs(jq_config.pending_refresh_interval_secs),
            ready_horizon_secs: jq_config.pending_ready_horizon_secs,
        })
    } else {
        None
    };

    let registry = Registry::new(blob_backend, metadata_store, repositories, registry_config);

    Ok((registry, pending))
}
