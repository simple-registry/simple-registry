use std::{sync::Arc, time::Duration};
use tracing::info;

use crate::{
    cache::Cache,
    command::{bootstrap, server::error::Error},
    configuration::{Configuration, RegistryStorageConfig, ResolvedStorageConfig},
    event_webhook::dispatcher::EventDispatcher,
    jobs::store::{self as job_store, JobStore, QueueDepthRefresh},
    registry::{Registry, RegistryConfig},
};

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

/// Build the runtime `Registry`. With `[global.job_queue]` the second element
/// carries what the server refreshes its queue-depth gauges from; draining the
/// queue stays `angos worker`'s job.
pub async fn build_registry(
    config: &Configuration,
    auth_cache: &Arc<Cache>,
) -> Result<(Arc<Registry>, Option<QueueDepthRefresh>), Error> {
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
        config.global.atime_audit_window_secs,
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

    // With [global.job_queue], cache-fill jobs route through the durable
    // backend so they survive restarts and `angos worker` can drain them.
    let pending = if let Some(jq_config) = &config.global.job_queue {
        let claim_mode = job_store::ensure_claim_support(metadata_store.object_store()).await?;
        let job_store: Arc<JobStore> = Arc::new(JobStore::alongside_with_retry_policy(
            &metadata_store,
            "server",
            claim_mode,
            jq_config.retry_policy(),
        ));
        registry_config.job_queue = Some(job_store.clone());
        Some(QueueDepthRefresh {
            store: job_store,
            period: Duration::from_secs(jq_config.pending_refresh_interval_secs),
            ready_horizon_secs: jq_config.pending_ready_horizon_secs,
        })
    } else {
        None
    };

    let registry = Registry::new(blob_backend, metadata_store, repositories, registry_config);

    Ok((registry, pending))
}
