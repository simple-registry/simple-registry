use std::{collections::HashMap, sync::Arc};

use tracing::info;

use angos_s3_client::Backend as S3HttpBackend;
use angos_storage::{
    ObjectStore, fs::Backend as StorageFsBackend, s3::Backend as StorageS3Backend,
};

use crate::{
    cache::{self, Cache},
    configuration::{Configuration, ResolvedStorageConfig},
    event_webhook::{self, dispatcher::EventDispatcher},
    jobs::store::{self as job_store, JobStore},
    registry::{
        self, Registry, RegistryConfig, Repository,
        blob_store::BlobStore,
        metadata_store::MetadataStore,
        repository,
        repository_resolver::{OverlapError, RepositoryResolver},
    },
};

/// Errors produced by the shared CLI bootstrap helpers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage backend failed: {0}")]
    StorageBackend(String),
    #[error("failed to initialize cache: {0}")]
    Cache(#[from] cache::Error),
    #[error("failed to initialize repository '{name}': {source}")]
    Repository {
        name: String,
        source: Box<registry::Error>,
    },
    #[error("repository configuration is invalid: {0}")]
    Overlap(#[from] OverlapError),
    #[error("failed to initialize job queue: {0}")]
    JobQueue(#[from] job_store::Error),
    #[error("failed to initialize event webhooks: {0}")]
    EventWebhook(#[from] event_webhook::Error),
    #[error("failed to initialize registry: {0}")]
    Registry(#[from] registry::Error),
}

impl From<angos_storage::Error> for Error {
    fn from(e: angos_storage::Error) -> Self {
        Error::StorageBackend(e.to_string())
    }
}

impl From<angos_s3_client::Error> for Error {
    fn from(e: angos_s3_client::Error) -> Self {
        Error::StorageBackend(e.to_string())
    }
}

/// Build the object store shared by the metadata store and the job store.
pub fn build_object_store(config: &ResolvedStorageConfig) -> Result<Arc<dyn ObjectStore>, Error> {
    let object: Arc<dyn ObjectStore> = match config {
        ResolvedStorageConfig::FS(config) => {
            info!("Using filesystem storage backend");
            Arc::new(
                StorageFsBackend::builder(&config.root_dir)
                    .sync_to_disk(config.sync_to_disk)
                    .build(),
            )
        }
        ResolvedStorageConfig::S3(config) => {
            info!("Using S3 storage backend");
            let http = S3HttpBackend::new(&config.connection.to_client_config())?;
            Arc::new(StorageS3Backend::builder(Arc::new(http)).build())
        }
    };

    Ok(object)
}

pub fn metadata_store(
    config: &ResolvedStorageConfig,
    auth_cache: &Arc<Cache>,
    namespace_walk_concurrency: usize,
    gc_grace_secs: u64,
) -> Result<Arc<MetadataStore>, Error> {
    let store = build_object_store(config)?;

    let (link_cache_ttl, access_time_debounce_secs) =
        if let ResolvedStorageConfig::S3(s3_cfg) = config {
            (s3_cfg.link_cache_ttl, s3_cfg.access_time_debounce_secs)
        } else {
            (0, 0)
        };

    let mut builder = MetadataStore::builder(store)
        .link_cache_ttl(link_cache_ttl)
        .access_time_debounce_secs(access_time_debounce_secs)
        .namespace_walk_concurrency(namespace_walk_concurrency)
        .gc_grace_secs(gc_grace_secs);

    // Wire in the auth cache for link-metadata caching (only meaningful on S3,
    // where link_cache_ttl > 0 by default).
    builder = builder.cache(auth_cache.clone());

    Ok(Arc::new(builder.build()))
}

/// The storage and repository handles every maintenance command (`prune`,
/// `replicate`, `scrub`, `worker`) boots with.
pub struct MaintenanceContext {
    pub blob_store: Arc<BlobStore>,
    pub metadata_store: Arc<MetadataStore>,
    pub repositories: Arc<RepositoryResolver>,
}

/// Build the shared maintenance-command context: auth cache, blob backend,
/// metadata store, and the resolved repositories, in the one canonical order.
pub async fn maintenance_context(config: &Configuration) -> Result<MaintenanceContext, Error> {
    let auth_cache = auth_cache(&config.cache)?;
    let blob_store = Arc::new(
        config
            .blob_store
            .build_backend()?
            .with_namespace_walk_concurrency(config.global.namespace_walk_concurrency),
    );
    let metadata_store = metadata_store(
        &config.resolve_registry_storage(),
        &auth_cache,
        config.global.namespace_walk_concurrency,
        config.global.gc_grace_secs,
    )?;
    let repositories = repositories(
        &config.repository,
        &auth_cache,
        config.global.max_manifest_size_bytes(),
    )
    .await?;
    Ok(MaintenanceContext {
        blob_store,
        metadata_store,
        repositories,
    })
}

pub fn auth_cache(config: &cache::Config) -> Result<Arc<Cache>, Error> {
    config.to_backend().map_err(Error::from)
}

/// Registry over the shared stores, with webhooks wired from configuration
/// and a caller-held job queue so no in-process drain loops are spawned.
/// Used by the maintenance and worker commands; the server wires its own
/// queue choice in `server setup`.
pub fn registry(
    config: &Configuration,
    blob_store: Arc<BlobStore>,
    metadata_store: Arc<MetadataStore>,
    resolver: Arc<RepositoryResolver>,
    job_store: Arc<JobStore>,
) -> Result<Arc<Registry>, Error> {
    let dispatcher = EventDispatcher::from_config(&config.event_webhook)?;
    let registry = Registry::new(
        blob_store,
        metadata_store,
        resolver,
        RegistryConfig {
            job_queue: Some(job_store),
            event_dispatcher: dispatcher,
            ..RegistryConfig::default()
        },
    );
    Ok(registry)
}

pub async fn repository(
    name: &str,
    config: &repository::Config,
    auth_cache: &Arc<Cache>,
    max_manifest_size_bytes: usize,
) -> Result<Repository, Error> {
    Repository::new(name, config, auth_cache, max_manifest_size_bytes)
        .await
        .map_err(|source| Error::Repository {
            name: name.to_string(),
            source: Box::new(source),
        })
}

pub async fn repositories(
    configs: &HashMap<String, repository::Config>,
    auth_cache: &Arc<Cache>,
    max_manifest_size_bytes: usize,
) -> Result<Arc<RepositoryResolver>, Error> {
    let mut map = HashMap::with_capacity(configs.len());
    for (name, config) in configs {
        map.insert(
            name.clone(),
            repository(name, config, auth_cache, max_manifest_size_bytes).await?,
        );
    }
    let resolver = RepositoryResolver::new(Arc::new(map))?;
    Ok(Arc::new(resolver))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        cache,
        command::bootstrap::{self, Error, auth_cache, repositories},
        command::maintenance::Error as MaintenanceError,
        command::server::Error as ServerError,
        policy::{AccessMode, AccessPolicyConfig},
        registry::{self, manifest::DEFAULT_MAX_MANIFEST_SIZE_BYTES, repository},
    };

    #[test]
    fn auth_cache_memory_succeeds() {
        let config = cache::Config::Memory;
        let result = auth_cache(&config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn repository_with_default_config_succeeds() {
        let repo_config = repository::Config {
            access_policy: Some(AccessPolicyConfig {
                default: AccessMode::Allow,
                ..AccessPolicyConfig::default()
            }),
            ..repository::Config::default()
        };
        let cache = auth_cache(&cache::Config::Memory).unwrap();
        let result = bootstrap::repository(
            "test-repo",
            &repo_config,
            &cache,
            DEFAULT_MAX_MANIFEST_SIZE_BYTES,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "test-repo");
    }

    #[tokio::test]
    async fn repositories_empty_map_succeeds() {
        let configs = HashMap::new();
        let cache = auth_cache(&cache::Config::Memory).unwrap();
        let result = repositories(&configs, &cache, DEFAULT_MAX_MANIFEST_SIZE_BYTES).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn repositories_overlapping_prefixes_fails() {
        let mut configs = HashMap::new();
        configs.insert(
            "team".to_string(),
            repository::Config {
                access_policy: Some(AccessPolicyConfig {
                    default: AccessMode::Allow,
                    ..AccessPolicyConfig::default()
                }),
                ..repository::Config::default()
            },
        );
        configs.insert(
            "team/app".to_string(),
            repository::Config {
                access_policy: Some(AccessPolicyConfig {
                    default: AccessMode::Allow,
                    ..AccessPolicyConfig::default()
                }),
                ..repository::Config::default()
            },
        );
        let cache = auth_cache(&cache::Config::Memory).unwrap();
        let result = repositories(&configs, &cache, DEFAULT_MAX_MANIFEST_SIZE_BYTES).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Overlap(_)));
    }

    #[test]
    fn error_registry_converts_from_registry_error() {
        let err: Error = registry::Error::BlobUnknown.into();
        assert!(matches!(err, Error::Registry(_)));
    }

    #[test]
    fn error_cache_converts_from_cache_error() {
        let inner = cache::Error::Execution("backend down".to_string());
        let err: Error = inner.into();
        assert!(matches!(err, Error::Cache(_)));
    }

    #[test]
    fn error_into_maintenance_error_registry_variant() {
        let bootstrap_err: Error = registry::Error::BlobUnknown.into();
        let maintenance_err: MaintenanceError = bootstrap_err.into();
        assert!(matches!(maintenance_err, MaintenanceError::Registry(_)));
    }

    #[test]
    fn error_into_maintenance_error_cache_variant() {
        let bootstrap_err: Error = cache::Error::Execution("x".to_string()).into();
        let maintenance_err: MaintenanceError = bootstrap_err.into();
        assert!(matches!(maintenance_err, MaintenanceError::Cache(_)));
    }

    #[test]
    fn error_into_server_error_registry_variant() {
        let bootstrap_err: Error = registry::Error::BlobUnknown.into();
        let server_err: ServerError = bootstrap_err.into();
        assert!(matches!(server_err, ServerError::Initialization(_)));
    }
}
