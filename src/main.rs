#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

use crate::command::{argon, scrub, server};
use crate::configuration::{
    BlobStorageConfig, Configuration, Error, LockStoreConfig, MetadataStoreConfig,
    ObservabilityConfig, ServerTlsConfig,
};
use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::{blob_store, metadata_store, Registry};
use argh::FromArgs;
use notify::{recommended_watcher, Event, RecommendedWatcher, RecursiveMode, Watcher};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use opentelemetry_semantic_conventions::attribute::SERVICE_VERSION;
use opentelemetry_stdout as stdout;
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter};

mod command;
mod configuration;
mod metrics_provider;
mod registry;

fn set_tracing(config: Option<ObservabilityConfig>) -> Result<(), Error> {
    let _ = SdkTracerProvider::builder()
        .with_simple_exporter(stdout::SpanExporter::default())
        .build();

    let resource = Resource::builder()
        .with_service_name(env!("CARGO_PKG_NAME"))
        .with_attribute(KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")))
        .build();

    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().json());

    if let Some(observability_config) = config {
        if let Some(tracing_config) = observability_config.tracing {
            let sampling_rate = tracing_config.sampling_rate;
            let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(sampling_rate)));

            let endpoint = tracing_config.endpoint;
            let exporter = SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()?;

            let provider = SdkTracerProvider::builder()
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(resource)
                .with_sampler(sampler)
                .with_batch_exporter(exporter)
                .build();

            let tracer = provider.tracer(env!("CARGO_PKG_NAME"));
            global::set_tracer_provider(provider);

            subscriber.with(OpenTelemetryLayer::new(tracer)).init();

            info!(
                "Enabled tracing with sampling rate: {}",
                tracing_config.sampling_rate
            );

            return Ok(());
        }
    }

    subscriber.init();
    Ok(())
}

fn set_config_watcher<B: BlobStore + 'static, M: MetadataStore + 'static>(
    blob_store: Arc<B>,
    metadata_store: Arc<M>,
    config_path: &str,
    tls_config: Option<ServerTlsConfig>,
    server: &Arc<server::Command<B, M>>,
) -> Result<RecommendedWatcher, command::Error> {
    info!("Setting up file system watcher for configuration file");
    let server_watcher = server.clone();
    let config_watcher_path = config_path.to_string();
    let mut config_watcher = recommended_watcher(move |event: notify::Result<Event>| {
        info!("Configuration file changed");
        let server = server_watcher.clone();
        let config_path = config_watcher_path.clone();
        let Ok(event) = event else {
            error!("Failed to watch configuration file: {event:?}");
            return;
        };

        if event.kind.is_modify() {
            let config = match Configuration::load(config_path) {
                Ok(config) => config,
                Err(error) => {
                    error!("Failed to reload configuration: {error}");
                    return;
                }
            };

            let registry = match Registry::new(
                blob_store.clone(),
                metadata_store.clone(),
                config.repository,
                &config.global,
                config.cache_store,
            ) {
                Ok(registry) => registry,
                Err(error) => {
                    error!("Failed to create registry with new configuration: {error}");
                    return;
                }
            };

            if let Err(error) =
                server.notify_config_change(config.server, &config.identity, registry)
            {
                error!("Failed to notify server of configuration change: {error}");
            } else {
                info!("Server notified of configuration change");
            }
        }
    })?;

    config_watcher.watch(Path::new(&config_path), RecursiveMode::NonRecursive)?;

    if let Some(tls_config) = tls_config {
        config_watcher.watch(
            Path::new(&tls_config.server_certificate_bundle),
            RecursiveMode::NonRecursive,
        )?;
        config_watcher.watch(
            Path::new(&tls_config.server_private_key),
            RecursiveMode::NonRecursive,
        )?;
        if let Some(client_ca) = tls_config.client_ca_bundle {
            config_watcher.watch(Path::new(&client_ca), RecursiveMode::NonRecursive)?;
        }
    }

    Ok(config_watcher)
}

#[derive(FromArgs, PartialEq, Debug)]
/// An OCI-compliant and docker-compatible registry service
struct GlobalArguments {
    #[argh(
        option,
        short = 'c',
        default = "GlobalArguments::default_config_path()"
    )]
    /// the path to the configuration file, defaults to `config.toml`
    config: String,

    #[argh(subcommand)]
    nested: SubCommand,
}

impl GlobalArguments {
    fn default_config_path() -> String {
        "config.toml".to_string()
    }
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Argon(argon::Options),
    Scrub(scrub::Options),
    Serve(server::Options),
}

fn main() -> Result<(), command::Error> {
    let arguments: GlobalArguments = argh::from_env();
    let config = Configuration::load(&arguments.config)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.global.max_concurrent_requests)
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        set_tracing(config.observability.clone())?;

        // Normalize metadata store configuration based on blob store type
        let metadata_config = normalize_metadata_config(&config.blob_store, &config.metadata_store);

        match (&config.blob_store, &metadata_config) {
            (BlobStorageConfig::FS(blob_cfg), MetadataStoreConfig::FS(meta_cfg)) => {
                info!("Using filesystem blob-store and metadata-store backends");
                let blob_store = Arc::new(blob_store::fs::Backend::new(blob_cfg.clone()));
                let metadata_store = Arc::new(metadata_store::fs::Backend::new(meta_cfg.clone())?);
                handle_command(config, arguments, blob_store, metadata_store).await
            }
            (BlobStorageConfig::FS(blob_cfg), MetadataStoreConfig::S3(meta_cfg)) => {
                info!("Using filesystem blob-store and S3 metadata-store backends");
                let blob_store = Arc::new(blob_store::fs::Backend::new(blob_cfg.clone()));
                let metadata_store = Arc::new(metadata_store::s3::Backend::new(meta_cfg.clone())?);
                handle_command(config, arguments, blob_store, metadata_store).await
            }
            (BlobStorageConfig::S3(blob_cfg), MetadataStoreConfig::FS(meta_cfg)) => {
                info!("Using S3 blob-store and filesystem metadata-store backends");
                let blob_store = Arc::new(blob_store::s3::Backend::new(blob_cfg.clone()));
                let metadata_store = Arc::new(metadata_store::fs::Backend::new(meta_cfg.clone())?);
                handle_command(config, arguments, blob_store, metadata_store).await
            }
            (BlobStorageConfig::S3(blob_cfg), MetadataStoreConfig::S3(meta_cfg)) => {
                info!("Using S3 blob-store and metadata-store backends");
                let blob_store = Arc::new(blob_store::s3::Backend::new(blob_cfg.clone()));
                let metadata_store = Arc::new(metadata_store::s3::Backend::new(meta_cfg.clone())?);
                handle_command(config, arguments, blob_store, metadata_store).await
            }
        }
    })
}

fn normalize_metadata_config(
    blob_config: &BlobStorageConfig,
    metadata_config: &MetadataStoreConfig,
) -> MetadataStoreConfig {
    match (blob_config, metadata_config) {
        // FS blob store with unconfigured FS metadata store - inherit root_dir
        (BlobStorageConfig::FS(blob_cfg), MetadataStoreConfig::FS(meta_cfg))
            if meta_cfg.root_dir.is_empty() =>
        {
            MetadataStoreConfig::FS(metadata_store::fs::BackendConfig {
                root_dir: blob_cfg.root_dir.clone(),
                lock_store: LockStoreConfig::default(),
            })
        }

        // S3 blob store with default FS metadata store - use S3 metadata store instead
        (BlobStorageConfig::S3(blob_cfg), MetadataStoreConfig::FS(meta_cfg))
            if meta_cfg.root_dir.is_empty() =>
        {
            info!("Auto-configuring S3 metadata-store from blob-store");
            MetadataStoreConfig::S3(metadata_store::s3::BackendConfig {
                bucket: blob_cfg.bucket.clone(),
                region: blob_cfg.region.clone(),
                endpoint: blob_cfg.endpoint.clone(),
                access_key_id: blob_cfg.access_key_id.clone(),
                secret_key: blob_cfg.secret_key.clone(),
                key_prefix: blob_cfg.key_prefix.clone(),
                lock_store: LockStoreConfig::default(),
            })
        }

        // S3 blob store with unconfigured S3 metadata store - inherit S3 config
        (BlobStorageConfig::S3(blob_cfg), MetadataStoreConfig::S3(meta_cfg))
            if meta_cfg.bucket.is_empty() =>
        {
            MetadataStoreConfig::S3(metadata_store::s3::BackendConfig {
                bucket: blob_cfg.bucket.clone(),
                region: blob_cfg.region.clone(),
                endpoint: blob_cfg.endpoint.clone(),
                access_key_id: blob_cfg.access_key_id.clone(),
                secret_key: blob_cfg.secret_key.clone(),
                key_prefix: blob_cfg.key_prefix.clone(),
                lock_store: LockStoreConfig::default(),
            })
        }

        // All other cases - use as configured
        _ => metadata_config.clone(),
    }
}

async fn handle_command<B: BlobStore + 'static, M: MetadataStore + 'static>(
    config: Configuration,
    arguments: GlobalArguments,
    data_store: Arc<B>,
    metadata_store: Arc<M>,
) -> Result<(), command::Error> {
    let registry = Registry::new(
        data_store.clone(),
        metadata_store.clone(),
        config.repository,
        &config.global,
        config.cache_store,
    )?;

    match arguments.nested {
        SubCommand::Argon(_) => argon::Command::run(),
        SubCommand::Scrub(scrub_options) => {
            let scrub = scrub::Command::new(&scrub_options, registry);
            scrub.run().await
        }
        SubCommand::Serve(_) => {
            let server = Arc::new(server::Command::new(
                &config.server,
                &config.identity,
                registry,
            )?);

            let _ = set_config_watcher(
                data_store,
                metadata_store,
                &arguments.config,
                config.server.tls,
                &server,
            )?;
            server.run().await
        }
    }
}
