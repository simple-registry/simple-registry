#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

use crate::command::{scrub, server};
use crate::configuration::{
    CacheStoreConfig, Configuration, DataStoreConfig, Error, ObservabilityConfig, RepositoryConfig,
    ServerTlsConfig,
};
use crate::registry::cache_store::CacheStore;
use crate::registry::data_store::{DataStore, FSBackend, S3Backend};
use crate::registry::lock_store::LockStore;
use crate::registry::Registry;
use argh::FromArgs;
use notify::{recommended_watcher, Event, RecommendedWatcher, RecursiveMode, Watcher};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use opentelemetry_semantic_conventions::attribute::SERVICE_VERSION;
use opentelemetry_stdout as stdout;
use std::collections::HashMap;
use std::mem;
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info};
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
        .with(tracing_subscriber::fmt::layer());

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
        };
    };

    subscriber.init();
    Ok(())
}

fn set_fs_watcher<D: DataStore + 'static>(
    data_store: Arc<D>,
    config_path: &str,
    tls_config: Option<ServerTlsConfig>,
    server: &Arc<server::Command<D>>,
) -> Result<RecommendedWatcher, command::Error> {
    info!("Setting up file system watcher for configuration file");
    let server_watcher = server.clone();
    let config_watcher_path = config_path.to_string();
    let mut config_watcher = recommended_watcher(move |event: notify::Result<Event>| {
        info!("Configuration file changed");
        let server = server_watcher.clone();
        let config_path = config_watcher_path.clone();
        let Ok(event) = event else {
            error!("Failed to watch configuration file: {:?}", event);
            return;
        };

        if event.kind.is_modify() {
            let config = match Configuration::load(config_path) {
                Ok(config) => config,
                Err(err) => {
                    error!("Failed to reload configuration: {}", err);
                    return;
                }
            };

            let registry =
                match build_registry(config.cache_store, config.repository, data_store.clone()) {
                    Ok(registry) => registry,
                    Err(err) => {
                        error!("Failed to create registry with new configuration: {}", err);
                        return;
                    }
                };

            if let Err(err) = server.notify_config_change(config.server, &config.identity, registry)
            {
                error!("Failed to notify server of configuration change: {}", err);
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

fn build_registry<D: DataStore>(
    cache_config: CacheStoreConfig,
    repository_config: HashMap<String, RepositoryConfig>,
    data_store: Arc<D>,
) -> Result<Registry<D>, Error> {
    let cache_store = Arc::new(CacheStore::new(cache_config)?);

    Registry::new(repository_config, data_store, cache_store)
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
    Scrub(scrub::Options),
    Serve(server::Options),
}

fn main() -> Result<(), command::Error> {
    let arguments: GlobalArguments = argh::from_env();

    let mut config = Configuration::load(&arguments.config)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.max_concurrent_requests)
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        set_tracing(mem::take(&mut config.observability))?;
        let lock_store = LockStore::new(mem::take(&mut config.lock_store))?;

        match mem::take(&mut config.storage) {
            DataStoreConfig::FS(storage_config) => {
                info!("Using filesystem backend");
                let data_store = Arc::new(FSBackend::new(storage_config, lock_store));
                handle_command(config, arguments, data_store).await
            }
            DataStoreConfig::S3(storage_config) => {
                info!("Using S3 backend");
                let data_store = Arc::new(S3Backend::new(storage_config, lock_store));
                handle_command(config, arguments, data_store).await
            }
        }
    })
}

async fn handle_command<D: DataStore + 'static>(
    config: Configuration,
    arguments: GlobalArguments,
    data_store: Arc<D>,
) -> Result<(), command::Error> {
    let registry = build_registry(config.cache_store, config.repository, data_store.clone())?;

    match arguments.nested {
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

            let _watcher =
                set_fs_watcher(data_store, &arguments.config, config.server.tls, &server)?;
            server.run().await
        }
    }
}
