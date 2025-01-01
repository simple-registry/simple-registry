#![forbid(unsafe_code)]
use crate::cmd::{Scrub, ScrubOptions, Server};
use clap::{ArgAction, Command};
use cmd::CommandError;
use notify::{recommended_watcher, Event, RecommendedWatcher, RecursiveMode, Watcher};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_sdk::trace::{BatchConfig, RandomIdGenerator, Sampler, TracerProvider};
use opentelemetry_sdk::{runtime, Resource};
use opentelemetry_semantic_conventions::{
    attribute::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_NAME, SERVICE_VERSION},
    SCHEMA_URL,
};
use opentelemetry_stdout as stdout;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::{error, info};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter};

mod cmd;
mod configuration;
mod error;
mod lock_manager;
mod oci;
mod policy;
mod registry;
mod storage;

use crate::configuration::Configuration;

const DEFAULT_CONFIG_PATH: &str = "config.toml";

fn get_config_path_from_matches(matches: &clap::ArgMatches) -> String {
    matches
        .get_one::<String>("config")
        .cloned()
        .unwrap_or(DEFAULT_CONFIG_PATH.to_string())
}

pub fn set_tracing(config: &Configuration) {
    let _ = TracerProvider::builder()
        .with_simple_exporter(stdout::SpanExporter::default())
        .build();

    let resource = Resource::from_schema_url(
        [
            KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
            KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
            KeyValue::new(DEPLOYMENT_ENVIRONMENT_NAME, "develop"),
        ],
        SCHEMA_URL,
    );

    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer());

    if let Some(observability_config) = &config.observability {
        if let Some(tracing_config) = &observability_config.tracing {
            let provider = opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_trace_config(
                    opentelemetry_sdk::trace::Config::default()
                        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                            tracing_config.sampling_rate,
                        ))))
                        .with_id_generator(RandomIdGenerator::default())
                        .with_resource(resource),
                )
                .with_batch_config(BatchConfig::default())
                .with_exporter(opentelemetry_otlp::new_exporter().tonic())
                .install_batch(runtime::Tokio)
                .unwrap();

            global::set_tracer_provider(provider.clone());
            let tracer = provider.tracer("tracing-otel-subscriber");

            info!(
                "Enabled tracing with sampling rate: {}",
                tracing_config.sampling_rate
            );

            subscriber.with(OpenTelemetryLayer::new(tracer)).init();

            return;
        };
    };

    subscriber.init();
}

pub fn set_watcher_path(watcher: &mut RecommendedWatcher, path: &str) -> Result<(), CommandError> {
    watcher.watch(Path::new(path), RecursiveMode::Recursive)?;

    info!("Watching for changes to {}", path);
    Ok(())
}

pub fn set_tls_watcher_paths(
    watcher: &mut RecommendedWatcher,
    config: &Configuration,
    paths: Arc<RwLock<Vec<String>>>,
) -> Result<(), CommandError> {
    let mut paths = match paths.write() {
        Ok(paths) => paths,
        Err(err) => {
            error!("Failed to acquire write lock on TLS watched paths: {}", err);
            return Err(CommandError::ConfigurationError(
                "Failed to acquire write lock on TLS watched paths".to_string(),
            ));
        }
    };

    for path in paths.iter() {
        watcher.watch(Path::new(path), RecursiveMode::Recursive)?;

        info!("Watching for changes to {}", path);
    }

    paths.clear();
    if let Some(tls) = config.server.tls.as_ref() {
        set_watcher_path(watcher, tls.server_certificate_bundle.as_str())?;
        paths.push(tls.server_certificate_bundle.clone());

        set_watcher_path(watcher, tls.server_private_key.as_str())?;
        paths.push(tls.server_private_key.clone());

        if let Some(client_ca_bundle) = tls.client_ca_bundle.as_ref() {
            set_watcher_path(watcher, client_ca_bundle.as_str())?;
            paths.push(client_ca_bundle.clone());
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), CommandError> {
    let matches = Command::new("origin")
        .about("An OCI-compliant container registry")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("scrub")
                .about("Check the registry storage engine for inconsistencies and fix them")
                .arg(
                    clap::Arg::new("config")
                        .short('c')
                        .long("config")
                        .value_name("FILE")
                        .help("Sets a custom configuration file"),
                )
                .arg(
                    clap::Arg::new("auto-fix")
                        .short('f')
                        .long("auto-fix")
                        .action(ArgAction::SetTrue)
                        .help("Automatically fix any inconsistencies found"),
                ),
        )
        .subcommand(
            Command::new("serve")
                .about("Start the registry server")
                .arg(
                    clap::Arg::new("config")
                        .short('c')
                        .long("config")
                        .value_name("FILE")
                        .help("Sets a custom configuration file"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("scrub", scrub_matches)) => {
            let config_path = get_config_path_from_matches(scrub_matches);
            let config = Configuration::load(&config_path)?;

            set_tracing(&config);

            let scrub_options = ScrubOptions::from_matches(scrub_matches);

            let scrub = Scrub::try_from_config(&config, &scrub_options)?;
            scrub.run().await
        }
        Some(("serve", run_matches)) => {
            let config_path = get_config_path_from_matches(run_matches);
            let config = Configuration::load(&config_path)?;

            set_tracing(&config);

            let tls_watched_paths: Vec<String> = Vec::new();
            let tls_watched_paths = Arc::new(RwLock::new(tls_watched_paths));

            let server = Arc::new(Server::try_from_config(&config)?);

            let server_watcher = server.clone();
            let config_watcher_path = config_path.clone();
            let mut config_watcher = recommended_watcher(move |event: notify::Result<Event>| {
                let server = server_watcher.clone();
                let config_path = config_watcher_path.clone();
                let Ok(event) = event else {
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

                    if let Err(err) = server.notify_config_change(&config) {
                        error!("Failed to notify server of configuration change: {}", err);
                    } else {
                        info!("Server notified of configuration change");
                    }
                }
            })?;
            set_watcher_path(&mut config_watcher, config_path.as_str())?;
            set_tls_watcher_paths(&mut config_watcher, &config, tls_watched_paths)?;

            server.run().await
        }
        _ => unreachable!(),
    }
}
