#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

use crate::command::{argon, scrub, server};
use crate::configuration::registry::create_registry;
use crate::configuration::watcher::ConfigWatcher;
use crate::configuration::{Configuration, ObservabilityConfig};
use crate::registry::server::ServerContext;
use argh::FromArgs;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use std::sync::Arc;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter};

mod command;
mod configuration;
mod metrics_provider;
mod registry;

fn set_tracing(config: Option<ObservabilityConfig>) -> Result<(), configuration::Error> {
    if let Some(ObservabilityConfig {
        tracing: Some(tracing_config),
    }) = config
    {
        let resource = Resource::builder()
            .with_service_name(env!("CARGO_PKG_NAME"))
            .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
            .build();
        let otlp_exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&tracing_config.endpoint)
            .with_timeout(std::time::Duration::from_secs(10))
            .build()?;

        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(otlp_exporter)
            .with_id_generator(RandomIdGenerator::default())
            .with_resource(resource)
            .with_sampler(Sampler::TraceIdRatioBased(tracing_config.sampling_rate))
            .build();

        let tracer = tracer_provider.tracer("simple-registry");
        let _ = global::set_tracer_provider(tracer_provider);
        let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

        let _ = tracing_subscriber::registry()
            .with(EnvFilter::from_default_env())
            .with(tracing_subscriber::fmt::layer().json())
            .with(telemetry)
            .try_init();
    } else {
        let _ = tracing_subscriber::registry()
            .with(EnvFilter::from_default_env())
            .with(tracing_subscriber::fmt::layer().json())
            .try_init();
    }
    Ok(())
}

#[derive(FromArgs, PartialEq, Debug)]
/// An OCI-compliant and docker-compatible registry service
struct GlobalArguments {
    #[argh(option, short = 'c', default = "String::from(\"config.toml\")")]
    /// the path to the configuration file, defaults to `config.toml`
    config: String,

    #[argh(subcommand)]
    subcommand: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Argon(argon::Options),
    Scrub(scrub::Options),
    Serve(server::Options),
}

fn main() -> Result<(), command::Error> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli_args: GlobalArguments = argh::from_env();

    let config = Configuration::load(&cli_args.config)?;

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.global.max_concurrent_requests)
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime")
        .block_on(run_command(cli_args, config))
}

async fn run_command(
    cli_args: GlobalArguments,
    config: Configuration,
) -> Result<(), command::Error> {
    set_tracing(config.observability.clone())?;

    let oidc_validators = ServerContext::build_oidc_validators(&config.auth.oidc, &config.cache)?;
    let registry = create_registry(&config)?;

    match cli_args.subcommand {
        SubCommand::Argon(_) => argon::Command::run(),
        SubCommand::Scrub(scrub_options) => {
            let scrub = scrub::Command::new(&scrub_options, registry);
            scrub.run().await
        }
        SubCommand::Serve(_) => {
            let server = Arc::new(server::Command::new(
                &config.server,
                &config.auth.identity,
                registry,
                oidc_validators,
            )?);

            let _watcher = ConfigWatcher::new(&cli_args.config, server.clone())?;
            server.run().await
        }
    }
}
