use crate::configuration;
use opentelemetry::metrics::{Counter, Gauge, Histogram, MeterProvider};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{Encoder, Registry as PrometheusRegistry, TextEncoder};
use std::sync::atomic::AtomicU64;
use std::sync::LazyLock;
use tracing::error;

pub static IN_FLIGHT_REQUESTS: AtomicU64 = AtomicU64::new(0);
pub static METRICS_PROVIDER: LazyLock<MetricsProvider> = LazyLock::new(|| {
    MetricsProvider::new().unwrap_or_else(|error| {
        error!("Unable to create metrics provider: {error}");
        std::process::exit(1);
    })
});

pub struct MetricsProvider {
    registry: PrometheusRegistry,
    #[allow(dead_code)]
    provider: SdkMeterProvider,
    pub metric_http_request_total: Counter<u64>,
    pub metric_http_request_duration: Histogram<f64>,
    pub metric_http_request_in_flight: Gauge<u64>,
}

impl MetricsProvider {
    pub fn new() -> Result<Self, configuration::Error> {
        let registry = PrometheusRegistry::new();
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .without_scope_info()
            .without_target_info()
            .build()
            .map_err(|error| {
                error!("Unable to create Prometheus exporter: {error}");
                configuration::Error::Http(String::from("Unable to create Prometheus exporter"))
            })?;

        let provider = SdkMeterProvider::builder().with_reader(exporter).build();

        let metrics_meter = provider.meter(env!("CARGO_PKG_NAME"));

        let metric_http_request_total = metrics_meter
            .u64_counter("http_requests")
            .with_description("Total number of HTTP requests made.")
            .build();

        let metric_http_request_duration = metrics_meter
            .f64_histogram("http_request_duration")
            .with_unit("ms")
            .with_description("The HTTP request latencies in milliseconds.")
            .build();

        let metric_http_request_in_flight = metrics_meter
            .u64_gauge("http_requests_in_flight")
            .with_description("The current number of in-flight HTTP requests.")
            .build();

        Ok(Self {
            registry,
            provider,
            metric_http_request_total,
            metric_http_request_duration,
            metric_http_request_in_flight,
        })
    }

    pub fn gather(&self) -> (String, Vec<u8>) {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        (encoder.format_type().to_string(), buffer)
    }
}
