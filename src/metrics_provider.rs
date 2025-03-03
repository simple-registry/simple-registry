use crate::configuration;
use lazy_static::lazy_static;
use opentelemetry::metrics::{Counter, Gauge, Histogram, MeterProvider};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{Encoder, Registry as PrometheusRegistry, TextEncoder};
use std::sync::atomic::AtomicU64;
use tracing::error;

lazy_static! {
    pub static ref IN_FLIGHT_REQUESTS: AtomicU64 = AtomicU64::new(0);
    pub static ref METRICS_PROVIDER: MetricsProvider = MetricsProvider::new().unwrap_or_else(|e| {
        error!("Unable to create metrics provider: {}", e);
        std::process::exit(1);
    });
}

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
            .map_err(|e| {
                error!("Unable to create Prometheus exporter: {}", e);
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
