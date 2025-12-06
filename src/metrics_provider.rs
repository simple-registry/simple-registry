use std::sync::atomic::AtomicU64;
use std::sync::LazyLock;

use prometheus::{
    register_histogram_with_registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, register_int_gauge_with_registry,
};
use prometheus::{
    Encoder, Histogram, IntCounter, IntCounterVec, IntGauge, Registry as PrometheusRegistry,
    TextEncoder,
};
use tracing::error;

use crate::registry::Error;

pub static IN_FLIGHT_REQUESTS: AtomicU64 = AtomicU64::new(0);

pub static AUTH_ATTEMPTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        "auth_attempts_total",
        "Total number of authentication attempts",
        &["method", "result"],
        &METRICS_PROVIDER.registry
    )
    .expect("Failed to register auth_attempts metric")
});

pub static METRICS_PROVIDER: LazyLock<MetricsProvider> =
    LazyLock::new(|| MetricsProvider::new().expect("Unable to create metrics provider: {error}"));

pub struct MetricsProvider {
    registry: PrometheusRegistry,
    pub metric_http_request_total: IntCounter,
    pub metric_http_request_duration: Histogram,
    pub metric_http_request_in_flight: IntGauge,
}

impl MetricsProvider {
    pub fn new() -> Result<Self, Error> {
        let registry = PrometheusRegistry::new();

        let metric_http_request_total = register_int_counter_with_registry!(
            "http_requests_total",
            "Total number of HTTP requests made.",
            &registry
        )
        .map_err(|error| {
            error!("Unable to create http_requests_total metric: {error}");
            Error::Initialization(String::from("Unable to create http_requests_total metric"))
        })?;

        let metric_http_request_duration = register_histogram_with_registry!(
            "http_request_duration_ms",
            "The HTTP request latencies in milliseconds.",
            &registry
        )
        .map_err(|error| {
            error!("Unable to create http_request_duration metric: {error}");
            Error::Initialization(String::from(
                "Unable to create http_request_duration metric",
            ))
        })?;

        let metric_http_request_in_flight = register_int_gauge_with_registry!(
            "http_requests_in_flight",
            "The current number of in-flight HTTP requests.",
            &registry
        )
        .map_err(|error| {
            error!("Unable to create http_requests_in_flight metric: {error}");
            Error::Initialization(String::from(
                "Unable to create http_requests_in_flight metric",
            ))
        })?;

        Ok(Self {
            registry,
            metric_http_request_total,
            metric_http_request_duration,
            metric_http_request_in_flight,
        })
    }

    pub fn gather(&self) -> Result<(String, Vec<u8>), Error> {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(|error| Error::Internal(format!("Unable to encode metrics: {error}")))?;
        Ok((encoder.format_type().to_string(), buffer))
    }
}
