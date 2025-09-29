#[cfg(test)]
mod tests;

use crate::registry::cache::Cache;
use crate::registry::error::Error;
use crate::registry::server::client_identity::ClientIdentity;
use crate::registry::server::route::Route;
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::request::Parts;
use hyper::http::HeaderMap;
use hyper::Uri;
use prometheus::{register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec};
use reqwest::redirect::Policy;
use reqwest::{Certificate, Client, Identity};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

static WEBHOOK_REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "webhook_authorization_requests_total",
        "Total webhook authorization requests",
        &["webhook", "result"]
    )
    .unwrap()
});

static WEBHOOK_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "webhook_authorization_duration_seconds",
        "Webhook authorization request duration",
        &["webhook"]
    )
    .unwrap()
});

#[derive(Clone, Debug, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub timeout_ms: u64,

    #[serde(flatten)]
    pub auth: Option<WebhookAuth>,

    pub client_certificate_bundle: Option<PathBuf>,
    pub client_private_key: Option<PathBuf>,

    pub server_ca_bundle: Option<PathBuf>,

    #[serde(default)]
    pub forward_headers: Vec<String>,

    #[serde(default = "WebhookConfig::default_cache_ttl")]
    pub cache_ttl: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookAuth {
    BasicAuth { username: String, password: String },
    BearerToken(String),
}

impl WebhookConfig {
    fn default_cache_ttl() -> u64 {
        60 // Default to 60 seconds
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.client_certificate_bundle.is_some() != self.client_private_key.is_some() {
            return Err(Error::Internal(
                "Both certificate and key required for mTLS".to_string(),
            ));
        }

        // Validate URL by parsing it
        let _ = Uri::try_from(&self.url)
            .map_err(|e| Error::Internal(format!("Invalid webhook URL: {e}")))?;

        Ok(())
    }
}

pub struct WebhookAuthorizer {
    name: String,
    config: WebhookConfig,
    client: Client,
    cache: Arc<dyn Cache>,
}

impl WebhookAuthorizer {
    pub fn new(name: String, config: WebhookConfig, cache: Arc<dyn Cache>) -> Result<Self, Error> {
        let mut client_builder = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_millis(config.timeout_ms));

        if let Some(ca_bundle) = &config.server_ca_bundle {
            let cert_pem = std::fs::read(ca_bundle)
                .map_err(|e| Error::Internal(format!("Failed to read CA bundle: {e}")))?;
            let cert = Certificate::from_pem(&cert_pem)
                .map_err(|e| Error::Internal(format!("Failed to parse CA bundle: {e}")))?;
            client_builder = client_builder.add_root_certificate(cert);
        }

        if let (Some(cert_path), Some(key_path)) = (
            &config.client_certificate_bundle,
            &config.client_private_key,
        ) {
            let cert_pem = std::fs::read(cert_path)
                .map_err(|e| Error::Internal(format!("Failed to read client certificate: {e}")))?;
            let key_pem = std::fs::read(key_path)
                .map_err(|e| Error::Internal(format!("Failed to read client key: {e}")))?;
            let identity = Identity::from_pem(&[cert_pem, key_pem].concat())
                .map_err(|e| Error::Internal(format!("Failed to create client identity: {e}")))?;
            client_builder = client_builder.identity(identity);
        }

        let client = client_builder
            .build()
            .map_err(|e| Error::Internal(format!("Failed to create HTTP client: {e}")))?;

        Ok(Self {
            name,
            config,
            client,
            cache,
        })
    }

    pub async fn authorize(
        &self,
        route: &Route<'_>,
        identity: &ClientIdentity,
        parts: &Parts,
    ) -> Result<bool, Error> {
        let cache_key = self.make_cache_key(route, identity);

        if let Ok(cached) = self.cache.retrieve(&cache_key).await {
            let cached_bool = cached.as_str() == "true";
            let result_label = if cached_bool {
                "cached_allow".to_string()
            } else {
                "cached_deny".to_string()
            };
            WEBHOOK_REQUESTS
                .with_label_values(&[&self.name, &result_label])
                .inc();
            return Ok(cached_bool);
        }

        let timer = WEBHOOK_DURATION
            .with_label_values(&[&self.name])
            .start_timer();

        let headers = self.build_headers(route, identity, parts)?;

        let mut req_builder = self.client.get(&self.config.url);

        for (key, value) in &headers {
            req_builder = req_builder.header(key, value);
        }

        if let Some(WebhookAuth::BearerToken(token)) = &self.config.auth {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        } else if let Some(WebhookAuth::BasicAuth { username, password }) = &self.config.auth {
            req_builder = req_builder.basic_auth(username, Some(password));
        }

        let response = req_builder.send().await;

        let allowed = match response {
            Ok(resp) => resp.status().is_success(),
            Err(e) => {
                tracing::warn!(webhook = %self.name, error = %e, "Webhook request failed");
                false
            }
        };

        timer.observe_duration();

        let result_label = if allowed {
            "allow".to_string()
        } else {
            "deny".to_string()
        };
        WEBHOOK_REQUESTS
            .with_label_values(&[&self.name, &result_label])
            .inc();

        let cache_value = if allowed { "true" } else { "false" };
        let _ = self
            .cache
            .store(&cache_key, cache_value, self.config.cache_ttl)
            .await;

        Ok(allowed)
    }

    fn create_header_value(value: &str, header_type: &str) -> Result<HeaderValue, Error> {
        HeaderValue::from_str(value)
            .map_err(|e| Error::Internal(format!("Invalid {header_type} header: {e}")))
    }

    #[allow(clippy::too_many_lines)]
    fn build_headers(
        &self,
        route: &Route<'_>,
        identity: &ClientIdentity,
        parts: &Parts,
    ) -> Result<HeaderMap, Error> {
        let mut headers = HeaderMap::new();

        headers.insert(
            "X-Forwarded-Method",
            Self::create_header_value(parts.method.as_str(), "method")?,
        );

        let proto = if parts.uri.scheme_str() == Some("https") {
            "https"
        } else {
            "http"
        };
        headers.insert("X-Forwarded-Proto", HeaderValue::from_static(proto));

        if let Some(host) = parts.headers.get("Host") {
            headers.insert("X-Forwarded-Host", host.clone());
        }

        headers.insert(
            "X-Forwarded-Uri",
            Self::create_header_value(&parts.uri.to_string(), "URI")?,
        );

        if let Some(ref ip) = identity.client_ip {
            headers.insert("X-Forwarded-For", Self::create_header_value(ip, "IP")?);
        }

        headers.insert(
            "X-Registry-Action",
            Self::create_header_value(route.action_name(), "action")?,
        );

        match route {
            Route::GetManifest {
                namespace,
                reference,
                ..
            }
            | Route::HeadManifest {
                namespace,
                reference,
                ..
            }
            | Route::PutManifest {
                namespace,
                reference,
                ..
            }
            | Route::DeleteManifest {
                namespace,
                reference,
            } => {
                headers.insert(
                    "X-Registry-Namespace",
                    Self::create_header_value(namespace, "namespace")?,
                );
                headers.insert(
                    "X-Registry-Reference",
                    Self::create_header_value(&reference.to_string(), "reference")?,
                );
            }
            Route::GetBlob {
                namespace, digest, ..
            }
            | Route::HeadBlob { namespace, digest }
            | Route::DeleteBlob { namespace, digest } => {
                headers.insert(
                    "X-Registry-Namespace",
                    Self::create_header_value(namespace, "namespace")?,
                );
                headers.insert(
                    "X-Registry-Digest",
                    Self::create_header_value(&digest.to_string(), "digest")?,
                );
            }
            Route::ListTags { namespace, .. }
            | Route::StartUpload { namespace, .. }
            | Route::GetUpload { namespace, .. }
            | Route::PatchUpload { namespace, .. }
            | Route::PutUpload { namespace, .. }
            | Route::DeleteUpload { namespace, .. } => {
                headers.insert(
                    "X-Registry-Namespace",
                    Self::create_header_value(namespace, "namespace")?,
                );
            }
            _ => {}
        }

        if let Some(ref username) = identity.username {
            headers.insert(
                "X-Registry-Username",
                Self::create_header_value(username, "username")?,
            );
        }

        if let Some(ref id) = identity.id {
            headers.insert(
                "X-Registry-Identity-ID",
                Self::create_header_value(id, "identity ID")?,
            );
        }

        if let Some(cn) = identity.certificate.common_names.first() {
            headers.insert(
                "X-Registry-Certificate-CN",
                Self::create_header_value(cn, "CN")?,
            );
        }

        if let Some(org) = identity.certificate.organizations.first() {
            headers.insert(
                "X-Registry-Certificate-O",
                Self::create_header_value(org, "org")?,
            );
        }

        for name in &self.config.forward_headers {
            if let Some(value) = parts.headers.get(name) {
                headers.insert(
                    HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                        Error::Internal(format!("Invalid forward header name: {e}"))
                    })?,
                    value.clone(),
                );
            }
        }

        Ok(headers)
    }

    fn make_cache_key(&self, route: &Route<'_>, identity: &ClientIdentity) -> String {
        let route_json = serde_json::to_string(route).unwrap_or_default();

        format!(
            "webhook:{}:{}:{}:{}",
            self.name,
            identity.id.as_deref().unwrap_or("anonymous"),
            identity.username.as_deref().unwrap_or(""),
            route_json
        )
    }
}
