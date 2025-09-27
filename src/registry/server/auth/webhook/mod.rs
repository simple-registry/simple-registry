use bytes::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::request::Parts;
use hyper::http::{HeaderMap, Request};
use hyper::{Method, Uri};
use prometheus::{register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::time::timeout;

use crate::registry::cache::Cache;
use crate::registry::error::Error;
use crate::registry::http_client::{HttpClient, HttpClientConfig};
use crate::registry::server::client_identity::ClientIdentity;
use crate::registry::server::route::Route;

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
    client: HttpClient,
    cache: Arc<dyn Cache>,
}

impl WebhookAuthorizer {
    pub fn new(name: String, config: WebhookConfig, cache: Arc<dyn Cache>) -> Result<Self, Error> {
        let (username, password) = match &config.auth {
            Some(WebhookAuth::BasicAuth { username, password }) => {
                (Some(username.clone()), Some(password.clone()))
            }
            _ => (None, None),
        };

        let http_config = HttpClientConfig {
            server_ca_bundle: config
                .server_ca_bundle
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            client_certificate: config
                .client_certificate_bundle
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            client_private_key: config
                .client_private_key
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            username,
            password,
            max_redirect: Some(0), // Disable redirects for webhooks
        };

        let client = HttpClient::new(http_config)
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

        let mut req_builder = Request::builder().method(Method::GET).uri(&self.config.url);

        for (key, value) in &headers {
            req_builder = req_builder.header(key, value);
        }

        if let Some(WebhookAuth::BearerToken(token)) = &self.config.auth {
            req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
        }

        let webhook_request = req_builder
            .body(http_body_util::Empty::<Bytes>::new())
            .map_err(|e| Error::Internal(format!("Failed to build webhook request: {e}")))?;

        let response = timeout(
            Duration::from_millis(self.config.timeout_ms),
            self.client.request(webhook_request),
        )
        .await;

        let allowed = match response {
            Ok(Ok(resp)) => resp.status().is_success(),
            Ok(Err(e)) => {
                tracing::warn!(webhook = %self.name, error = %e, "Webhook request failed");
                false
            }
            Err(_) => {
                tracing::warn!(webhook = %self.name, "Webhook request timed out");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::oci::Reference;
    use std::path::PathBuf;

    #[test]
    fn test_webhook_config_validation() {
        let valid_config = WebhookConfig {
            url: "https://example.com/authorize".to_string(),
            timeout_ms: 1000,
            auth: None,
            client_certificate_bundle: None,
            client_private_key: None,
            server_ca_bundle: None,
            forward_headers: vec![],
            cache_ttl: 60,
        };
        assert!(valid_config.validate().is_ok());

        let invalid_config1 = WebhookConfig {
            url: "https://example.com/authorize".to_string(),
            timeout_ms: 1000,
            auth: None,
            client_certificate_bundle: Some(PathBuf::from("/cert.pem")),
            client_private_key: None,
            server_ca_bundle: None,
            forward_headers: vec![],
            cache_ttl: 60,
        };
        assert!(invalid_config1.validate().is_err());

        let invalid_config2 = WebhookConfig {
            url: "https://example.com/authorize".to_string(),
            timeout_ms: 1000,
            auth: None,
            client_certificate_bundle: None,
            client_private_key: Some(PathBuf::from("/key.pem")),
            server_ca_bundle: None,
            forward_headers: vec![],
            cache_ttl: 60,
        };
        assert!(invalid_config2.validate().is_err());
    }

    #[test]
    fn test_webhook_action_header() {
        use crate::registry::server::route::Route;

        let route = Route::GetManifest {
            namespace: "test",
            reference: Reference::Tag("latest".to_string()),
        };
        assert_eq!(route.action_name(), "get-manifest");

        let route = Route::PutManifest {
            namespace: "test",
            reference: Reference::Tag("v1.0".to_string()),
        };
        assert_eq!(route.action_name(), "put-manifest");

        let route = Route::DeleteManifest {
            namespace: "test",
            reference: Reference::Tag("old".to_string()),
        };
        assert_eq!(route.action_name(), "delete-manifest");

        let route = Route::ApiVersion;
        assert_eq!(route.action_name(), "get-api-version");

        let route = Route::GetBlob {
            namespace: "test",
            digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap(),
        };
        assert_eq!(route.action_name(), "get-blob");

        let route = Route::StartUpload {
            namespace: "test",
            digest: None,
        };
        assert_eq!(route.action_name(), "start-upload");
    }

    #[test]
    fn test_webhook_auth_deserialization() {
        let toml = r#"
            url = "https://example.com"
            timeout_ms = 1000
            basic_auth = { username = "user", password = "pass" }
        "#;
        let config: WebhookConfig = toml::from_str(toml).unwrap();
        match config.auth {
            Some(WebhookAuth::BasicAuth { username, password }) => {
                assert_eq!(username, "user");
                assert_eq!(password, "pass");
            }
            _ => panic!("Expected BasicAuth"),
        }
        assert_eq!(config.cache_ttl, 60); // Should use default

        let toml = r#"
            url = "https://example.com"
            timeout_ms = 1000
            bearer_token = "secret-token"
            cache_ttl = 120
        "#;
        let config: WebhookConfig = toml::from_str(toml).unwrap();
        match config.auth {
            Some(WebhookAuth::BearerToken(token)) => {
                assert_eq!(token, "secret-token");
            }
            _ => panic!("Expected BearerToken"),
        }
        assert_eq!(config.cache_ttl, 120); // Should use configured value
    }
}
