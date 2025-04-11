use crate::configuration::RepositoryUpstreamConfig;
use crate::registry;
use crate::registry::api::hyper::response_ext::{IntoAsyncRead, ResponseExt};
use crate::registry::cache_store::CacheStore;
use crate::registry::http_client::HttpClient;
use crate::registry::oci_types::{Digest, Reference};
use crate::registry::repository::authentication_scheme::AuthenticationScheme;
use crate::registry::repository::bearer_token::BearerToken;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::header::{HeaderValue, ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::http::request;
use hyper::{HeaderMap, Method, Response, StatusCode};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, warn};

#[derive(Debug)]
pub struct RepositoryUpstream {
    token_cache: Arc<CacheStore>,
    pub url: String,
    pub client: Box<dyn HttpClient>,
    pub basic_auth_header: Option<String>,
}

impl RepositoryUpstream {
    pub fn new(
        config: RepositoryUpstreamConfig,
        client: Box<dyn HttpClient>,
        token_cache: Arc<CacheStore>,
    ) -> Self {
        let mut upstream = Self {
            token_cache,
            url: config.url,
            client,
            basic_auth_header: None,
        };

        match (config.username, config.password) {
            (Some(username), Some(password)) => {
                let header = format!(
                    "Basic {}",
                    BASE64_STANDARD.encode(format!("{username}:{password}"))
                );

                upstream.basic_auth_header = Some(header);
            }
            (Some(_), None) | (None, Some(_)) => {
                warn!("Username and password must be both provided");
            }
            _ => {}
        }

        upstream
    }

    async fn get_auth_token_from_cache(
        &self,
        namespace: &str,
    ) -> Result<Option<HeaderValue>, registry::Error> {
        debug!("Checking bearer token in cache for namespace: {namespace}");
        let Ok(token) = self.token_cache.retrieve(namespace).await else {
            return Ok(None);
        };

        debug!("Retrieved token from cache for namespace: {namespace}");
        Ok(Some(HeaderValue::from_str(&token)?))
    }

    #[tracing::instrument(skip(self))]
    async fn query_bearer_token(
        &self,
        realm: &str,
        parameters: &HashMap<String, String>,
    ) -> Result<(String, u64), registry::Error> {
        let parameters = parameters
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<String>>()
            .join("&");

        let auth_location = format!("{realm}?{parameters}");

        let req;
        if let Some(basic_auth_header) = &self.basic_auth_header {
            req = request::Builder::new()
                .method(Method::GET)
                .uri(&auth_location)
                .header(AUTHORIZATION, basic_auth_header)
                .body(Empty::new())?;
        } else {
            req = request::Builder::new()
                .method(Method::GET)
                .uri(&auth_location)
                .body(Empty::new())?;
        }

        debug!("Requesting token from upstream");
        match self.client.request(req).await {
            Ok(response) => {
                let mut response = response.into_async_read();
                let mut token = Vec::new();
                response.read_to_end(&mut token).await?;

                let token = BearerToken::from_slice(&token)?;
                let header = format!("Bearer {}", token.token()?);
                Ok((header, token.ttl()))
            }
            Err(error) => {
                error!("Failed to authenticate with upstream: {error}");
                return Err(registry::Error::Unauthorized(
                    "Failed to authenticate with upstream".to_string(),
                ));
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn query(
        &self,
        namespace: &str,
        method: &Method,
        accepted_mime_types: &[String],
        location: &str,
    ) -> Result<Response<Incoming>, registry::Error> {
        let mut headers = HeaderMap::new();
        for mime_type in accepted_mime_types {
            if let Ok(header_value) = HeaderValue::from_str(mime_type) {
                headers.append(ACCEPT, header_value);
            }
        }

        let mut authorization_header = self.get_auth_token_from_cache(namespace).await?;

        loop {
            info!("Requesting manifest from upstream: {location}");
            let mut request = request::Builder::new().method(method).uri(location);

            for (key, value) in &headers {
                request = request.header(key, value);
            }

            if let Some(authorization_header) = &authorization_header {
                debug!("Using bearer token for upstream authentication");
                request = request.header(AUTHORIZATION, authorization_header);
            }

            let request = request.body(Empty::new())?;
            let response = self.client.request(request).await?;

            if response.status().is_success() {
                debug!("Successfully fetched manifest from upstream");
                return Ok(response);
            } else if response.status() == StatusCode::UNAUTHORIZED {
                if authorization_header.is_some() {
                    return Err(registry::Error::Unauthorized(
                        "Failed to authenticate with upstream".to_string(),
                    ));
                }

                let Some(auth_header) = response.get_header(WWW_AUTHENTICATE) else {
                    return Err(registry::Error::Unauthorized(
                        "Failed to authenticate with upstream".to_string(),
                    ));
                };

                let token;
                let ttl;

                match AuthenticationScheme::from_www_authenticate_header(&auth_header)? {
                    AuthenticationScheme::Bearer(realm, parameters) => {
                        (token, ttl) = self.query_bearer_token(&realm, &parameters).await?;
                    }
                    AuthenticationScheme::Basic => {
                        if let Some(header) = &self.basic_auth_header {
                            debug!("Using provided basic auth credentials");
                            token = header.to_owned();
                            ttl = 3600;
                        } else {
                            debug!("Basic authentication required by upstream");
                            return Err(registry::Error::Unauthorized(
                                "Authentication required by upstream".to_string(),
                            ));
                        }
                    }
                }

                self.token_cache.store(namespace, &token, ttl).await?;
                authorization_header = Some(HeaderValue::from_str(&token)?);
            } else if response.status() == StatusCode::FORBIDDEN {
                return Err(registry::Error::Denied(
                    "Access to upstream is forbidden".to_string(),
                ));
            } else {
                error!("Failed to fetch upstream manifest: {}", response.status());
                return Err(registry::Error::Internal(
                    "Failed to fetch upstream manifest".to_string(),
                ));
            }
        }
    }

    fn get_upstream_namespace(local_name: &str, upstream_name: &str) -> String {
        upstream_name
            .strip_prefix(local_name)
            .unwrap_or(upstream_name)
            .trim_start_matches('/')
            .to_string()
    }

    pub fn get_manifest_path(
        &self,
        local_name: &str,
        upstream_name: &str,
        reference: &Reference,
    ) -> String {
        let namespace = Self::get_upstream_namespace(local_name, upstream_name);
        format!("{}/v2/{namespace}/manifests/{reference}", self.url)
    }

    pub fn get_blob_path(&self, local_name: &str, upstream_name: &str, digest: &Digest) -> String {
        let namespace = Self::get_upstream_namespace(local_name, upstream_name);
        format!("{}/v2/{namespace}/blobs/{digest}", self.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::CacheStoreConfig;
    use async_trait::async_trait;
    use hyper::body::Bytes;
    use mockall::*;

    mock! {
        #[derive(Debug)]
        pub HttpClientMock {}

        #[async_trait]
        impl HttpClient for HttpClientMock {
            async fn request(
                &self,
                request: hyper::Request<Empty<Bytes>>
            ) -> Result<Response<Incoming>, registry::Error>;
        }
    }

    fn build_upstream(with_password: bool) -> RepositoryUpstream {
        let token_cache = CacheStore::new(CacheStoreConfig::default()).unwrap();

        let mut username = None;
        let mut password = None;
        if with_password {
            username = Some("username".to_string());
            password = Some("password".to_string());
        }

        RepositoryUpstream::new(
            RepositoryUpstreamConfig {
                url: "https://example.com".to_string(),
                max_redirect: 5,
                server_ca_bundle: None,
                client_certificate: None,
                client_private_key: None,
                username,
                password,
            },
            Box::new(MockHttpClientMock::new()),
            Arc::new(token_cache),
        )
    }

    #[test]
    fn test_get_upstream_namespace() {
        let local_name = "local";
        let upstream_name = "local/repo";

        let result = RepositoryUpstream::get_upstream_namespace(local_name, upstream_name);
        assert_eq!(result, "repo");

        let upstream_name = "completely_different";
        let result = RepositoryUpstream::get_upstream_namespace(local_name, upstream_name);
        assert_eq!(result, "completely_different");
    }

    #[tokio::test]
    async fn test_get_manifest_path() {
        let repo = build_upstream(true);

        let local_name = "local";
        let upstream_name = "local/repo";
        let reference = Reference::from_str("latest").unwrap();

        let path = repo.get_manifest_path(local_name, upstream_name, &reference);
        assert_eq!(path, "https://example.com/v2/repo/manifests/latest");
    }

    #[tokio::test]
    async fn test_get_blob_path() {
        let repo = build_upstream(false);

        let local_name = "local";
        let upstream_name = "local/repo";
        let digest = Digest::try_from(
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )
        .unwrap();

        let path = repo.get_blob_path(local_name, upstream_name, &digest);
        assert_eq!(path, "https://example.com/v2/repo/blobs/sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    }

    #[tokio::test]
    async fn test_get_auth_token_from_cache_success() {
        const TEST_NAMESPACE: &str = "test-namespace";

        let upstream = build_upstream(false);
        let result = upstream.get_auth_token_from_cache(TEST_NAMESPACE).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        upstream
            .token_cache
            .store(TEST_NAMESPACE, "test-token", 3600)
            .await
            .unwrap();

        let result = upstream.get_auth_token_from_cache(TEST_NAMESPACE).await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            Some(HeaderValue::from_str("test-token").unwrap())
        );
    }
}
