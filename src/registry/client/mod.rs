mod authentication_scheme;
mod bearer_token;
#[cfg(test)]
mod tests;

use crate::configuration::RepositoryUpstreamConfig;
use crate::registry::cache::Cache;
use crate::registry::client::authentication_scheme::AuthenticationScheme;
use crate::registry::client::bearer_token::BearerToken;
use crate::registry::http_client::{HttpClient, HttpClientBuilder};
use crate::registry::oci::{Digest, Reference};
use crate::registry::server::response_ext::{IntoAsyncRead, ResponseExt};
use crate::{configuration, registry};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::header::{HeaderValue, ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::http::request;
use hyper::{HeaderMap, Method, Response, StatusCode};
use std::collections::HashMap;
use std::fmt::Debug;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, warn};

#[derive(Debug)]
pub struct RegistryClient {
    pub url: String,
    pub client: Box<dyn HttpClient>,
    pub basic_auth_header: Option<String>,
}

impl RegistryClient {
    pub fn new(mut config: RepositoryUpstreamConfig) -> Result<Self, configuration::Error> {
        let server_ca_bundle = config.server_ca_bundle.take();
        let client_certificate = config.client_certificate.take();
        let client_private_key = config.client_private_key.take();

        let client = HttpClientBuilder::new()
            .set_server_ca_bundle(server_ca_bundle)
            .set_client_certificate(client_certificate)
            .set_client_private_key(client_private_key)
            .set_max_redirect(config.max_redirect)
            .build()?;

        let basic_auth_header = match (config.username, config.password) {
            (Some(username), Some(password)) => {
                let header = format!(
                    "Basic {}",
                    BASE64_STANDARD.encode(format!("{username}:{password}"))
                );
                Some(header)
            }
            (Some(_), None) | (None, Some(_)) => {
                warn!("Username and password must be both provided");
                None
            }
            _ => None,
        };

        Ok(Self {
            url: config.url,
            client,
            basic_auth_header,
        })
    }

    async fn get_auth_token_from_cache(
        &self,
        cache: &dyn Cache,
        namespace: &str,
    ) -> Result<Option<HeaderValue>, registry::Error> {
        debug!("Checking bearer token in cache for namespace: {namespace}");
        let Ok(token) = cache.retrieve(namespace).await else {
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

        let req = if let Some(basic_auth_header) = &self.basic_auth_header {
            request::Builder::new()
                .method(Method::GET)
                .uri(&auth_location)
                .header(AUTHORIZATION, basic_auth_header)
                .body(Empty::new())?
        } else {
            request::Builder::new()
                .method(Method::GET)
                .uri(&auth_location)
                .body(Empty::new())?
        };

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
                Err(registry::Error::Unauthorized(
                    "Failed to authenticate with upstream".to_string(),
                ))
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn query(
        &self,
        cache: &dyn Cache,
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

        let mut authorization_header = self.get_auth_token_from_cache(cache, namespace).await?;

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

                cache.store(namespace, &token, ttl).await?;
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
