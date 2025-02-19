use crate::configuration::{Error, RepositoryUpstreamConfig};
use crate::registry;
use crate::registry::cache_store::CacheStore;
use crate::registry::oci_types::{Digest, Reference};
use crate::registry::repository::authentication_scheme::AuthenticationScheme;
use crate::registry::repository::bearer_token::BearerToken;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, ACCEPT, AUTHORIZATION, LOCATION, WWW_AUTHENTICATE};
use hyper::http::request;
use hyper::{HeaderMap, Method, Response, StatusCode};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

#[derive(Debug)]
pub struct RepositoryUpstream {
    token_cache: Arc<CacheStore>,
    pub url: String,
    pub max_redirect: u8,
    pub client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
    pub basic_auth_header: Option<String>,
}

impl RepositoryUpstream {
    pub fn new(
        config: RepositoryUpstreamConfig,
        token_cache: Arc<CacheStore>,
    ) -> Result<Self, Error> {
        let client = Self::build_http_client(
            config.server_ca_bundle,
            config.client_certificate,
            config.client_private_key,
        )?;

        let mut upstream = Self {
            token_cache,
            url: config.url,
            max_redirect: config.max_redirect,
            client,
            basic_auth_header: None,
        };

        match (config.username, config.password) {
            (Some(username), Some(password)) => {
                upstream.set_basic_auth(&username, &password);
            }
            (Some(_), None) | (None, Some(_)) => {
                warn!("Username and password must be both provided");
            }
            _ => {}
        }

        Ok(upstream)
    }

    fn set_basic_auth(&mut self, username: &str, password: &str) {
        let header = format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("{username}:{password}"))
        );

        self.basic_auth_header = Some(header);
    }

    fn build_http_client(
        server_ca_bundle: Option<String>,
        client_certificate: Option<String>,
        client_private_key: Option<String>,
    ) -> Result<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>, Error> {
        let mut root_store = RootCertStore::empty();
        let certs = if let Some(server_ca_bundle) = server_ca_bundle {
            CertificateDer::pem_file_iter(server_ca_bundle)?.collect::<Result<Vec<_>, _>>()?
        } else {
            rustls_native_certs::load_native_certs().expect("could not load platform certs")
        };
        root_store.add_parsable_certificates(certs);

        let tls_config = match (client_certificate, client_private_key) {
            (Some(client_certificate), Some(client_private_key)) => {
                let certs = CertificateDer::pem_file_iter(client_certificate)?
                    .collect::<Result<Vec<_>, _>>()?;
                let key = PrivateKeyDer::from_pem_file(client_private_key)?;

                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_client_auth_cert(certs, key)?
            }
            (None, Some(_)) | (Some(_), None) => {
                warn!("Client certificate and private key must be both provided");
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth()
            }
            _ => rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        };

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .build();

        Ok(Client::builder(TokioExecutor::new()).build(connector))
    }

    fn get_basic_auth_header(&self) -> Result<(String, u64), registry::Error> {
        if let Some(header) = &self.basic_auth_header {
            return Ok((header.clone(), 60));
        }

        debug!("Basic authentication required by upstream");
        Err(registry::Error::Unauthorized(
            "Authentication required by upstream".to_string(),
        ))
    }

    #[tracing::instrument]
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

        let mut req = request::Builder::new()
            .method(Method::GET)
            .uri(&auth_location);
        if let Some(basic_auth_header) = &self.basic_auth_header {
            req = req.header(AUTHORIZATION, basic_auth_header);
        }

        let req = req.body(Empty::new())?;

        debug!("Requesting token from upstream");

        let response = match self.client.request(req).await {
            Ok(response) => response,
            Err(e) => {
                error!("Failed to authenticate with upstream: {:?}", e);
                return Err(registry::Error::Unauthorized(
                    "Failed to authenticate with upstream".to_string(),
                ));
            }
        };

        // TODO: this pattern is present in multiple places across the codebase, consider refactoring,
        // and using a more efficient implementation
        let mut content = Vec::new();
        let mut body = response.into_data_stream();
        while let Some(frame) = body.next().await {
            let frame = frame.map_err(|e| {
                error!("Data stream error: {}", e);
                std::io::Error::new(std::io::ErrorKind::Other, e)
            })?;
            content.extend_from_slice(&frame);
        }

        let token = BearerToken::from_slice(&content)?;

        let ttl = token.ttl();
        let header = format!("Bearer {}", token.token()?);

        Ok((header, ttl))
    }

    async fn get_auth_token_from_cache(
        &self,
        namespace: &str,
    ) -> Result<Option<HeaderValue>, registry::Error> {
        debug!("Checking bearer token in cache for namespace: {namespace:?}");
        let Ok(token) = self.token_cache.retrieve(namespace).await else {
            return Ok(None);
        };

        debug!("Retrieved token from cache for namespace: {namespace:?}");
        Ok(Some(HeaderValue::from_str(&token).map_err(|e| {
            debug!("Failed to build bearer token: {:?}", e);
            registry::Error::Internal("Failed to build bearer token for upstream".to_string())
        })?))
    }

    #[tracing::instrument]
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

        let mut location = location.to_string();
        let mut redirect_count = 0;
        let mut authenticate_count = 0;

        let response = loop {
            info!("Requesting manifest from upstream: {}", &location);

            let mut request = request::Builder::new().method(method).uri(&location);

            for (key, value) in &headers {
                request = request.header(key, value);
            }

            if let Some(authorization_header) = &authorization_header {
                debug!("Using bearer token for upstream authentication");
                request = request.header(AUTHORIZATION, authorization_header);
            }

            let request = request.body(Empty::new())?;
            let response = match self.client.request(request).await {
                Ok(res) => res,
                Err(e) => {
                    error!("Failed to fetch manifest from upstream: {:?}", e);
                    return Err(registry::Error::Internal(
                        "Failed to fetch manifest from upstream".to_string(),
                    ));
                }
            };

            if response.status().is_redirection() {
                if let Some(new_location) = response.headers().get(LOCATION).cloned() {
                    location = new_location
                        .to_str()
                        .map_err(|e| {
                            error!("Failed to parse Location header: {:?}", e);
                            registry::Error::Internal("Failed to parse Location header".to_string())
                        })?
                        .to_string();
                    redirect_count += 1;

                    if redirect_count >= self.max_redirect {
                        error!("Too many upstream redirections");
                        return Err(registry::Error::Internal(
                            "Too many upstream redirections".to_string(),
                        ));
                    }
                    continue;
                }
            }

            if response.status() == StatusCode::UNAUTHORIZED {
                if authenticate_count > 0 {
                    debug!("Too many upstream authentication requests");
                    return Err(registry::Error::Unauthorized(
                        "Too many upstream authentication requests".to_string(),
                    ));
                }

                let (token, token_ttl) = if let Some(www_authenticate_header) = response
                    .headers()
                    .get(WWW_AUTHENTICATE)
                    .and_then(|header| header.to_str().ok())
                {
                    match AuthenticationScheme::from_www_authenticate_header(
                        www_authenticate_header,
                    )? {
                        AuthenticationScheme::Bearer(realm, parameters) => {
                            self.query_bearer_token(&realm, &parameters).await
                        }
                        AuthenticationScheme::Basic => self.get_basic_auth_header(),
                    }
                } else {
                    // If no WWW-Authenticate header is present, assume we need to use basic auth.
                    self.get_basic_auth_header()
                }?;

                self.token_cache.store(namespace, &token, token_ttl).await?;

                authorization_header = Some(HeaderValue::from_str(&token).map_err(|e| {
                    debug!("Failed to build bearer token: {:?}", e);
                    registry::Error::Internal(
                        "Failed to build bearer token for upstream".to_string(),
                    )
                })?);

                authenticate_count += 1;
                continue;
            }

            break response;
        };

        if response.status().is_success() {
            Ok(response)
        } else if response.status() == StatusCode::UNAUTHORIZED {
            Err(registry::Error::Unauthorized(
                "Failed to authenticate with upstream".to_string(),
            ))
        } else if response.status() == StatusCode::FORBIDDEN {
            Err(registry::Error::Denied(
                "Access to upstream is forbidden".to_string(),
            ))
        } else {
            error!(
                "Failed to fetch manifest from upstream: {}",
                response.status()
            );
            Err(registry::Error::Internal(
                "Failed to fetch manifest from upstream".to_string(),
            ))
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
mod tests {}
