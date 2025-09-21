mod auth;
mod bearer_token;

use crate::configuration::Error;
use crate::registry;
use crate::registry::cache::Cache;
use crate::registry::server::response_ext::{IntoAsyncRead, ResponseExt};
use auth::AuthenticationScheme;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bearer_token::BearerToken;
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, AUTHORIZATION, LOCATION, WWW_AUTHENTICATE};
use hyper::{Method, Request, Response, StatusCode};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tracing::warn;

#[derive(Clone, Debug)]
pub struct HttpClient {
    client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
    max_redirect: u8,
    basic_auth: Option<(String, String)>,
    cache: Option<Arc<dyn Cache>>,
}

#[derive(Clone, Debug, Default)]
pub struct HttpClientConfig {
    pub server_ca_bundle: Option<String>,
    pub client_certificate: Option<String>,
    pub client_private_key: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub max_redirect: Option<u8>,
}

impl HttpClient {
    pub fn new(config: HttpClientConfig) -> Result<Self, Error> {
        Self::with_cache(config, None)
    }

    pub fn with_cache(
        config: HttpClientConfig,
        cache: Option<Arc<dyn Cache>>,
    ) -> Result<Self, Error> {
        let tls_config = build_tls_config(
            config.server_ca_bundle,
            config.client_certificate,
            config.client_private_key,
        )?;

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .build();

        let client = Client::builder(TokioExecutor::new()).build(connector);

        let basic_auth = match (config.username, config.password) {
            (Some(username), Some(password)) => Some((username, password)),
            (Some(_), None) | (None, Some(_)) => {
                warn!("Username and password must be both provided");
                None
            }
            _ => None,
        };

        Ok(Self {
            client,
            max_redirect: config.max_redirect.unwrap_or(5),
            basic_auth,
            cache,
        })
    }

    pub async fn request(
        &self,
        mut request: Request<Empty<Bytes>>,
    ) -> Result<Response<Incoming>, registry::Error> {
        let mut redirects = 0;

        loop {
            let authority = request.uri().authority().cloned();

            if let Some(cache) = &self.cache {
                if let Some(authority) = &authority {
                    let cache_key = format!("auth:{authority}");
                    if let Ok(token) = cache.retrieve(&cache_key).await {
                        request
                            .headers_mut()
                            .insert(AUTHORIZATION, HeaderValue::from_str(&token)?);
                    }
                }
            }

            let response = self
                .client
                .request(request.clone())
                .await
                .map_err(|e| registry::Error::Internal(format!("HTTP request failed: {e}")))?;

            if response.status().is_redirection() {
                if redirects >= self.max_redirect {
                    return Err(registry::Error::Internal("Too many redirects".to_string()));
                }

                let location = response.get_header(LOCATION).ok_or_else(|| {
                    registry::Error::Internal("Missing Location header".to_string())
                })?;

                request = Request::builder()
                    .method(request.method())
                    .uri(location.as_str())
                    .body(Empty::new())?;

                redirects += 1;
                continue;
            }

            if response.status() == StatusCode::UNAUTHORIZED {
                let (token, ttl) = self.authenticate(&response).await?;

                if let Some(cache) = &self.cache {
                    if let Some(authority) = &authority {
                        cache
                            .store(&format!("auth:{authority}"), &token, ttl)
                            .await?;
                    }
                }

                request
                    .headers_mut()
                    .insert(AUTHORIZATION, HeaderValue::from_str(&token)?);

                let final_response =
                    self.client.request(request).await.map_err(|e| {
                        registry::Error::Internal(format!("HTTP request failed: {e}"))
                    })?;

                return Ok(final_response);
            }

            if response.status() == StatusCode::FORBIDDEN {
                return Err(registry::Error::Denied("Access forbidden".to_string()));
            }

            return Ok(response);
        }
    }

    async fn authenticate(
        &self,
        response: &Response<Incoming>,
    ) -> Result<(String, u64), registry::Error> {
        let auth_header = response
            .get_header(WWW_AUTHENTICATE)
            .ok_or_else(|| registry::Error::Unauthorized("Missing WWW-Authenticate".to_string()))?;

        match AuthenticationScheme::from_www_authenticate_header(&auth_header)? {
            AuthenticationScheme::Bearer(realm, params) => {
                let query = params
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("&");

                let mut req = Request::builder()
                    .method(Method::GET)
                    .uri(format!("{realm}?{query}"));

                if let Some((user, pass)) = &self.basic_auth {
                    let encoded = BASE64_STANDARD.encode(format!("{user}:{pass}"));
                    req = req.header(AUTHORIZATION, format!("Basic {encoded}"));
                }

                let resp = self
                    .client
                    .request(req.body(Empty::new())?)
                    .await
                    .map_err(|e| registry::Error::Internal(format!("Token request failed: {e}")))?;

                if !resp.status().is_success() {
                    return Err(registry::Error::Unauthorized(format!(
                        "Token acquisition failed: {}",
                        resp.status()
                    )));
                }

                let mut body = Vec::new();
                resp.into_async_read().read_to_end(&mut body).await?;

                let bearer = BearerToken::from_slice(&body)?;
                Ok((format!("Bearer {}", bearer.token()?), bearer.ttl()))
            }
            AuthenticationScheme::Basic => {
                let (user, pass) = self.basic_auth.as_ref().ok_or_else(|| {
                    registry::Error::Unauthorized(
                        "Basic auth required but not configured".to_string(),
                    )
                })?;
                let encoded = BASE64_STANDARD.encode(format!("{user}:{pass}"));
                Ok((format!("Basic {encoded}"), 3600))
            }
        }
    }
}

fn build_tls_config(
    ca_bundle: Option<String>,
    client_cert: Option<String>,
    client_key: Option<String>,
) -> Result<rustls::ClientConfig, Error> {
    let mut root_store = RootCertStore::empty();

    let certs = if let Some(bundle) = ca_bundle {
        CertificateDer::pem_file_iter(bundle)?.collect::<Result<Vec<_>, _>>()?
    } else {
        rustls_native_certs::load_native_certs().certs
    };

    root_store.add_parsable_certificates(certs);

    let config = rustls::ClientConfig::builder().with_root_certificates(root_store);

    match (client_cert, client_key) {
        (Some(cert), Some(key)) => {
            let certs = CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?;
            let key = PrivateKeyDer::from_pem_file(key)?;
            Ok(config.with_client_auth_cert(certs, key)?)
        }
        (None, None) => Ok(config.with_no_client_auth()),
        _ => {
            warn!("Client certificate and key must both be provided");
            Ok(config.with_no_client_auth())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_client_without_cache() -> Result<(), Error> {
        let config = HttpClientConfig::default();
        let client = HttpClient::new(config)?;
        assert!(client.cache.is_none());
        Ok(())
    }

    #[test]
    fn test_http_client_with_cache() -> Result<(), Error> {
        let config = HttpClientConfig::default();
        let cache = Arc::new(crate::registry::cache::memory::Backend::new());
        let client = HttpClient::with_cache(config, Some(cache))?;
        assert!(client.cache.is_some());
        Ok(())
    }
}
