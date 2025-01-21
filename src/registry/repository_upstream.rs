use crate::configuration::{Error, RepositoryUpstreamConfig};
use crate::oci::{Digest, Reference};
use crate::registry;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, ACCEPT, AUTHORIZATION, LOCATION, WWW_AUTHENTICATE};
use hyper::http::request;
use hyper::{HeaderMap, Method, Response};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use lazy_static::lazy_static;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

lazy_static! {
    static ref WWW_AUTHENTICATE_HEADER_PARAMETER: regex::Regex =
        regex::Regex::new(r#"(\w+)="([^"]+)""#).unwrap();
}

#[derive(Debug)]
pub struct RepositoryUpstream {
    pub url: String,
    pub max_redirect: u8,
    pub client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
    pub basic_auth_header: Option<HeaderValue>,
}

#[derive(Debug, Deserialize)]
struct TokenSpec {
    token: Option<String>,
    access_token: Option<String>,
    // TODO: expires_in: Option<u64>, // For use in cache as TTL
}

enum AuthenticationScheme {
    Bearer(String, HashMap<String, String>),
    Basic,
}

impl RepositoryUpstream {
    pub fn new(config: RepositoryUpstreamConfig) -> Result<Self, Error> {
        let client = Self::build_http_client(
            config.server_ca_bundle,
            config.client_certificate,
            config.client_private_key,
        )?;

        let mut upstream = Self {
            url: config.url,
            max_redirect: config.max_redirect,
            client,
            basic_auth_header: None,
        };

        match (config.username, config.password) {
            (Some(username), Some(password)) => {
                upstream.set_basic_auth(&username, &password)?;
            }
            (Some(_), None) | (None, Some(_)) => {
                warn!("Username and password must be both provided");
            }
            _ => {}
        }

        Ok(upstream)
    }

    fn set_basic_auth(&mut self, username: &str, password: &str) -> Result<(), Error> {
        let header = format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("{username}:{password}"))
        );

        self.basic_auth_header = Some(HeaderValue::from_str(&header)?);

        Ok(())
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

    fn parse_www_authenticate_header(
        www_authenticate_header: &str,
    ) -> Result<AuthenticationScheme, registry::Error> {
        let header_parameters;
        if www_authenticate_header.starts_with("Bearer ") {
            header_parameters = www_authenticate_header.trim_start_matches("Bearer ").trim();
            let mut parameters = HashMap::new();

            for (_, [key, value]) in WWW_AUTHENTICATE_HEADER_PARAMETER
                .captures_iter(header_parameters)
                .map(|c| c.extract())
            {
                parameters.insert(key.to_string(), value.to_string());
            }

            let realm = parameters.remove("realm").ok_or_else(|| {
                registry::Error::Internal(Some(
                    "Missing realm parameter in WWW-Authenticate header".to_string(),
                ))
            })?;

            Ok(AuthenticationScheme::Bearer(realm, parameters))
        } else if www_authenticate_header.starts_with("Basic ") {
            Ok(AuthenticationScheme::Basic)
        } else {
            Err(registry::Error::Internal(Some(
                "Unsupported authentication scheme in WWW-Authenticate header".to_string(),
            )))
        }
    }

    async fn query_bearer_token(
        &self,
        realm: &str,
        parameters: &HashMap<String, String>,
    ) -> Result<HeaderValue, registry::Error> {
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
                return Err(registry::Error::Internal(Some(
                    "Failed to authenticate with upstream".to_string(),
                )));
            }
        };

        // TODO: this pattern is present in multiple places accross the codebase, consider refactoring,
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

        let token_spec: TokenSpec = serde_json::from_slice(&content)?;

        let token = token_spec
            .token
            .or(token_spec.access_token)
            .ok_or_else(|| {
                registry::Error::Internal(Some(
                    "Missing token in authentication response".to_string(),
                ))
            })?;

        let header = format!("Bearer {token}");
        // TODO: store the token in a cache with the provided TTL

        HeaderValue::from_str(&header).map_err(|e| {
            debug!("Failed to build bearer token: {:?}", e);
            registry::Error::Internal(Some(
                "Failed to build bearer token for upstream".to_string(),
            ))
        })
    }

    pub async fn query(
        &self,
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

        // TODO: add an option to NOT wait for Unauthorized response to use a token, either for
        // basic auth or for bearer token
        let mut authorization_header = None;

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
                request = request.header(AUTHORIZATION, authorization_header);
            }

            let request = request.body(Empty::new())?;
            let response = match self.client.request(request).await {
                Ok(res) => res,
                Err(e) => {
                    error!("Failed to fetch manifest from upstream: {:?}", e);
                    return Err(registry::Error::Internal(Some(
                        "Failed to fetch manifest from upstream".to_string(),
                    )));
                }
            };

            if response.status().is_redirection() {
                if let Some(new_location) = response.headers().get(LOCATION).cloned() {
                    location = new_location
                        .to_str()
                        .map_err(|e| {
                            error!("Failed to parse Location header: {:?}", e);
                            registry::Error::Internal(Some(
                                "Failed to parse Location header".to_string(),
                            ))
                        })?
                        .to_string();
                    redirect_count += 1;

                    if redirect_count >= self.max_redirect {
                        error!("Too many upstream redirections");
                        return Err(registry::Error::Internal(Some(
                            "Too many upstream redirections".to_string(),
                        )));
                    }
                    continue;
                }
            }

            if let Some(www_authenticate_header) = response.headers().get(WWW_AUTHENTICATE) {
                if authenticate_count > 0 {
                    debug!("Too many upstream authentication requests");
                    return Err(registry::Error::Internal(Some(
                        "Too many upstream authentication requests".to_string(),
                    )));
                }
                let www_authenticate_header = www_authenticate_header.to_str().map_err(|e| {
                    debug!("Failed to parse WWW-Authenticate header: {:?}", e);
                    registry::Error::Internal(Some(
                        "Failed to parse WWW-Authenticate header".to_string(),
                    ))
                })?;

                match Self::parse_www_authenticate_header(www_authenticate_header)? {
                    AuthenticationScheme::Bearer(realm, parameters) => {
                        authorization_header =
                            Some(self.query_bearer_token(&realm, &parameters).await?);
                    }
                    AuthenticationScheme::Basic => {
                        authorization_header.clone_from(&self.basic_auth_header);
                    }
                };

                authenticate_count += 1;
                continue;
            }

            break response;
        };

        if response.status().is_success() {
            Ok(response)
        } else {
            error!(
                "Failed to fetch manifest from upstream: {}",
                response.status()
            );
            Err(registry::Error::Internal(Some(
                "Failed to fetch manifest from upstream".to_string(),
            )))
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
