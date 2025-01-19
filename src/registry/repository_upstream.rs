use crate::configuration::{Error, RepositoryUpstreamConfig};
use crate::oci::{Digest, Reference};
use crate::registry;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, ACCEPT, AUTHORIZATION, LOCATION};
use hyper::http::request;
use hyper::{HeaderMap, Method, Response};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{error, info, warn};

#[derive(Debug)]
pub struct RepositoryUpstream {
    pub url: String,
    pub max_redirect: u8,
    pub client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
    pub basic_auth_header: Option<HeaderValue>,
}

impl RepositoryUpstream {
    pub fn new(config: RepositoryUpstreamConfig) -> Result<Self, Error> {
        let client = Self::build_http_client(
            config.server_ca_bundle,
            config.client_certificate,
            config.client_private_key,
        )?;
        let basic_auth_header =
            Self::build_upstream_basic_auth_header(config.username, config.password);

        Ok(Self {
            url: config.url,
            max_redirect: config.max_redirect,
            client,
            basic_auth_header,
        })
    }

    fn build_upstream_basic_auth_header(
        username: Option<String>,
        password: Option<String>,
    ) -> Option<HeaderValue> {
        if let (Some(username), Some(password)) = (username, password) {
            let header = format!(
                "Basic {}",
                BASE64_STANDARD.encode(format!("{username}:{password}"))
            );

            match HeaderValue::from_str(&header) {
                Ok(header_value) => Some(header_value),
                Err(e) => {
                    error!("Failed to create basic auth header: {:?}", e);
                    None
                }
            }
        } else {
            None
        }
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

    pub async fn query(
        &self,
        method: &Method,
        accepted_mime_types: &[String],
        location: &str,
    ) -> Result<Response<Incoming>, registry::Error> {
        let mut headers = HeaderMap::new();
        if let Some(basic_auth_header) = self.basic_auth_header.clone() {
            headers.insert(AUTHORIZATION, basic_auth_header);
        }
        for mime_type in accepted_mime_types {
            if let Ok(header_value) = HeaderValue::from_str(mime_type) {
                headers.append(ACCEPT, header_value);
            }
        }

        let mut location = location;
        let mut redirect_count = 0;
        let mut response;

        loop {
            info!("Requesting manifest from upstream: {}", location);

            let mut request = request::Builder::new().method(method).uri(location);

            for (key, value) in &headers {
                request = request.header(key, value);
            }

            let request = request.body(Empty::new())?;
            response = match self.client.request(request).await {
                Ok(res) => res,
                Err(e) => {
                    error!("Failed to fetch manifest from upstream: {:?}", e);
                    return Err(registry::Error::Internal(Some(
                        "Failed to fetch manifest from upstream".to_string(),
                    )));
                }
            };

            if let Some(new_location) = response.headers().get(LOCATION) {
                location = new_location.to_str().map_err(|e| {
                    error!("Failed to parse Location header: {:?}", e);
                    registry::Error::Internal(Some("Failed to parse Location header".to_string()))
                })?;
                redirect_count += 1;
            } else {
                break;
            }

            if redirect_count >= self.max_redirect {
                error!("Too many upstream redirections");
                return Err(registry::Error::Internal(Some(
                    "Too many upstream redirections".to_string(),
                )));
            }
        }

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
