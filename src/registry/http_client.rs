use crate::configuration::Error;
use crate::registry;
use crate::registry::server::response_ext::ResponseExt;
use async_trait::async_trait;
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::header::LOCATION;
use hyper::{Request, Response};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fmt::Debug;
use tracing::{error, warn};

#[async_trait]
pub trait HttpClient: Send + Sync + Debug {
    async fn request(
        &self,
        request: Request<Empty<Bytes>>,
    ) -> Result<Response<Incoming>, registry::Error>;
}

#[derive(Clone, Debug)]
struct HttpsClient {
    max_redirect: u8,
    client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
}

#[async_trait]
impl HttpClient for HttpsClient {
    async fn request(
        &self,
        mut request: Request<Empty<Bytes>>,
    ) -> Result<Response<Incoming>, registry::Error> {
        let mut redirect_count = 0;

        loop {
            let response = self
                .client
                .request(request.clone())
                .await
                .map_err(|error| {
                    error!("Failed to fetch manifest from upstream: {error}");
                    registry::Error::Internal("Failed to fetch manifest from upstream".to_string())
                })?;

            if response.status().is_redirection() {
                let Some(new_location) = response.get_header(LOCATION) else {
                    return Err(registry::Error::Internal(
                        "Redirect response without location header".to_string(),
                    ));
                };

                *request.uri_mut() = new_location.parse()?;

                if redirect_count >= self.max_redirect {
                    error!("Too many upstream redirections");
                    return Err(registry::Error::Internal(
                        "Too many upstream redirections".to_string(),
                    ));
                }

                redirect_count += 1;
                continue;
            }

            return Ok(response);
        }
    }
}

pub struct HttpClientBuilder {
    server_ca_bundle: Option<String>,
    client_certificate: Option<String>,
    client_private_key: Option<String>,
    max_redirect: u8,
}

impl HttpClientBuilder {
    pub fn new() -> Self {
        Self {
            server_ca_bundle: None,
            client_certificate: None,
            client_private_key: None,
            max_redirect: 10,
        }
    }

    pub fn set_server_ca_bundle(mut self, server_ca_bundle: Option<String>) -> Self {
        self.server_ca_bundle = server_ca_bundle;
        self
    }

    pub fn set_client_certificate(mut self, client_certificate: Option<String>) -> Self {
        self.client_certificate = client_certificate;
        self
    }

    pub fn set_client_private_key(mut self, client_private_key: Option<String>) -> Self {
        self.client_private_key = client_private_key;
        self
    }

    pub fn set_max_redirect(mut self, max_redirect: u8) -> Self {
        self.max_redirect = max_redirect;
        self
    }

    pub fn build(self) -> Result<Box<dyn HttpClient>, Error> {
        let mut root_store = RootCertStore::empty();
        let certs = if let Some(server_ca_bundle) = self.server_ca_bundle {
            CertificateDer::pem_file_iter(server_ca_bundle)?.collect::<Result<Vec<_>, _>>()?
        } else {
            rustls_native_certs::load_native_certs().expect("could not load platform certs")
        };
        root_store.add_parsable_certificates(certs);

        let tls_config = match (self.client_certificate, self.client_private_key) {
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

        let client = HttpsClient {
            max_redirect: self.max_redirect,
            client: Client::builder(TokioExecutor::new()).build(connector),
        };
        Ok(Box::new(client))
    }
}
