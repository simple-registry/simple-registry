#[cfg(test)]
mod tests;

use crate::configuration;
use crate::registry::cache::Cache;
use crate::registry::http_client::{HttpClient, HttpClientConfig};
use crate::registry::oci::{Digest, Reference};
use crate::registry::Error;
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::header::ACCEPT;
use hyper::{Method, Request, Response};
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;

#[derive(Clone, Debug, Deserialize)]
pub struct ClientConfig {
    pub url: String,
    #[serde(default = "ClientConfig::default_max_redirect")]
    pub max_redirect: u8,
    pub server_ca_bundle: Option<String>,
    pub client_certificate: Option<String>,
    pub client_private_key: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ClientConfig {
    fn default_max_redirect() -> u8 {
        5
    }
}

#[derive(Debug)]
pub struct RegistryClient {
    pub url: String,
    client: HttpClient,
}

impl RegistryClient {
    pub fn new(config: ClientConfig, cache: Arc<dyn Cache>) -> Result<Self, configuration::Error> {
        let http_config = HttpClientConfig {
            server_ca_bundle: config.server_ca_bundle,
            client_certificate: config.client_certificate,
            client_private_key: config.client_private_key,
            username: config.username,
            password: config.password,
            max_redirect: Some(config.max_redirect),
        };

        let client = HttpClient::with_cache(http_config, Some(cache))?;

        Ok(Self {
            url: config.url,
            client,
        })
    }

    pub async fn query(
        &self,
        method: &Method,
        accepted_types: &[String],
        location: &str,
    ) -> Result<Response<Incoming>, Error> {
        info!("Requesting from upstream: {location}");

        let mut request = Request::builder().method(method).uri(location);

        for accepted_type in accepted_types {
            request = request.header(ACCEPT, accepted_type);
        }

        let request = request.body(Empty::<Bytes>::new())?;
        self.client.request(request).await
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
