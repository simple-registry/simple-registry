use crate::configuration::{Error, RepositoryConfig, RepositoryUpstreamConfig};
use crate::registry;
use crate::registry::cache::Cache;
use crate::registry::oci::{Digest, Reference};
use hyper::body::Incoming;
use hyper::{Method, Response};
use tracing::instrument;

pub mod access_policy;
mod authentication_scheme;
mod bearer_token;
mod repository_upstream;
pub mod retention_policy;

use crate::registry::http_client::HttpClientBuilder;
pub use access_policy::AccessPolicy;
use repository_upstream::RepositoryUpstream;
pub use retention_policy::RetentionPolicy;

pub struct Repository {
    pub name: String,
    pub upstream: Vec<RepositoryUpstream>,
    pub access_policy: AccessPolicy,
    pub retention_policy: RetentionPolicy,
}

impl Repository {
    pub fn new(config: RepositoryConfig, name: String) -> Result<Self, Error> {
        let access_policy = AccessPolicy::new(&config.access_policy)?;
        let retention_policy = RetentionPolicy::new(&config.retention_policy)?;
        let upstream = Self::build_upstreams(config.upstream)?;

        Ok(Self {
            name,
            upstream,
            access_policy,
            retention_policy,
        })
    }

    fn build_upstreams(
        upstreams_config: Vec<RepositoryUpstreamConfig>,
    ) -> Result<Vec<RepositoryUpstream>, Error> {
        let mut upstreams = Vec::new();

        for mut upstream_config in upstreams_config {
            let server_ca_bundle = upstream_config.server_ca_bundle.take();
            let client_certificate = upstream_config.client_certificate.take();
            let client_private_key = upstream_config.client_private_key.take();

            let client = HttpClientBuilder::new()
                .set_server_ca_bundle(server_ca_bundle)
                .set_client_certificate(client_certificate)
                .set_client_private_key(client_private_key)
                .set_max_redirect(upstream_config.max_redirect)
                .build()?;

            upstreams.push(RepositoryUpstream::new(upstream_config, client));
        }

        Ok(upstreams)
    }

    pub fn is_pull_through(&self) -> bool {
        !self.upstream.is_empty()
    }

    #[instrument(skip(self))]
    pub async fn query_upstream_blob(
        &self,
        auth_token_cache: &dyn Cache,
        method: &Method,
        accepted_mime_types: &[String],
        namespace: &str,
        digest: &Digest,
    ) -> Result<Response<Incoming>, registry::Error> {
        let mut response = Err(registry::Error::ManifestUnknown);
        for upstream in &self.upstream {
            let location = upstream.get_blob_path(&self.name, namespace, digest);
            response = upstream
                .query(
                    auth_token_cache,
                    namespace,
                    method,
                    accepted_mime_types,
                    &location,
                )
                .await;
            if response.is_ok() {
                break;
            }
        }
        response
    }

    #[instrument(skip(self))]
    pub async fn query_upstream_manifest(
        &self,
        auth_token_cache: &dyn Cache,
        method: &Method,
        accepted_mime_types: &[String],
        namespace: &str,
        reference: &Reference,
    ) -> Result<Response<Incoming>, registry::Error> {
        for upstream in &self.upstream {
            let location = upstream.get_manifest_path(&self.name, namespace, reference);
            if let Ok(response) = upstream
                .query(
                    auth_token_cache,
                    namespace,
                    method,
                    accepted_mime_types,
                    &location,
                )
                .await
            {
                return Ok(response);
            }
        }

        Err(registry::Error::ManifestUnknown)
    }
}
