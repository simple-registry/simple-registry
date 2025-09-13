use crate::configuration::{Error, RepositoryConfig};
use crate::registry;
use crate::registry::cache::Cache;
use crate::registry::oci::{Digest, Reference};
use hyper::body::Incoming;
use hyper::{Method, Response};
use tracing::instrument;

pub mod access_policy;
pub mod retention_policy;

use crate::registry::client::RegistryClient;
pub use access_policy::AccessPolicy;
pub use retention_policy::RetentionPolicy;

pub struct Repository {
    pub name: String,
    pub upstreams: Vec<RegistryClient>,
    pub access_policy: AccessPolicy,
    pub retention_policy: RetentionPolicy,
}

impl Repository {
    pub fn new(name: String, config: RepositoryConfig) -> Result<Self, Error> {
        let mut upstreams = Vec::new();
        for config in config.upstream {
            upstreams.push(RegistryClient::new(config)?);
        }

        let access_policy = AccessPolicy::new(&config.access_policy)?;
        let retention_policy = RetentionPolicy::new(&config.retention_policy)?;

        Ok(Self {
            name,
            upstreams,
            access_policy,
            retention_policy,
        })
    }

    pub fn is_pull_through(&self) -> bool {
        !self.upstreams.is_empty()
    }

    #[instrument(skip(self))]
    pub async fn query_blob(
        &self,
        auth_token_cache: &dyn Cache,
        method: &Method,
        accepted_mime_types: &[String],
        namespace: &str,
        digest: &Digest,
    ) -> Result<Response<Incoming>, registry::Error> {
        let mut response = Err(registry::Error::ManifestUnknown);
        for upstream in &self.upstreams {
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
    pub async fn query_manifest(
        &self,
        auth_token_cache: &dyn Cache,
        method: &Method,
        accepted_mime_types: &[String],
        namespace: &str,
        reference: &Reference,
    ) -> Result<Response<Incoming>, registry::Error> {
        for upstream in &self.upstreams {
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
