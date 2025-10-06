use crate::configuration::{Error, RepositoryConfig};
use crate::registry;
use crate::registry::cache::Cache;
use crate::oci::{Digest, Reference};
use std::sync::Arc;
use tracing::instrument;

pub mod access_policy;
pub mod retention_policy;

use crate::registry::blob_store::Reader;
use crate::registry::client::RegistryClient;
pub use access_policy::AccessPolicy;
pub use retention_policy::RetentionPolicy;

pub struct Repository {
    pub name: String,
    pub upstreams: Vec<RegistryClient>,
    pub retention_policy: RetentionPolicy,
}

impl Repository {
    pub fn new(
        name: String,
        config: RepositoryConfig,
        cache: &Arc<dyn Cache>,
    ) -> Result<Self, Error> {
        let mut upstreams = Vec::new();
        for config in config.upstream {
            upstreams.push(RegistryClient::new(config, cache.clone())?);
        }

        let retention_policy = RetentionPolicy::new(&config.retention_policy)?;

        Ok(Self {
            name,
            upstreams,
            retention_policy,
        })
    }

    pub fn is_pull_through(&self) -> bool {
        !self.upstreams.is_empty()
    }

    #[instrument(skip(self))]
    pub async fn head_blob(
        &self,
        accepted_types: &[String],
        namespace: &str,
        digest: &Digest,
    ) -> Result<(Digest, u64), registry::Error> {
        for upstream in &self.upstreams {
            let location = upstream.get_blob_path(&self.name, namespace, digest);
            let response = upstream.head_blob(accepted_types, &location).await;

            if response.is_ok() {
                return response;
            }
        }

        Err(registry::Error::ManifestUnknown)
    }

    #[instrument(skip(self))]
    pub async fn get_blob(
        &self,
        accepted_types: &[String],
        namespace: &str,
        digest: &Digest,
    ) -> Result<(u64, Box<dyn Reader>), registry::Error> {
        for upstream in &self.upstreams {
            let location = upstream.get_blob_path(&self.name, namespace, digest);
            if let Ok(response) = upstream.get_blob(accepted_types, &location).await {
                return Ok(response);
            }
        }

        Err(registry::Error::ManifestUnknown)
    }

    #[instrument(skip(self))]
    pub async fn head_manifest(
        &self,
        accepted_types: &[String],
        namespace: &str,
        reference: &Reference,
    ) -> Result<(Option<String>, Digest, u64), registry::Error> {
        for upstream in &self.upstreams {
            let location = upstream.get_manifest_path(&self.name, namespace, reference);
            if let Ok(response) = upstream.head_manifest(accepted_types, &location).await {
                return Ok(response);
            }
        }

        Err(registry::Error::ManifestUnknown)
    }

    #[instrument(skip(self))]
    pub async fn get_manifest(
        &self,
        accepted_types: &[String],
        namespace: &str,
        reference: &Reference,
    ) -> Result<(Option<String>, Digest, Vec<u8>), registry::Error> {
        for upstream in &self.upstreams {
            let location = upstream.get_manifest_path(&self.name, namespace, reference);
            if let Ok(response) = upstream.get_manifest(accepted_types, &location).await {
                return Ok(response);
            }
        }

        Err(registry::Error::ManifestUnknown)
    }
}
