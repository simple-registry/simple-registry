use crate::cache::Cache;
use crate::oci::{Digest, Reference};
use serde::Deserialize;
use std::sync::Arc;
use tracing::instrument;
mod registry_client;

use crate::registry::blob_store::Reader;
use registry_client::RegistryClient;

use crate::registry::access_policy::AccessPolicyConfig;
use crate::registry::retention_policy::{RetentionPolicy, RetentionPolicyConfig};
use crate::registry::Error;
pub use registry_client::RegistryClientConfig;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub upstream: Vec<RegistryClientConfig>,
    #[serde(default)]
    pub access_policy: AccessPolicyConfig,
    #[serde(default)]
    pub retention_policy: RetentionPolicyConfig,
    #[serde(default)]
    pub immutable_tags: bool,
    #[serde(default)]
    pub immutable_tags_exclusions: Vec<String>,
    pub authorization_webhook: Option<String>,
}

pub struct Repository {
    pub name: String,
    pub upstreams: Vec<RegistryClient>,
    pub retention_policy: RetentionPolicy,
}

impl Repository {
    pub fn new(name: &str, config: &Config, cache: &Arc<dyn Cache>) -> Result<Self, Error> {
        let mut upstreams = Vec::new();
        for config in &config.upstream {
            upstreams.push(RegistryClient::new(config, cache.clone())?);
        }

        let retention_policy = RetentionPolicy::new(&config.retention_policy)?;

        Ok(Self {
            name: name.to_string(),
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
    ) -> Result<(Digest, u64), Error> {
        for upstream in &self.upstreams {
            let location = upstream.get_blob_path(&self.name, namespace, digest);
            let response = upstream.head_blob(accepted_types, &location).await;

            if response.is_ok() {
                return response;
            }
        }

        Err(Error::ManifestUnknown)
    }

    #[instrument(skip(self))]
    pub async fn get_blob(
        &self,
        accepted_types: &[String],
        namespace: &str,
        digest: &Digest,
    ) -> Result<(u64, Box<dyn Reader>), Error> {
        for upstream in &self.upstreams {
            let location = upstream.get_blob_path(&self.name, namespace, digest);
            if let Ok(response) = upstream.get_blob(accepted_types, &location).await {
                return Ok(response);
            }
        }

        Err(Error::ManifestUnknown)
    }

    #[instrument(skip(self))]
    pub async fn head_manifest(
        &self,
        accepted_types: &[String],
        namespace: &str,
        reference: &Reference,
    ) -> Result<(Option<String>, Digest, u64), Error> {
        for upstream in &self.upstreams {
            let location = upstream.get_manifest_path(&self.name, namespace, reference);
            if let Ok(response) = upstream.head_manifest(accepted_types, &location).await {
                return Ok(response);
            }
        }

        Err(Error::ManifestUnknown)
    }

    #[instrument(skip(self))]
    pub async fn get_manifest(
        &self,
        accepted_types: &[String],
        namespace: &str,
        reference: &Reference,
    ) -> Result<(Option<String>, Digest, Vec<u8>), Error> {
        for upstream in &self.upstreams {
            let location = upstream.get_manifest_path(&self.name, namespace, reference);
            if let Ok(response) = upstream.get_manifest(accepted_types, &location).await {
                return Ok(response);
            }
        }

        Err(Error::ManifestUnknown)
    }
}
