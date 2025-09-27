use crate::configuration::{Error, RepositoryConfig};
use crate::registry;
use crate::registry::cache::Cache;
use crate::registry::oci::{Digest, Reference};
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Method, Response};
use regex::Regex;
use std::sync::Arc;
use tracing::{error, instrument};

pub mod access_policy;
pub mod retention_policy;

use crate::registry::blob::DOCKER_CONTENT_DIGEST;
use crate::registry::client::RegistryClient;
use crate::registry::server::response_ext::ResponseExt;
pub use access_policy::AccessPolicy;
pub use retention_policy::RetentionPolicy;

pub struct Repository {
    pub name: String,
    pub upstreams: Vec<RegistryClient>,
    pub access_policy: AccessPolicy,
    pub retention_policy: RetentionPolicy,
    pub immutable_tags: bool,
    pub immutable_tags_exclusions: Vec<Regex>,
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

        let access_policy = AccessPolicy::new(&config.access_policy)?;
        let retention_policy = RetentionPolicy::new(&config.retention_policy)?;

        let immutable_tags_exclusions = config
            .immutable_tags_exclusions
            .into_iter()
            .filter_map(|p| match Regex::new(&p) {
                Ok(regex) => Some(regex),
                Err(e) => {
                    error!("Invalid regex pattern '{}': {}", p, e);
                    None
                }
            })
            .collect();

        Ok(Self {
            name,
            upstreams,
            access_policy,
            retention_policy,
            immutable_tags: config.immutable_tags,
            immutable_tags_exclusions,
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
            if let Ok(response) = upstream
                .query(&Method::HEAD, accepted_types, &location)
                .await
            {
                let digest = response.parse_header(DOCKER_CONTENT_DIGEST)?;
                let size = response.parse_header(CONTENT_LENGTH)?;
                return Ok((digest, size));
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
    ) -> Result<Response<Incoming>, registry::Error> {
        let mut response = Err(registry::Error::ManifestUnknown);
        for upstream in &self.upstreams {
            let location = upstream.get_blob_path(&self.name, namespace, digest);
            response = upstream
                .query(&Method::GET, accepted_types, &location)
                .await;
            if response.is_ok() {
                break;
            }
        }
        response
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
            if let Ok(response) = upstream
                .query(&Method::HEAD, accepted_types, &location)
                .await
            {
                let media_type = response.get_header(CONTENT_TYPE);
                let digest = response.parse_header(DOCKER_CONTENT_DIGEST)?;
                let size = response.parse_header(CONTENT_LENGTH)?;
                return Ok((media_type, digest, size));
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
    ) -> Result<Response<Incoming>, registry::Error> {
        for upstream in &self.upstreams {
            let location = upstream.get_manifest_path(&self.name, namespace, reference);
            if let Ok(response) = upstream
                .query(&Method::GET, accepted_types, &location)
                .await
            {
                return Ok(response);
            }
        }

        Err(registry::Error::ManifestUnknown)
    }
}
