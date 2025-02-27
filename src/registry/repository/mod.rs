use crate::configuration::{Error, RepositoryConfig, RepositoryUpstreamConfig};
use crate::registry;
use crate::registry::cache_store::CacheStore;
use crate::registry::oci_types::{Digest, Reference};
use cel_interpreter::Program;
use hyper::body::Incoming;
use hyper::{Method, Response};
use std::sync::Arc;
use tracing::instrument;

mod authentication_scheme;
mod bearer_token;
mod repository_upstream;

use repository_upstream::RepositoryUpstream;

pub struct Repository {
    pub name: String,
    pub upstream: Vec<RepositoryUpstream>,
    pub access_default_allow: bool,
    pub access_rules: Vec<Program>,
    pub retention_rules: Vec<Program>,
}

impl Repository {
    pub fn new(
        config: RepositoryConfig,
        name: String,
        token_cache: &Arc<CacheStore>,
    ) -> Result<Self, Error> {
        let access_rules = Self::compile_program_vec(&config.access_policy.rules)?;
        let upstream = Self::build_upstreams(config.upstream, token_cache)?;
        let retention_rules = Self::compile_program_vec(&config.retention_policy.rules)?;

        Ok(Self {
            name,
            upstream,
            access_default_allow: config.access_policy.default_allow,
            access_rules,
            retention_rules,
        })
    }

    fn compile_program_vec(programs: &[String]) -> Result<Vec<Program>, Error> {
        Ok(programs
            .iter()
            .map(|policy| Program::compile(policy))
            .collect::<Result<Vec<Program>, _>>()?)
    }

    fn build_upstreams(
        upstreams_config: Vec<RepositoryUpstreamConfig>,
        token_cache: &Arc<CacheStore>,
    ) -> Result<Vec<RepositoryUpstream>, Error> {
        let mut upstreams = Vec::new();

        for upstream_config in upstreams_config {
            upstreams.push(RepositoryUpstream::new(
                upstream_config,
                token_cache.clone(),
            )?);
        }

        Ok(upstreams)
    }

    pub fn is_pull_through(&self) -> bool {
        !self.upstream.is_empty()
    }

    #[instrument(skip(self))]
    pub async fn query_upstream_blob(
        &self,
        method: &Method,
        accepted_mime_types: &[String],
        namespace: &str,
        digest: &Digest,
    ) -> Result<Response<Incoming>, registry::Error> {
        let mut response = Err(registry::Error::ManifestUnknown);
        for upstream in &self.upstream {
            let location = upstream.get_blob_path(&self.name, namespace, digest);
            response = upstream
                .query(namespace, method, accepted_mime_types, &location)
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
        method: &Method,
        accepted_mime_types: &[String],
        namespace: &str,
        reference: &Reference,
    ) -> Result<Response<Incoming>, registry::Error> {
        let mut response = Err(registry::Error::ManifestUnknown);
        for upstream in &self.upstream {
            let location = upstream.get_manifest_path(&self.name, namespace, reference);
            response = upstream
                .query(namespace, method, accepted_mime_types, &location)
                .await;
            if response.is_ok() {
                break;
            }
        }
        response
    }
}
