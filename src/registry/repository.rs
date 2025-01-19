use crate::configuration::{Error, RepositoryConfig, RepositoryUpstreamConfig};
use crate::oci::{Digest, Reference};
use crate::registry;
use crate::registry::repository_upstream::RepositoryUpstream;
use cel_interpreter::Program;
use hyper::body::Incoming;
use hyper::{Method, Response};
use tracing::error;

#[derive(Debug)]
pub struct Repository {
    pub upstream: Vec<RepositoryUpstream>,
    pub access_default_allow: bool,
    pub access_rules: Vec<Program>,
    #[allow(dead_code)]
    pub retention_rules: Vec<Program>,
}

impl Repository {
    pub fn new(config: RepositoryConfig) -> Result<Self, Error> {
        let access_rules = Self::compile_program_vec(&config.access_policy.rules)?;

        let upstream = Self::build_upstreams(config.upstream)?;
        let retention_rules = Self::compile_program_vec(&config.retention_policy.rules)?;

        Ok(Self {
            upstream,
            access_default_allow: config.access_policy.default_allow,
            access_rules,
            retention_rules,
        })
    }

    fn build_upstreams(
        upstreams_config: Vec<RepositoryUpstreamConfig>,
    ) -> Result<Vec<RepositoryUpstream>, Error> {
        let mut upstreams = Vec::new();

        for upstream_config in upstreams_config {
            upstreams.push(RepositoryUpstream::new(upstream_config)?);
        }

        Ok(upstreams)
    }

    pub async fn query_upstream_blob(
        &self,
        method: &Method,
        accepted_mime_types: &[String],
        repository_name: &str,
        namespace: &str,
        digest: &Digest,
    ) -> Result<Response<Incoming>, registry::Error> {
        for upstream in &self.upstream {
            let location = upstream.get_blob_path(repository_name, namespace, digest);
            match upstream.query(method, accepted_mime_types, &location).await {
                Ok(response) => {
                    return Ok(response);
                }
                Err(e) => {
                    error!("Failed to fetch manifest from upstream: {:?}", e);
                    continue;
                }
            }
        }

        Err(registry::Error::ManifestUnknown)
    }

    pub async fn query_upstream_manifest(
        &self,
        method: &Method,
        accepted_mime_types: &[String],
        repository_name: &str,
        namespace: &str,
        reference: &Reference,
    ) -> Result<Response<Incoming>, registry::Error> {
        for upstream in &self.upstream {
            let location = upstream.get_manifest_path(repository_name, namespace, reference);
            match upstream.query(method, accepted_mime_types, &location).await {
                Ok(response) => {
                    return Ok(response);
                }
                Err(e) => {
                    error!("Failed to fetch manifest from upstream: {:?}", e);
                    continue;
                }
            }
        }

        Err(registry::Error::ManifestUnknown)
    }

    fn compile_program_vec(programs: &[String]) -> Result<Vec<Program>, Error> {
        Ok(programs
            .iter()
            .map(|policy| Program::compile(policy))
            .collect::<Result<Vec<Program>, _>>()?)
    }

    pub fn is_pull_through(&self) -> bool {
        !self.upstream.is_empty()
    }
}
