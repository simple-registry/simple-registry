use chrono::Duration;
use hyper::body::Incoming;
use hyper::header::AsHeaderName;
use hyper::Response;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;
use tracing::instrument;

mod blob;
pub mod cache_store;
mod content_discovery;
pub mod data_store;
mod error;
pub mod lock_store;
mod manifest;
pub mod oci_types;
pub mod policy_types;
mod scrub;
mod upload;
mod utils;

use crate::configuration;
use crate::configuration::RepositoryConfig;
use crate::registry::cache_store::CacheStore;
use crate::registry::data_store::DataStore;
use crate::registry::utils::Repository;
pub use blob::GetBlobResponse;
pub use error::Error;
pub use manifest::parse_manifest_digests;
pub use upload::StartUploadResponse;

lazy_static! {
    static ref NAMESPACE_RE: Regex =
        Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$").unwrap();
}

#[derive(Debug)]
pub struct Registry {
    streaming_chunk_size: usize,
    storage_engine: Arc<Box<dyn DataStore>>,
    repositories: HashMap<String, Repository>,
    scrub_dry_run: bool,
    scrub_upload_timeout: Duration,
}

impl Registry {
    #[instrument]
    pub fn new(
        repositories_config: HashMap<String, RepositoryConfig>,
        streaming_chunk_size: usize,
        storage_engine: Box<dyn DataStore>,
        token_cache: Arc<CacheStore>,
    ) -> Result<Self, configuration::Error> {
        let mut repositories = HashMap::new();
        for (namespace, repository_config) in repositories_config {
            let res = Repository::new(repository_config, &token_cache)?;
            repositories.insert(namespace, res);
        }

        let res = Self {
            streaming_chunk_size,
            storage_engine: Arc::new(storage_engine),
            repositories,
            scrub_dry_run: true,
            scrub_upload_timeout: Duration::days(1),
        };

        Ok(res)
    }

    pub fn with_dry_run(mut self, scrub_dry_run: bool) -> Self {
        self.scrub_dry_run = scrub_dry_run;
        self
    }

    pub fn with_upload_timeout(mut self, scrub_upload_timeout: Duration) -> Self {
        self.scrub_upload_timeout = scrub_upload_timeout;
        self
    }

    // TODO: check usage (called twice for most requests)
    pub fn find_repository(&self, namespace: &str) -> Option<(&String, &Repository)> {
        self.repositories
            .iter()
            .find(|(repository, _)| namespace.starts_with(*repository))
    }

    #[instrument]
    pub fn validate_namespace(&self, namespace: &str) -> Result<(&String, &Repository), Error> {
        if NAMESPACE_RE.is_match(namespace) {
            self.find_repository(namespace).ok_or(Error::NameUnknown)
        } else {
            Err(Error::NameInvalid)
        }
    }

    fn get_header<K>(res: &Response<Incoming>, header: K) -> Option<String>
    where
        K: AsHeaderName,
    {
        res.headers()
            .get(header)
            .and_then(|header| header.to_str().ok())
            .map(ToString::to_string)
    }

    fn parse_header<T, K>(res: &Response<Incoming>, header: K) -> Result<T, Error>
    where
        T: FromStr,
        K: AsHeaderName,
    {
        res.headers()
            .get(header)
            .and_then(|header| header.to_str().ok())
            .and_then(|header| header.parse().ok())
            .ok_or(Error::Unsupported)
    }
}
