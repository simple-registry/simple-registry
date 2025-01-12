use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::fmt::Debug;
use tracing::instrument;

mod blob;
mod content_discovery;
mod error;
mod manifest;
mod repository;
mod upload;

use crate::configuration;
use crate::configuration::RepositoryConfig;
use crate::registry::repository::Repository;
use crate::storage::GenericStorageEngine;
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
    pub streaming_chunk_size: usize,
    pub storage_engine: Box<dyn GenericStorageEngine>,
    pub repositories: HashMap<String, Repository>,
}

impl Registry {
    #[instrument]
    pub fn new(
        repositories_config: HashMap<String, RepositoryConfig>,
        streaming_chunk_size: usize,
        storage_engine: Box<dyn GenericStorageEngine>,
    ) -> Result<Self, configuration::Error> {
        let mut repositories = HashMap::new();
        for (namespace, repository_config) in repositories_config {
            let res = Repository::new(&repository_config)?;
            repositories.insert(namespace, res);
        }

        let res = Self {
            streaming_chunk_size,
            storage_engine,
            repositories,
        };

        Ok(res)
    }

    #[instrument]
    pub fn validate_namespace(&self, namespace: &str) -> Result<(), Error> {
        if NAMESPACE_RE.is_match(namespace) {
            Ok(())
        } else {
            Err(Error::NameInvalid)
        }
    }
}
