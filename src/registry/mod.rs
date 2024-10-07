mod blob;
mod content_discovery;
mod manifest;
mod upload;

use lazy_static::lazy_static;
use regex::Regex;

use crate::error::RegistryError;
use crate::storage::StorageEngine;

pub use blob::BlobData;
pub use upload::NewUpload;

lazy_static! {
    static ref REPOSITORY_NAME_RE: Regex =
        Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$").unwrap();
}

pub struct Registry<T>
where
    T: StorageEngine,
{
    pub storage: T,
}

impl<T> Registry<T>
where
    T: StorageEngine,
{
    fn validate_namespace(&self, namespace: &str) -> Result<(), RegistryError> {
        if REPOSITORY_NAME_RE.is_match(namespace) {
            Ok(())
        } else {
            Err(RegistryError::NameInvalid)
        }
    }
}
