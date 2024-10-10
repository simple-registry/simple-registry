mod blob;
mod content_discovery;
mod manifest;
mod upload;

use cel_interpreter::Program;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};

pub use blob::BlobData;
pub use upload::NewUpload;

use crate::error::RegistryError;
use crate::storage::StorageEngine;

lazy_static! {
    static ref REPOSITORY_NAME_RE: Regex =
        Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$").unwrap();
}

pub struct Registry<T>
where
    T: StorageEngine,
{
    pub storage: T,
    pub credentials: HashMap<String, (String, String)>,
    pub namespaces: HashSet<String>,
    pub namespace_default_allow: HashMap<String, bool>,
    pub namespace_policies: HashMap<String, Vec<Program>>,
}

impl<T> Registry<T>
where
    T: StorageEngine,
{
    pub fn validate_namespace(&self, namespace: &str) -> Result<(), RegistryError> {
        if REPOSITORY_NAME_RE.is_match(namespace) {
            Ok(())
        } else {
            Err(RegistryError::NameInvalid)
        }
    }

    pub fn validate_credentials(
        &self,
        credentials: &Option<(String, String)>,
    ) -> Result<Option<String>, RegistryError> {
        let Some((username, password)) = credentials else {
            return Ok(None);
        };

        let (identity_id, identity_password) = self
            .credentials
            .get(username)
            .ok_or_else(|| RegistryError::Unauthorized("Invalid credentials".to_string()))?;

        if !identity_password.eq(password) {
            // TODO: use a hash algorithm instead of plain text password :-/
            return Err(RegistryError::Unauthorized(
                "Invalid credentials".to_string(),
            ));
        }

        Ok(Some(identity_id.clone()))
    }

    pub fn is_namespace_policy_default_allow(&self, namespace: &str) -> bool {
        *self
            .namespace_default_allow
            .get(namespace)
            .unwrap_or(&false)
    }

    pub fn get_namespace_policies(&self, namespace: &str) -> Option<&Vec<Program>> {
        self.namespace_policies.get(namespace)
    }
}

pub fn extract_namespace(name: String) -> String {
    // TODO: match self.namespace entries instead!

    let mut namespace_parts = Vec::new();
    for namespace in name.split('/') {
        namespace_parts.push(namespace);
    }

    namespace_parts.pop();
    namespace_parts.join("/")
}
