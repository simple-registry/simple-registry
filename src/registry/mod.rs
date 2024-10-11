mod blob;
mod content_discovery;
mod manifest;
mod upload;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use cel_interpreter::Program;
use lazy_static::lazy_static;
use log::error;
use regex::Regex;
use std::collections::{HashMap, HashSet};

pub use blob::BlobData;
pub use upload::NewUpload;

use crate::config::Config;
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
    pub fn from_config(config: &Config, storage: T) -> Self {
        Self {
            storage,
            credentials: config.build_credentials(),
            namespaces: config.build_namespace_list(),
            namespace_default_allow: config.build_namespace_default_allow_list(),
            namespace_policies: config
                .build_namespace_policies()
                .expect("Failed to build policy rules"),
        }
    }

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

        let identity_password = PasswordHash::new(identity_password).map_err(|e| {
            error!("Unable to hash password: {}", e);
            RegistryError::Unauthorized("Unable to verify credentials".to_string())
        })?;

        Argon2::default()
            .verify_password(password.as_bytes(), &identity_password)
            .map_err(|e| {
                error!("Unable to verify password: {}", e);
                RegistryError::Unauthorized("Invalid credentials".to_string())
            })?;

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
