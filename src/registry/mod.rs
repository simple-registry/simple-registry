use argon2::{Argon2, PasswordHash, PasswordVerifier};
use cel_interpreter::Program;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use tracing::{debug, error, instrument, warn};

mod blob;
mod content_discovery;
mod link_reference;
mod manifest;
mod upload;

pub use blob::BlobData;
pub use link_reference::LinkReference;
pub use manifest::parse_manifest_digests;
pub use upload::NewUpload;

use crate::config::Config;
use crate::error::RegistryError;
use crate::oci::Digest;
use crate::shared_lock::{ReadGuard, SharedRwLock, WriteGuard};
use crate::storage::{FileSystemStorageEngine, StorageEngine};

lazy_static! {
    static ref NAMESPACE_RE: Regex =
        Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$").unwrap();
}

pub struct Registry {
    pub storage: Box<dyn StorageEngine>,
    pub credentials: HashMap<String, (String, String)>,
    pub repositories: HashSet<String>,
    pub repository_default_allow: HashMap<String, bool>,
    pub repository_policies: HashMap<String, Vec<Program>>,
}

impl Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("shared_lock_manager", &"SharedRwLock")
            .field("storage", &self.storage)
            .field("credentials", &self.credentials.len())
            .field("repositories", &self.repositories.len())
            .field(
                "repository_default_allow",
                &self.repository_default_allow.len(),
            )
            .field("repository_policies", &self.repository_policies.len())
            .finish()
    }
}

impl Registry {
    #[instrument(skip(config))]
    pub fn try_from_config(config: &Config) -> Result<Self, RegistryError> {
        let res = Self {
            storage: config.build_storage_engine()?,
            credentials: config.build_credentials(),
            repositories: config.build_repositories_list(),
            repository_default_allow: config.build_repository_default_allow_list(),
            repository_policies: config.build_repository_policies()?,
        };

        Ok(res)
    }

    #[instrument]
    pub fn validate_namespace(&self, namespace: &str) -> Result<(), RegistryError> {
        if NAMESPACE_RE.is_match(namespace) {
            Ok(())
        } else {
            Err(RegistryError::NameInvalid)
        }
    }

    #[instrument(skip(credentials))]
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
            .ok_or_else(|| RegistryError::Unauthorized(Some("Invalid credentials".to_string())))?;

        let identity_password = PasswordHash::new(identity_password).map_err(|e| {
            error!("Unable to hash password: {}", e);
            RegistryError::Unauthorized(Some("Unable to verify credentials".to_string()))
        })?;

        Argon2::default()
            .verify_password(password.as_bytes(), &identity_password)
            .map_err(|e| {
                error!("Unable to verify password: {}", e);
                RegistryError::Unauthorized(Some("Invalid credentials".to_string()))
            })?;

        Ok(Some(identity_id.clone()))
    }

    #[instrument]
    pub fn get_repository(&self, namespace: &str) -> Option<String> {
        debug!("Looking for repository matching namespace: {}", namespace);
        let repository = self
            .repositories
            .iter()
            .find(|&n| namespace.starts_with(n))
            .cloned();

        debug!("Found repository: {:?}", repository);
        repository
    }

    #[instrument]
    pub fn is_repository_policy_default_allow(&self, namespace: &str) -> bool {
        *self
            .repository_default_allow
            .get(namespace)
            .unwrap_or(&false)
    }

    #[instrument]
    pub fn get_repository_policies(&self, namespace: &str) -> Option<&Vec<Program>> {
        self.repository_policies.get(namespace)
    }
}

impl Default for Registry {
    fn default() -> Self {
        let storage_engine = FileSystemStorageEngine::new(
            "./registry".to_string(),
            SharedRwLock::new_in_memory(),
        );
        Self {
            storage: Box::new(storage_engine),
            credentials: Default::default(),
            repositories: Default::default(),
            repository_default_allow: Default::default(),
            repository_policies: Default::default(),
        }
    }
}
