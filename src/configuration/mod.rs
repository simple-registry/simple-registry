use crate::error::RegistryError;
use crate::lock_manager::LockManager;
use crate::storage::{FileSystemStorageEngine, S3StorageEngine, StorageEngine};
use cel_interpreter::Program;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use tracing::{debug, error, info};

mod data_size;

pub use data_size::DataSize;

lazy_static! {
    // This regex is used to validate repository names.
    // We choose to have the same constraints as namespaces initial part.
    static ref REPOSITORY_RE: Regex =
        Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$").unwrap();
}

#[derive(Clone, Debug, Deserialize)]
pub struct Configuration {
    pub server: ServerConfig,
    pub locking: Option<LockingConfig>,
    pub storage: StorageConfig,
    #[serde(default)]
    pub identity: HashMap<String, IdentityConfig>, // hashmap of identity_id <-> identity_config (username, password)
    #[serde(default)]
    pub repository: Vec<RepositoryConfig>,
    #[serde(default)]
    pub observability: Option<ObservabilityConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub bind_address: IpAddr,
    pub port: u16,
    #[serde(default = "ServerConfig::default_query_timeout")]
    pub query_timeout: u64,
    #[serde(default = "ServerConfig::default_query_timeout_grace_period")]
    pub query_timeout_grace_period: u64,
    pub tls: Option<ServerTlsConfig>,
    #[serde(default)]
    pub streaming_chunk_size: DataSize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LockingConfig {
    #[serde(flatten)]
    pub backend: LockingBackendConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub enum LockingBackendConfig {
    #[serde(rename = "redis")]
    Redis(RedisLockingConfig),
}

#[derive(Clone, Debug, Deserialize)]
pub struct RedisLockingConfig {
    pub url: String,
    pub ttl: usize,
}

impl ServerConfig {
    fn default_query_timeout() -> u64 {
        3600
    }

    fn default_query_timeout_grace_period() -> u64 {
        60
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerTlsConfig {
    pub server_certificate_bundle: String,
    pub server_private_key: String,
    pub client_ca_bundle: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct StorageConfig {
    #[serde(flatten)]
    pub backend: StorageBackendConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub enum StorageBackendConfig {
    #[serde(rename = "fs")]
    FS(StorageFSConfig),
    #[serde(rename = "s3")]
    S3(StorageS3Config),
}

impl Default for StorageBackendConfig {
    fn default() -> Self {
        StorageBackendConfig::FS(StorageFSConfig::default())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct StorageFSConfig {
    pub root_dir: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StorageS3Config {
    pub access_key_id: String,
    pub secret_key: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub key_prefix: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityConfig {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RepositoryConfig {
    pub namespace: String,
    pub policy_default_allow: bool,
    #[serde(default)]
    pub policies: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub tracing: Option<TracingConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TracingConfig {
    // TODO: additional options
    pub sampling_rate: f64,
}

impl Configuration {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, RegistryError> {
        let config_str = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&config_str)?;

        if config.server.streaming_chunk_size.as_bytes() < 5 * 1024 * 1024 {
            return Err(RegistryError::InternalServerError(Some(
                "Streaming chunk size must be at least 5MiB".to_string(),
            )));
        }

        Ok(config)
    }

    pub fn build_lock_manager(&self) -> Result<LockManager, RegistryError> {
        match &self.locking {
            Some(LockingConfig { backend }) => match backend {
                LockingBackendConfig::Redis(redis_config) => {
                    info!("Building Redis lock manager");
                    LockManager::new_redis(&redis_config.url, redis_config.ttl)
                }
            },
            None => {
                info!("Building in-memory lock manager");
                Ok(LockManager::new_in_memory())
            }
        }
    }

    pub fn build_storage_engine(&self) -> Result<Box<dyn StorageEngine>, RegistryError> {
        match &self.storage.backend {
            StorageBackendConfig::FS(fs_config) => Ok(Box::new(FileSystemStorageEngine::new(
                fs_config.root_dir.clone(),
                self.build_lock_manager()?,
            ))),
            StorageBackendConfig::S3(s3_config) => Ok(Box::new(S3StorageEngine::new(
                s3_config,
                self.build_lock_manager()?,
            )?)),
        }
    }

    pub fn build_credentials(&self) -> HashMap<String, (String, String)> {
        let mut credentials_map = HashMap::new();
        for (identity_id, identity_config) in self.identity.iter() {
            credentials_map.insert(
                identity_config.username.clone(),
                (identity_id.clone(), identity_config.password.clone()),
            );
        }
        credentials_map
    }

    pub fn build_repositories_list(&self) -> HashSet<String> {
        let mut namespace_set = HashSet::new();
        for repo in self.repository.iter() {
            if !REPOSITORY_RE.is_match(&repo.namespace) {
                error!("Invalid repository name: {}", repo.namespace);
                continue;
            }
            namespace_set.insert(repo.namespace.clone());
        }
        namespace_set
    }

    pub fn build_repository_default_allow_list(&self) -> HashMap<String, bool> {
        let mut policy_default_allow_map = HashMap::new();
        for repo in self.repository.iter() {
            policy_default_allow_map.insert(repo.namespace.clone(), repo.policy_default_allow);
        }
        policy_default_allow_map
    }

    pub fn build_repository_policies(
        &self,
    ) -> Result<HashMap<String, Vec<Program>>, RegistryError> {
        let mut policy_rules_map = HashMap::new();
        for repo in &self.repository {
            let mut policies = Vec::new();

            for policy in &repo.policies {
                debug!("Compiling policy: {}", policy);
                let program = Program::compile(policy)?;
                policies.push(program);
            }

            debug!(
                "Compiled {} policies for namespace {}",
                policies.len(),
                repo.namespace
            );
            policy_rules_map.insert(repo.namespace.clone(), policies);
        }

        Ok(policy_rules_map)
    }
}
