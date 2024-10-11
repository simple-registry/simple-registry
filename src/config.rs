use cel_interpreter::Program;
use log::{debug, error};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tokio::fs;

use crate::error::RegistryError;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub identity: HashMap<String, IdentityConfig>, // hashmap of identity_id <-> identity_config (username, password)
    #[serde(default)]
    pub repository: Vec<RepositoryConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub bind_address: String,
    pub port: u16,
    pub tls: Option<ServerTlsConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerTlsConfig {
    pub server_certificate_bundle: String,
    pub server_private_key: String,
    pub client_ca_bundle: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StorageConfig {
    pub root_dir: String,
}

#[derive(Clone, Debug, Deserialize)]
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

impl Config {
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let config_str = fs::read_to_string(path).await?;
        let config: Self = toml::from_str(&config_str)?;
        Ok(config)
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

    pub fn build_namespace_list(&self) -> HashSet<String> {
        let mut namespace_set = HashSet::new();
        for repo in self.repository.iter() {
            // TODO: validate namespace name!
            namespace_set.insert(repo.namespace.clone());
        }
        namespace_set
    }

    pub fn build_namespace_default_allow_list(&self) -> HashMap<String, bool> {
        let mut policy_default_allow_map = HashMap::new();
        for repo in self.repository.iter() {
            policy_default_allow_map.insert(repo.namespace.clone(), repo.policy_default_allow);
        }
        policy_default_allow_map
    }

    pub fn build_namespace_policies(&self) -> Result<HashMap<String, Vec<Program>>, RegistryError> {
        let mut policy_rules_map = HashMap::new();
        for repo in &self.repository {
            let mut policies = Vec::new();

            for policy in &repo.policies {
                debug!("Compiling policy: {}", policy);
                let program = Program::compile(policy).map_err(|err| {
                    error!("Failed to compile policy: {}", err);
                    RegistryError::InternalServerError
                })?; // TODO: better error please
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
