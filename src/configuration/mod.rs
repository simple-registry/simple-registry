use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

mod error;
pub mod registry;
pub mod watcher;

use crate::registry::repository::access_policy::RepositoryAccessPolicyConfig;
use crate::registry::repository::retention_policy::RepositoryRetentionPolicyConfig;
use crate::registry::server::auth::oidc;
use crate::registry::server::auth::webhook::WebhookConfig;
use crate::registry::server::listeners::{insecure, tls};
use crate::registry::{blob_store, cache, client, metadata_store};
pub use error::Error;

#[derive(Clone, Debug, Deserialize)]
pub struct Configuration {
    pub server: ServerConfig,
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default, alias = "cache_store")]
    pub cache: cache::CacheStoreConfig,
    #[serde(default, alias = "storage")]
    pub blob_store: blob_store::BlobStorageConfig,
    #[serde(default)]
    pub metadata_store: Option<metadata_store::MetadataStoreConfig>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub repository: HashMap<String, RepositoryConfig>, // hashmap of namespace <-> repository_config
    #[serde(default)]
    pub observability: Option<ObservabilityConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ServerConfig {
    Tls(tls::Config),
    Insecure(insecure::Config),
}

#[derive(Clone, Debug, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "GlobalConfig::default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
    #[serde(default = "GlobalConfig::default_max_concurrent_cache_jobs")]
    pub max_concurrent_cache_jobs: usize,
    #[serde(default = "GlobalConfig::default_update_pull_time")]
    pub update_pull_time: bool,
    #[serde(default)]
    pub access_policy: RepositoryAccessPolicyConfig,
    #[serde(default)]
    pub retention_policy: RepositoryRetentionPolicyConfig,
    #[serde(default)]
    pub immutable_tags: bool,
    #[serde(default)]
    pub immutable_tags_exclusions: Vec<String>,
    pub authorization_webhook: Option<String>,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        GlobalConfig {
            max_concurrent_requests: GlobalConfig::default_max_concurrent_requests(),
            max_concurrent_cache_jobs: GlobalConfig::default_max_concurrent_cache_jobs(),
            update_pull_time: GlobalConfig::default_update_pull_time(),
            access_policy: RepositoryAccessPolicyConfig::default(),
            retention_policy: RepositoryRetentionPolicyConfig::default(),
            immutable_tags: false,
            immutable_tags_exclusions: Vec::new(),
            authorization_webhook: None,
        }
    }
}

impl GlobalConfig {
    fn default_max_concurrent_requests() -> usize {
        4
    }

    fn default_max_concurrent_cache_jobs() -> usize {
        4
    }

    fn default_update_pull_time() -> bool {
        false
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub identity: HashMap<String, IdentityConfig>,
    #[serde(default)]
    pub oidc: HashMap<String, OidcProviderConfig>,
    #[serde(default)]
    pub webhook: HashMap<String, WebhookConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityConfig {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "provider", rename_all = "lowercase")]
pub enum OidcProviderConfig {
    Generic(oidc::provider::generic::ProviderConfig),
    GitHub(oidc::provider::github::ProviderConfig),
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RepositoryConfig {
    #[serde(default)]
    pub upstream: Vec<client::ClientConfig>,
    #[serde(default)]
    pub access_policy: RepositoryAccessPolicyConfig,
    #[serde(default)]
    pub retention_policy: RepositoryRetentionPolicyConfig,
    #[serde(default)]
    pub immutable_tags: bool,
    #[serde(default)]
    pub immutable_tags_exclusions: Vec<String>,
    pub authorization_webhook: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub tracing: Option<TracingConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TracingConfig {
    pub endpoint: String,
    pub sampling_rate: f64,
}

impl Configuration {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let config_str = fs::read_to_string(path)?;
        Self::load_from_str(&config_str)
    }

    pub fn load_from_str(slice: &str) -> Result<Self, Error> {
        let config: Configuration = toml::from_str(slice).map_err(|e| {
            println!("Configuration file format error:");
            println!("{e}");
            Error::ConfigurationFileFormat(e.to_string())
        })?;

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), Error> {
        for (name, webhook) in &self.auth.webhook {
            webhook.validate().map_err(|e| {
                Error::ConfigurationFileFormat(format!("Invalid webhook '{name}': {e}"))
            })?;
        }

        let webhook_names: std::collections::HashSet<&str> =
            self.auth.webhook.keys().map(String::as_str).collect();

        if let Some(ref webhook_name) = self.global.authorization_webhook {
            if !webhook_names.contains(webhook_name.as_str()) {
                return Err(Error::ConfigurationFileFormat(format!(
                    "Global authorization_webhook '{webhook_name}' not found in auth.webhook definitions"
                )));
            }
        }

        for (repo_name, repo_config) in &self.repository {
            if let Some(ref webhook_name) = repo_config.authorization_webhook {
                if !webhook_name.is_empty() && !webhook_names.contains(webhook_name.as_str()) {
                    return Err(Error::ConfigurationFileFormat(format!(
                        "Repository '{repo_name}' references undefined webhook '{webhook_name}'"
                    )));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::data_store;

    #[tokio::test]
    async fn test_load_minimal_config() {
        let config = r#"
        [server]
        bind_address = "0.0.0.0"
        "#;

        let config = Configuration::load_from_str(config).unwrap();

        assert_eq!(config.global.max_concurrent_requests, 4);
        assert_eq!(config.global.max_concurrent_cache_jobs, 4);
        assert!(!config.global.update_pull_time);

        let ServerConfig::Insecure(server_config) = config.server else {
            panic!("Expected Insecure server config");
        };

        let bind_address = server_config.bind_address.to_string();
        assert_eq!(bind_address, "0.0.0.0".to_string());
        assert_eq!(server_config.port, 8000);
        assert_eq!(server_config.query_timeout, 3600);
        assert_eq!(server_config.query_timeout_grace_period, 60);

        assert_eq!(config.cache, cache::CacheStoreConfig::Memory);
        assert_eq!(config.blob_store, blob_store::BlobStorageConfig::default());

        assert!(config.auth.identity.is_empty());
        assert!(config.repository.is_empty());
        assert!(config.observability.is_none());
    }

    #[tokio::test]
    async fn test_storage_field_backward_compatibility() {
        // Test that old 'storage' field is supported for backward compatibility
        let config = r#"
        [server]
        bind_address = "0.0.0.0"
        
        [storage.fs]
        root_dir = "/data/registry"
        "#;

        let config = Configuration::load_from_str(config).unwrap();

        // Should parse 'storage' as 'blob_store'
        let expected = blob_store::BlobStorageConfig::FS(data_store::fs::BackendConfig {
            root_dir: "/data/registry".to_string(),
            sync_to_disk: false,
        });
        assert_eq!(config.blob_store, expected);

        // Should autoconfigure metadata store based on blob store
        assert_eq!(config.metadata_store, None);
    }

    #[tokio::test]
    async fn test_tls_config_detection() {
        let config = r#"
        [server]
        bind_address = "0.0.0.0"
        port = 8000

        [server.tls]
        server_certificate_bundle = "server.pem"
        server_private_key = "server.key"
        "#;

        let config = Configuration::load_from_str(config).unwrap();

        match config.server {
            ServerConfig::Tls(tls_config) => {
                assert_eq!(tls_config.tls.server_certificate_bundle, "server.pem");
                assert_eq!(tls_config.tls.server_private_key, "server.key");
            }
            ServerConfig::Insecure(_) => {
                panic!("Expected TLS server config but got Insecure");
            }
        }
    }

    #[tokio::test]
    async fn test_metadata_store_explicit_config_not_overridden() {
        // When metadata store is explicitly configured, it should not be overridden
        let config = r#"
        [server]
        bind_address = "0.0.0.0"
        
        [blob_store.s3]
        bucket = "blob-bucket"
        region = "us-west-2"
        endpoint = "https://blob.example.com"
        access_key_id = "blob-key"
        secret_key = "blob-secret"
        
        [metadata_store.fs]
        root_dir = "/custom/metadata/path"
        "#;

        let config = Configuration::load_from_str(config).unwrap();

        // Should keep the explicitly configured FS metadata store
        match config.metadata_store {
            Some(metadata_store::MetadataStoreConfig::FS(config)) => {
                assert_eq!(config.root_dir, "/custom/metadata/path");
            }
            _ => panic!("Expected explicitly configured FS metadata store to be preserved"),
        }
    }

    #[tokio::test]
    async fn test_auth_section() {
        // Test auth section configuration
        let config = r#"
        [server]
        bind_address = "0.0.0.0"

        [auth.identity.user1]
        username = "bob"
        password = "password456"

        [auth.oidc.generic]
        provider = "generic"
        issuer = "https://example.com"
        discovery_url = "https://example.com/.well-known/openid-configuration"
        "#;

        let config = Configuration::load_from_str(config).unwrap();
        assert_eq!(config.auth.identity.len(), 1);
        assert_eq!(config.auth.identity["user1"].username, "bob");
        assert_eq!(config.auth.oidc.len(), 1);
        assert!(matches!(
            config.auth.oidc.get("generic"),
            Some(OidcProviderConfig::Generic(_))
        ));
    }
}
