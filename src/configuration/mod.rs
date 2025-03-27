use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

mod data_size;
mod error;

pub use data_size::DataSize;
pub use error::Error;

lazy_static! {
    // This regex is used to validate repository names.
    // We choose to have the same constraints as namespaces initial part.
    static ref REPOSITORY_RE: Regex =
        Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$").unwrap();
}

#[derive(Clone, Debug, Deserialize)]
pub struct Configuration {
    #[serde(default = "Configuration::default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
    pub server: ServerConfig,
    #[serde(default)]
    pub lock_store: LockStoreConfig,
    #[serde(default)]
    pub cache_store: CacheStoreConfig,
    #[serde(default)]
    pub storage: DataStoreConfig,
    #[serde(default)]
    pub identity: HashMap<String, IdentityConfig>, // hashmap of identity_id <-> identity_config (username, password)
    #[serde(default)]
    pub repository: HashMap<String, RepositoryConfig>, // hashmap of namespace <-> repository_config
    #[serde(default)]
    pub observability: Option<ObservabilityConfig>,
}

impl Configuration {
    fn default_max_concurrent_requests() -> usize {
        50
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub bind_address: IpAddr,
    #[serde(default = "ServerConfig::default_port")]
    pub port: u16,
    #[serde(default = "ServerConfig::default_query_timeout")]
    pub query_timeout: u64,
    #[serde(default = "ServerConfig::default_query_timeout_grace_period")]
    pub query_timeout_grace_period: u64,
    pub tls: Option<ServerTlsConfig>,
}

impl ServerConfig {
    fn default_port() -> u16 {
        8000
    }

    fn default_query_timeout() -> u64 {
        3600
    }

    fn default_query_timeout_grace_period() -> u64 {
        60
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct LockStoreConfig {
    pub redis: Option<RedisLockStoreConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RedisLockStoreConfig {
    pub url: String,
    pub ttl: usize,
    #[serde(default)]
    pub key_prefix: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct CacheStoreConfig {
    pub redis: Option<RedisCacheConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RedisCacheConfig {
    pub url: String,
    #[serde(default)]
    pub key_prefix: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerTlsConfig {
    pub server_certificate_bundle: String,
    pub server_private_key: String,
    pub client_ca_bundle: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
// This is acceptable to have a large enum variant for configuration things.
#[allow(clippy::large_enum_variant)]
pub enum DataStoreConfig {
    #[serde(rename = "fs")]
    FS(StorageFSConfig),
    #[serde(rename = "s3")]
    S3(StorageS3Config),
}

impl Default for DataStoreConfig {
    fn default() -> Self {
        DataStoreConfig::FS(StorageFSConfig::default())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct StorageFSConfig {
    pub root_dir: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct StorageS3Config {
    pub access_key_id: String,
    pub secret_key: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub key_prefix: Option<String>,
    #[serde(default = "StorageS3Config::default_multipart_copy_threshold")]
    pub multipart_copy_threshold: DataSize,
    #[serde(default = "StorageS3Config::default_multipart_copy_chunk_size")]
    pub multipart_copy_chunk_size: DataSize,
    #[serde(default = "StorageS3Config::default_multipart_copy_jobs")]
    pub multipart_copy_jobs: usize,
    #[serde(default = "StorageS3Config::default_multipart_part_size")]
    pub multipart_part_size: DataSize,
}

impl StorageS3Config {
    fn default_multipart_copy_threshold() -> DataSize {
        DataSize::WithUnit(5, "GB".to_string())
    }

    fn default_multipart_copy_chunk_size() -> DataSize {
        DataSize::WithUnit(100, "MB".to_string())
    }

    fn default_multipart_copy_jobs() -> usize {
        4
    }

    fn default_multipart_part_size() -> DataSize {
        DataSize::WithUnit(100, "MIB".to_string())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityConfig {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RepositoryConfig {
    #[serde(default)]
    pub upstream: Vec<RepositoryUpstreamConfig>,
    #[serde(default)]
    pub access_policy: RepositoryAccessPolicyConfig,
    #[serde(default)]
    pub retention_policy: RepositoryRetentionPolicyConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RepositoryUpstreamConfig {
    pub url: String,
    #[serde(default = "RepositoryUpstreamConfig::default_max_redirect")]
    pub max_redirect: u8,
    pub server_ca_bundle: Option<String>,
    pub client_certificate: Option<String>,
    pub client_private_key: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl RepositoryUpstreamConfig {
    fn default_max_redirect() -> u8 {
        5
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RepositoryAccessPolicyConfig {
    #[serde(default)]
    pub default_allow: bool,
    #[serde(default)]
    pub rules: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RepositoryRetentionPolicyConfig {
    pub rules: Vec<String>,
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

        if let DataStoreConfig::S3(storage) = &config.storage {
            if storage.multipart_part_size.to_usize() < 50 * 1024 * 1024 {
                return Err(Error::StreamingChunkSize(
                    "Multipart part size must be at least 50MiB".to_string(),
                ));
            }
        };
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_minimal_config() {
        let config = r#"
        [server]
        bind_address = "0.0.0.0"
        "#;

        let config = Configuration::load_from_str(config).unwrap();

        assert_eq!(config.max_concurrent_requests, 50);
        assert_eq!(
            config.server.bind_address.to_string(),
            "0.0.0.0".to_string()
        );
        assert_eq!(config.server.port, 8000);
        assert_eq!(config.server.query_timeout, 3600);
        assert_eq!(config.server.query_timeout_grace_period, 60);
        assert!(config.lock_store.redis.is_none());
        assert!(config.cache_store.redis.is_none());
        assert_eq!(
            config.storage,
            DataStoreConfig::FS(StorageFSConfig {
                root_dir: "".to_string()
            })
        );
        assert!(config.identity.is_empty());
        assert!(config.repository.is_empty());
        assert!(config.observability.is_none());
    }
}
