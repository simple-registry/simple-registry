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
    pub locking: LockingConfig,
    #[serde(default)]
    pub storage: StorageConfig,
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
    pub port: u16,
    #[serde(default = "ServerConfig::default_query_timeout")]
    pub query_timeout: u64,
    #[serde(default = "ServerConfig::default_query_timeout_grace_period")]
    pub query_timeout_grace_period: u64,
    pub tls: Option<ServerTlsConfig>,
    #[serde(default = "ServerConfig::default_streaming_chunk_size")]
    pub streaming_chunk_size: DataSize,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct LockingConfig {
    pub redis: Option<RedisLockingConfig>,
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

    fn default_streaming_chunk_size() -> DataSize {
        DataSize::WithUnit(50, "MiB".to_string())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerTlsConfig {
    pub server_certificate_bundle: String,
    pub server_private_key: String,
    pub client_ca_bundle: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StorageConfig {
    pub fs: Option<StorageFSConfig>,
    pub s3: Option<StorageS3Config>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            fs: Some(StorageFSConfig::default()),
            s3: None,
        }
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
    #[serde(default = "StorageS3Config::default_multipart_copy_threshold")]
    pub multipart_copy_threshold: DataSize,
    #[serde(default = "StorageS3Config::default_multipart_copy_chunk_size")]
    pub multipart_copy_chunk_size: DataSize,
    #[serde(default = "StorageS3Config::default_multipart_copy_jobs")]
    pub multipart_copy_jobs: usize,
    #[serde(default = "StorageS3Config::default_multipart_min_part_size")]
    pub multipart_min_part_size: DataSize,
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

    fn default_multipart_min_part_size() -> DataSize {
        DataSize::WithUnit(5, "MB".to_string())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityConfig {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
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
        let config: Self = toml::from_str(&config_str)?;

        if config.server.streaming_chunk_size.to_usize() < 5 * 1024 * 1024 {
            return Err(Error::StreamingChunkSize(
                "Streaming chunk size must be at least 5MiB".to_string(),
            ));
        }

        Ok(config)
    }
}
