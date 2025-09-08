use bytesize::ByteSize;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

mod error;

use crate::registry::{blob_store, cache, metadata_store};
pub use error::Error;

#[derive(Clone, Debug, Deserialize)]
pub struct Configuration {
    pub server: ServerConfig,
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub cache_store: CacheStoreConfig,
    #[serde(default, alias = "storage")]
    pub blob_store: BlobStorageConfig,
    #[serde(default)]
    pub metadata_store: MetadataStoreConfig,
    #[serde(default)]
    pub identity: HashMap<String, IdentityConfig>, // hashmap of identity_id <-> identity_config (username, password)
    #[serde(default)]
    pub repository: HashMap<String, RepositoryConfig>, // hashmap of namespace <-> repository_config
    #[serde(default)]
    pub observability: Option<ObservabilityConfig>,
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

#[derive(Clone, Debug, Deserialize)]
pub struct ServerTlsConfig {
    pub server_certificate_bundle: String,
    pub server_private_key: String,
    pub client_ca_bundle: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "GlobalConfig::default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
    #[serde(default = "GlobalConfig::default_max_concurrent_cache_jobs")]
    pub max_concurrent_cache_jobs: usize,
    #[serde(default = "GlobalConfig::default_update_pull_time")]
    pub update_pull_time: bool,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        GlobalConfig {
            max_concurrent_requests: GlobalConfig::default_max_concurrent_requests(),
            max_concurrent_cache_jobs: GlobalConfig::default_max_concurrent_cache_jobs(),
            update_pull_time: GlobalConfig::default_update_pull_time(),
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

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub enum CacheStoreConfig {
    #[default]
    #[serde(rename = "memory")]
    Memory,
    #[serde(rename = "redis")]
    Redis(cache::redis::BackendConfig),
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum BlobStorageConfig {
    #[serde(rename = "fs")]
    FS(blob_store::fs::BackendConfig),
    #[serde(rename = "s3")]
    S3(blob_store::s3::BackendConfig),
}

impl Default for BlobStorageConfig {
    fn default() -> Self {
        BlobStorageConfig::FS(blob_store::fs::BackendConfig::default())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum MetadataStoreConfig {
    #[serde(rename = "fs")]
    FS(metadata_store::fs::BackendConfig),
    #[serde(rename = "s3")]
    S3(metadata_store::s3::BackendConfig),
    #[serde(skip_deserializing)]
    #[default]
    Unspecified,
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
        let mut config: Configuration = toml::from_str(slice).map_err(|e| {
            println!("Configuration file format error:");
            println!("{e}");
            Error::ConfigurationFileFormat(e.to_string())
        })?;

        // Resolve Unspecified metadata_store based on blob_store configuration
        if matches!(config.metadata_store, MetadataStoreConfig::Unspecified) {
            config.metadata_store = match &config.blob_store {
                BlobStorageConfig::FS(cfg) => {
                    MetadataStoreConfig::FS(metadata_store::fs::BackendConfig {
                        root_dir: cfg.root_dir.clone(),
                        redis: None,
                        sync_to_disk: cfg.sync_to_disk,
                    })
                }
                BlobStorageConfig::S3(cfg) => {
                    tracing::info!("Auto-configuring S3 metadata-store from blob-store");
                    MetadataStoreConfig::S3(metadata_store::s3::BackendConfig {
                        bucket: cfg.bucket.clone(),
                        region: cfg.region.clone(),
                        endpoint: cfg.endpoint.clone(),
                        access_key_id: cfg.access_key_id.clone(),
                        secret_key: cfg.secret_key.clone(),
                        key_prefix: cfg.key_prefix.clone(),
                        redis: None,
                    })
                }
            };
        }

        if let BlobStorageConfig::S3(s3_storage) = &config.blob_store {
            if s3_storage.multipart_part_size < ByteSize::mib(5) {
                return Err(Error::StreamingChunkSize(
                    "Multipart part size must be at least 5MiB".to_string(),
                ));
            }
            if s3_storage.multipart_copy_chunk_size > ByteSize::gib(5) {
                return Err(Error::StreamingChunkSize(
                    "Multipart copy chunk size must be at most 5GiB".to_string(),
                ));
            }
        }
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

        assert_eq!(config.global.max_concurrent_requests, 4);
        assert_eq!(config.global.max_concurrent_cache_jobs, 4);
        assert!(!config.global.update_pull_time);

        let bind_address = config.server.bind_address.to_string();
        assert_eq!(bind_address, "0.0.0.0".to_string());
        assert_eq!(config.server.port, 8000);
        assert_eq!(config.server.query_timeout, 3600);
        assert_eq!(config.server.query_timeout_grace_period, 60);
        assert_eq!(config.cache_store, CacheStoreConfig::Memory);

        assert_eq!(config.blob_store, BlobStorageConfig::default());

        assert!(config.identity.is_empty());
        assert!(config.repository.is_empty());
        assert!(config.observability.is_none());
    }

    #[tokio::test]
    async fn test_metadata_store_defaults_with_s3_blob_store() {
        // When using S3 blob store and no metadata store is specified,
        // it should auto-configure S3 metadata store
        let config = r#"
        [server]
        bind_address = "0.0.0.0"
        
        [blob_store.s3]
        bucket = "test-bucket"
        region = "us-east-1"
        endpoint = "http://localhost:9000"
        access_key_id = "test-key"
        secret_key = "test-secret"
        "#;

        let config = Configuration::load_from_str(config).unwrap();

        // Should auto-configure S3 metadata store with same settings
        match config.metadata_store {
            MetadataStoreConfig::S3(ref meta_cfg) => {
                assert_eq!(meta_cfg.bucket, "test-bucket");
                assert_eq!(meta_cfg.region, "us-east-1");
                assert_eq!(meta_cfg.endpoint, "http://localhost:9000");
                assert_eq!(meta_cfg.access_key_id, "test-key");
                assert_eq!(meta_cfg.secret_key, "test-secret");
            }
            _ => panic!("Expected S3 metadata store to be auto-configured"),
        }
    }

    #[tokio::test]
    async fn test_metadata_store_defaults_with_fs_blob_store() {
        // When using FS blob store and no metadata store is specified,
        // it should use FS metadata store with same root_dir
        let config = r#"
        [server]
        bind_address = "0.0.0.0"
        
        [blob_store.fs]
        root_dir = "/data/registry"
        sync_to_disk = true
        "#;

        let config = Configuration::load_from_str(config).unwrap();

        // Should use FS metadata store with same root_dir
        match config.metadata_store {
            MetadataStoreConfig::FS(ref meta_cfg) => {
                assert_eq!(meta_cfg.root_dir, "/data/registry");
                assert!(meta_cfg.sync_to_disk);
            }
            _ => panic!("Expected FS metadata store"),
        }
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
        match config.blob_store {
            BlobStorageConfig::FS(ref cfg) => {
                assert_eq!(cfg.root_dir, "/data/registry");
            }
            BlobStorageConfig::S3(_) => panic!("Expected FS blob store from 'storage' field"),
        }

        // Should auto-configure metadata store based on blob store
        match config.metadata_store {
            MetadataStoreConfig::FS(ref cfg) => {
                assert_eq!(cfg.root_dir, "/data/registry");
            }
            _ => panic!("Expected FS metadata store to be auto-configured"),
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
            MetadataStoreConfig::FS(ref meta_cfg) => {
                assert_eq!(meta_cfg.root_dir, "/custom/metadata/path");
            }
            _ => panic!("Expected explicitly configured FS metadata store to be preserved"),
        }
    }
}
