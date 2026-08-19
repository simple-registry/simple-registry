use std::path::PathBuf;

use serde::{Deserialize, Deserializer, de::IgnoredAny};

use crate::registry::{blob_store, s3_connection::S3ConnectionConfig};

// The deprecated coordination keys a `[metadata_store]` sub-table may still
// carry (`lock_strategy` with its `redis`/`s3` sub-tables, a bare `redis`
// table, `conditional_operations`) configured the removed transaction engine.
// They parse as ignored raw values so existing configs keep loading, and are
// silently ignored.

// FS backend config

#[derive(Clone, Debug, PartialEq)]
pub struct MetadataFsConfig {
    pub root_dir: PathBuf,
    pub sync_to_disk: bool,
}

impl Default for MetadataFsConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::new(),
            sync_to_disk: false,
        }
    }
}

impl<'de> Deserialize<'de> for MetadataFsConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            root_dir: PathBuf,
            #[serde(default)]
            redis: Option<IgnoredAny>,
            #[serde(default)]
            lock_strategy: Option<IgnoredAny>,
            #[serde(default)]
            sync_to_disk: bool,
        }

        let raw = Raw::deserialize(deserializer)?;
        let _ = (raw.redis, raw.lock_strategy);
        Ok(MetadataFsConfig {
            root_dir: raw.root_dir,
            sync_to_disk: raw.sync_to_disk,
        })
    }
}

// S3 backend config

#[derive(Clone, Debug, PartialEq)]
pub struct MetadataS3Config {
    pub connection: S3ConnectionConfig,
    pub link_cache_ttl: u64,
    pub access_time_debounce_secs: u64,
}

impl Default for MetadataS3Config {
    fn default() -> Self {
        Self {
            connection: S3ConnectionConfig::default(),
            link_cache_ttl: default_link_cache_ttl(),
            access_time_debounce_secs: default_access_time_debounce(),
        }
    }
}

impl<'de> Deserialize<'de> for MetadataS3Config {
    // Custom impl because the deprecated coordination keys must parse as
    // ignored raw values (sub-tables included) without erroring.
    // The connection fields come in flat alongside the metadata-specific
    // keys; flattening `S3ConnectionConfig` preserves its required/optional
    // contract (all required except `key_prefix`).
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(flatten)]
            connection: S3ConnectionConfig,
            #[serde(default)]
            redis: Option<IgnoredAny>,
            #[serde(default)]
            lock_strategy: Option<IgnoredAny>,
            #[serde(default = "default_link_cache_ttl")]
            link_cache_ttl: u64,
            #[serde(default = "default_access_time_debounce")]
            access_time_debounce_secs: u64,
            #[serde(default)]
            conditional_operations: Option<IgnoredAny>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let _ = (raw.redis, raw.lock_strategy, raw.conditional_operations);
        Ok(MetadataS3Config {
            connection: raw.connection,
            link_cache_ttl: raw.link_cache_ttl,
            access_time_debounce_secs: raw.access_time_debounce_secs,
        })
    }
}

fn default_link_cache_ttl() -> u64 {
    30
}

fn default_access_time_debounce() -> u64 {
    60
}

// RegistryStorageConfig

/// Unified storage configuration for both the metadata store and the job store.
///
/// Both subsystems share the same `ObjectStore` built once at startup by the
/// CLI bootstrap (`crate::command::bootstrap::build_store`); this module
/// carries only the parsed configuration.
///
/// The operator-facing TOML key remains `[metadata_store]` (with `.fs` or
/// `.s3` sub-tables). The `Inherit` variant is the default and resolves to
/// the blob-store configuration at startup.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum RegistryStorageConfig {
    /// Inherit blob-store credentials and root path.
    ///
    /// Resolved via [`crate::configuration::Configuration::resolve_registry_storage`]
    /// before any backend is built. Reaching the bootstrap's `build_store`
    /// with this variant is a programming error.
    #[default]
    Inherit,
    #[serde(rename = "fs")]
    FS(MetadataFsConfig),
    #[serde(rename = "s3")]
    S3(MetadataS3Config),
}

/// A [`RegistryStorageConfig`] after its `Inherit` default has been resolved to
/// a concrete backend by
/// [`Configuration::resolve_registry_storage`](crate::configuration::Configuration::resolve_registry_storage).
/// Having only two variants lets every consumer match without a dead `Inherit`
/// arm.
#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ResolvedStorageConfig {
    FS(MetadataFsConfig),
    S3(MetadataS3Config),
}

impl ResolvedStorageConfig {
    /// Build a `ResolvedStorageConfig` that mirrors the given blob-store config,
    /// the resolution of the `Inherit` default.
    pub fn from_blob_store(blob: &blob_store::BlobStoreConfig) -> Self {
        match blob {
            blob_store::BlobStoreConfig::FS(config) => {
                ResolvedStorageConfig::FS(MetadataFsConfig {
                    root_dir: config.root_dir.clone(),
                    sync_to_disk: config.sync_to_disk,
                })
            }
            blob_store::BlobStoreConfig::S3(config) => {
                ResolvedStorageConfig::S3(MetadataS3Config {
                    connection: config.connection.clone(),
                    ..Default::default()
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        registry::{blob_store, s3_connection::S3ConnectionConfig},
        secret::Secret,
    };

    #[test]
    fn test_from_blob_store_fs_copies_paths_and_sync() {
        let blob = blob_store::BlobStoreConfig::FS(blob_store::FsBackendConfig {
            root_dir: PathBuf::from("/var/lib/registry"),
            sync_to_disk: true,
        });
        match ResolvedStorageConfig::from_blob_store(&blob) {
            ResolvedStorageConfig::FS(c) => {
                assert_eq!(c.root_dir, PathBuf::from("/var/lib/registry"));
                assert!(c.sync_to_disk);
            }
            ResolvedStorageConfig::S3(_) => {
                panic!("expected FS storage config")
            }
        }
    }

    #[test]
    fn test_from_blob_store_s3_copies_credentials_and_bucket() {
        let blob = blob_store::BlobStoreConfig::S3(blob_store::S3BackendConfig {
            connection: S3ConnectionConfig {
                access_key_id: Secret::new("key".to_string()),
                secret_key: Secret::new("secret".to_string()),
                endpoint: "http://localhost:9000".to_string(),
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                key_prefix: "foo".to_string(),
            },
            ..blob_store::S3BackendConfig::default()
        });
        match ResolvedStorageConfig::from_blob_store(&blob) {
            ResolvedStorageConfig::S3(c) => {
                assert_eq!(c.connection.bucket, "test-bucket");
                assert_eq!(c.connection.region, "us-east-1");
                assert_eq!(c.connection.endpoint, "http://localhost:9000");
                assert_eq!(c.connection.access_key_id.expose(), "key");
                assert_eq!(c.connection.secret_key.expose(), "secret");
                assert_eq!(c.connection.key_prefix, "foo");
            }
            ResolvedStorageConfig::FS(_) => {
                panic!("expected S3 storage config")
            }
        }
    }

    /// `[metadata_store.s3]` round-trip: flat TOML deserialises into a
    /// `MetadataS3Config` whose `connection` carries the right values and whose
    /// metadata-specific keys override their defaults.
    #[test]
    fn s3_backend_config_toml_round_trip() {
        let toml = r#"
            access_key_id            = "meta-key"
            secret_key               = "meta-secret"
            endpoint                 = "https://meta.s3.example.com"
            bucket                   = "meta-bucket"
            region                   = "eu-central-1"
            key_prefix               = "_meta"
            link_cache_ttl           = 60
            access_time_debounce_secs = 120
        "#;

        let cfg: MetadataS3Config = toml::from_str(toml).expect("deserialize");
        assert_eq!(cfg.connection.access_key_id.expose(), "meta-key");
        assert_eq!(cfg.connection.secret_key.expose(), "meta-secret");
        assert_eq!(cfg.connection.endpoint, "https://meta.s3.example.com");
        assert_eq!(cfg.connection.bucket, "meta-bucket");
        assert_eq!(cfg.connection.region, "eu-central-1");
        assert_eq!(cfg.connection.key_prefix, "_meta");
        assert_eq!(cfg.link_cache_ttl, 60);
        assert_eq!(cfg.access_time_debounce_secs, 120);
    }

    /// Regression: `region` must be required, matching the documented schema
    /// and the behaviour before consolidation.
    #[test]
    fn s3_backend_config_requires_region() {
        let toml = r#"
            access_key_id = "k"
            secret_key    = "s"
            endpoint      = "http://localhost:9000"
            bucket        = "b"
        "#;
        let err = toml::from_str::<MetadataS3Config>(toml).expect_err("region must be required");
        assert!(
            err.to_string().contains("region"),
            "error should mention the missing `region` field, got: {err}"
        );
    }

    fn s3_toml_with(extra: &str) -> String {
        format!(
            r#"
            access_key_id = "k"
            secret_key    = "s"
            endpoint      = "http://localhost:9000"
            bucket        = "b"
            region        = "r"
            {extra}
        "#
        )
    }

    /// The deprecated coordination keys still parse, in every shape they were
    /// ever accepted in, and are silently ignored.
    #[test]
    fn deprecated_lock_keys_parse_and_are_ignored() {
        for extra in [
            "conditional_operations = false",
            r#"lock_strategy = "memory""#,
            "[lock_strategy.s3]\nttl_secs = 30",
            "[lock_strategy.redis]\nurl = \"redis://localhost\"",
            "[redis]\nurl = \"redis://localhost\"",
        ] {
            let cfg: MetadataS3Config = toml::from_str(&s3_toml_with(extra))
                .unwrap_or_else(|e| panic!("deprecated key {extra:?} must still parse: {e}"));
            assert_eq!(cfg.connection.bucket, "b");
        }
    }

    /// Same tolerance for the FS sub-table.
    #[test]
    fn deprecated_lock_keys_parse_and_are_ignored_on_fs() {
        for extra in [
            r#"lock_strategy = "memory""#,
            "[redis]\nurl = \"redis://localhost\"",
        ] {
            let toml = format!("root_dir = \"/data\"\n{extra}");
            let cfg: MetadataFsConfig = toml::from_str(&toml)
                .unwrap_or_else(|e| panic!("deprecated key {extra:?} must still parse: {e}"));
            assert_eq!(cfg.root_dir, PathBuf::from("/data"));
        }
    }
}
