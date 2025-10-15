use crate::cache;
use crate::cache::Cache;
use crate::command::scrub::error::Error;
use crate::command::scrub::Scrubber;
use crate::configuration::Configuration;
use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::{blob_store, repository, Repository, RetentionPolicy, RetentionPolicyConfig};
use argh::FromArgs;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

#[derive(FromArgs, PartialEq, Debug)]
#[allow(clippy::struct_excessive_bools)]
#[argh(
    subcommand,
    name = "scrub",
    description = "Check the storage backend for inconsistencies"
)]
pub struct Options {
    #[argh(switch, short = 'd')]
    /// only report issues, no changes will be made to the storage
    pub dry_mode: bool,
    #[argh(option, short = 't')]
    /// the maximum duration an upload can be in progress before it is considered obsolete in seconds
    pub upload_timeout: Option<humantime::Duration>,
    #[argh(switch, short = 'u')]
    /// check for obsolete uploads
    pub check_uploads: bool,
    #[argh(switch, short = 'g')]
    /// check for orphan blobs
    pub check_tags: bool,
    #[argh(switch, short = 'r')]
    /// check for revision inconsistencies
    pub check_revisions: bool,
    #[argh(switch, short = 'b')]
    /// check for blob inconsistencies
    pub check_blobs: bool,
    #[argh(switch, short = 'p')]
    /// enforce retention policies
    pub enforce_retention_policies: bool,
}

#[derive(Hash, Eq, PartialEq)]
enum ScrubCheck {
    Uploads,
    Tags,
    Revisions,
    Blobs,
    Retention,
}

pub struct Command {
    blob_store: Arc<dyn BlobStore + Send + Sync>,
    metadata_store: Arc<dyn MetadataStore + Send + Sync>,
    repositories: Arc<HashMap<String, Repository>>,
    global_retention_policy: Option<Arc<RetentionPolicy>>,
    dry_run: bool,
    upload_timeout: chrono::Duration,
    enabled_checks: HashSet<ScrubCheck>,
}

fn build_blob_store(config: &blob_store::BlobStorageConfig) -> Result<Arc<dyn BlobStore>, Error> {
    let Ok(blob_store) = config.to_backend() else {
        let msg = "Failed to initialize blob store".to_string();
        return Err(Error::Initialization(msg));
    };

    Ok(blob_store)
}

fn build_metadata_store(config: &Configuration) -> Result<Arc<dyn MetadataStore>, Error> {
    match config.resolve_metadata_config().to_backend() {
        Ok(store) => Ok(store),
        Err(err) => {
            let msg = format!("Failed to initialize metadata store: {err}");
            Err(Error::Initialization(msg))
        }
    }
}

fn build_auth_cache(config: &cache::Config) -> Result<Arc<dyn Cache>, Error> {
    match config.to_backend() {
        Ok(cache) => Ok(cache),
        Err(err) => {
            let msg = format!("Failed to initialize auth token cache: {err}");
            Err(Error::Initialization(msg))
        }
    }
}

fn build_repository(
    name: &str,
    config: &repository::Config,
    auth_cache: &Arc<dyn Cache>,
) -> Result<Repository, Error> {
    match Repository::new(name, config, auth_cache) {
        Ok(repo) => Ok(repo),
        Err(err) => {
            let msg = format!("Failed to initialize repository '{name}': {err}");
            Err(Error::Initialization(msg))
        }
    }
}

fn build_repositories(
    configs: &HashMap<String, repository::Config>,
    auth_cache: &Arc<dyn Cache>,
) -> Result<Arc<HashMap<String, Repository>>, Error> {
    let mut repositories = HashMap::new();
    for (name, config) in configs {
        let repo = build_repository(name, config, auth_cache)?;
        repositories.insert(name.clone(), repo);
    }

    Ok(Arc::new(repositories))
}

fn build_global_retention_policy(
    config: &RetentionPolicyConfig,
) -> Result<Option<Arc<RetentionPolicy>>, Error> {
    if config.rules.is_empty() {
        return Ok(None);
    }

    match RetentionPolicy::new(config) {
        Ok(policy) => Ok(Some(Arc::new(policy))),
        Err(err) => {
            let msg = format!("Failed to initialize global retention policy: {err}");
            Err(Error::Initialization(msg))
        }
    }
}

fn build_enabled_checks(options: &Options) -> HashSet<ScrubCheck> {
    let mut enabled_checks = HashSet::new();

    if options.check_uploads {
        enabled_checks.insert(ScrubCheck::Uploads);
    }

    if options.check_tags {
        enabled_checks.insert(ScrubCheck::Tags);
    }

    if options.check_revisions {
        enabled_checks.insert(ScrubCheck::Revisions);
    }

    if options.check_blobs {
        enabled_checks.insert(ScrubCheck::Blobs);
    }

    if options.enforce_retention_policies {
        enabled_checks.insert(ScrubCheck::Retention);
    }

    enabled_checks
}

impl Command {
    pub fn new(options: &Options, config: &Configuration) -> Result<Self, Error> {
        let blob_store = build_blob_store(&config.blob_store)?;
        let metadata_store = build_metadata_store(config)?;
        let auth_cache = build_auth_cache(&config.cache)?;
        let repositories = build_repositories(&config.repository, &auth_cache)?;
        let global_retention_policy =
            build_global_retention_policy(&config.global.retention_policy)?;

        let upload_timeout = options
            .upload_timeout
            .map_or(Duration::from_secs(86400), Into::into);

        let upload_timeout =
            chrono::Duration::from_std(upload_timeout).expect("Upload timeout must be valid");

        info!(
            "Upload timeout set to {} second(s)",
            upload_timeout.num_seconds()
        );

        let enabled_checks = build_enabled_checks(options);

        if options.dry_mode {
            info!("Dry-run mode: no changes will be made to the storage");
        }

        Ok(Self {
            blob_store,
            metadata_store,
            repositories,
            global_retention_policy,
            dry_run: options.dry_mode,
            upload_timeout,
            enabled_checks,
        })
    }

    pub async fn run(&self) -> Result<(), Error> {
        let scrubber = Scrubber::new(
            self.blob_store.clone(),
            self.metadata_store.clone(),
            self.repositories.clone(),
            self.global_retention_policy.clone(),
            self.dry_run,
            self.upload_timeout,
        );

        self.process_all_namespaces(&scrubber).await?;

        if self.enabled_checks.contains(&ScrubCheck::Blobs) {
            let _ = scrubber.cleanup_orphan_blobs().await;
        }

        Ok(())
    }

    async fn process_all_namespaces(&self, scrubber: &Scrubber) -> Result<(), Error> {
        let mut marker = None;
        loop {
            let Ok((namespaces, next_marker)) =
                self.metadata_store.list_namespaces(100, marker).await
            else {
                error!("Failed to read catalog");
                return Err(Error::Execution("Failed to read catalog".to_string()));
            };

            for namespace in namespaces {
                self.process_namespace(scrubber, &namespace).await;
            }

            if next_marker.is_none() {
                break;
            }

            marker = next_marker;
        }

        Ok(())
    }

    async fn process_namespace(&self, scrubber: &Scrubber, namespace: &str) {
        if self.enabled_checks.contains(&ScrubCheck::Retention) {
            let _ = scrubber.enforce_retention(namespace).await;
        }

        if self.enabled_checks.contains(&ScrubCheck::Uploads) {
            let _ = scrubber.scrub_uploads(namespace).await;
        }

        if self.enabled_checks.contains(&ScrubCheck::Tags) {
            let _ = scrubber.scrub_tags(namespace).await;
        }

        if self.enabled_checks.contains(&ScrubCheck::Revisions) {
            let _ = scrubber.scrub_revisions(namespace).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_enabled_checks_all() {
        let options = Options {
            dry_mode: false,
            upload_timeout: None,
            check_uploads: true,
            check_tags: true,
            check_revisions: true,
            check_blobs: true,
            enforce_retention_policies: true,
        };

        let checks = build_enabled_checks(&options);

        assert_eq!(checks.len(), 5);
        assert!(checks.contains(&ScrubCheck::Uploads));
        assert!(checks.contains(&ScrubCheck::Tags));
        assert!(checks.contains(&ScrubCheck::Revisions));
        assert!(checks.contains(&ScrubCheck::Blobs));
        assert!(checks.contains(&ScrubCheck::Retention));
    }

    #[test]
    fn test_build_enabled_checks_none() {
        let options = Options {
            dry_mode: false,
            upload_timeout: None,
            check_uploads: false,
            check_tags: false,
            check_revisions: false,
            check_blobs: false,
            enforce_retention_policies: false,
        };

        let checks = build_enabled_checks(&options);
        assert_eq!(checks.len(), 0);
    }

    #[test]
    fn test_build_global_retention_policy_empty() {
        let config = RetentionPolicyConfig { rules: vec![] };
        let result = build_global_retention_policy(&config);

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_build_global_retention_policy_with_rules() {
        let config = RetentionPolicyConfig {
            rules: vec!["image.pushed_at > now() - days(30)".to_string()],
        };
        let result = build_global_retention_policy(&config);

        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_build_global_retention_policy_invalid_rule() {
        let config = RetentionPolicyConfig {
            rules: vec!["invalid cel expression!!!".to_string()],
        };
        let result = build_global_retention_policy(&config);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_command_new_with_valid_config() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_string_lossy().to_string();

        let config_content = format!(
            r#"
            [blob_store.fs]
            root_dir = "{path}"

            [metadata_store.fs]
            root_dir = "{path}"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10

            [global.retention_policy]
            rules = []
            "#
        );

        let config: Configuration = toml::from_str(&config_content).unwrap();

        let options = Options {
            dry_mode: true,
            upload_timeout: Some(humantime::Duration::from(std::time::Duration::from_secs(
                3600,
            ))),
            check_uploads: true,
            check_tags: true,
            check_revisions: true,
            check_blobs: true,
            enforce_retention_policies: true,
        };

        let command = Command::new(&options, &config);

        assert!(command.is_ok());
        let cmd = command.unwrap();
        assert!(cmd.dry_run);
        assert_eq!(cmd.upload_timeout.num_seconds(), 3600);
        assert_eq!(cmd.enabled_checks.len(), 5);
    }

    #[tokio::test]
    async fn test_command_run_executes_checks() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_string_lossy().to_string();

        let config_content = format!(
            r#"
            [blob_store.fs]
            root_dir = "{path}"

            [metadata_store.fs]
            root_dir = "{path}"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10

            [global.retention_policy]
            rules = []
            "#
        );

        let config: crate::configuration::Configuration = toml::from_str(&config_content).unwrap();

        let options = Options {
            dry_mode: true,
            upload_timeout: None,
            check_uploads: true,
            check_tags: false,
            check_revisions: false,
            check_blobs: false,
            enforce_retention_policies: false,
        };

        let command = Command::new(&options, &config).unwrap();
        let result = command.run().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_command_run_with_namespace() {
        use crate::oci::Digest;
        use crate::registry::metadata_store::link_kind::LinkKind;
        use std::str::FromStr;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_string_lossy().to_string();

        let config_content = format!(
            r#"
            [blob_store.fs]
            root_dir = "{path}"

            [metadata_store.fs]
            root_dir = "{path}"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10

            [global.retention_policy]
            rules = []
            "#
        );

        let config: crate::configuration::Configuration = toml::from_str(&config_content).unwrap();

        let _blob_store = build_blob_store(&config.blob_store).unwrap();
        let metadata_store = build_metadata_store(&config).unwrap();

        let namespace = "test-namespace";
        let digest = Digest::from_str(
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )
        .unwrap();

        metadata_store
            .create_link(namespace, &LinkKind::Tag("test".to_string()), &digest)
            .await
            .unwrap();

        let options = Options {
            dry_mode: false,
            upload_timeout: None,
            check_uploads: false,
            check_tags: true,
            check_revisions: false,
            check_blobs: false,
            enforce_retention_policies: false,
        };

        let command = Command::new(&options, &config).unwrap();
        let result = command.run().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_process_namespace_executes_selected_checks() {
        use crate::oci::Digest;
        use crate::registry::metadata_store::link_kind::LinkKind;
        use std::str::FromStr;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_string_lossy().to_string();

        let config_content = format!(
            r#"
            [blob_store.fs]
            root_dir = "{path}"

            [metadata_store.fs]
            root_dir = "{path}"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10

            [global.retention_policy]
            rules = []
            "#
        );

        let config: crate::configuration::Configuration = toml::from_str(&config_content).unwrap();

        let blob_store = build_blob_store(&config.blob_store).unwrap();
        let metadata_store = build_metadata_store(&config).unwrap();

        let namespace = "test-namespace";
        let digest = Digest::from_str(
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )
        .unwrap();

        metadata_store
            .create_link(namespace, &LinkKind::Tag("test".to_string()), &digest)
            .await
            .unwrap();

        let options = Options {
            dry_mode: false,
            upload_timeout: None,
            check_uploads: true,
            check_tags: true,
            check_revisions: false,
            check_blobs: false,
            enforce_retention_policies: false,
        };

        let command = Command::new(&options, &config).unwrap();

        let scrubber = Scrubber::new(
            blob_store,
            metadata_store,
            command.repositories.clone(),
            command.global_retention_policy.clone(),
            command.dry_run,
            command.upload_timeout,
        );

        command.process_namespace(&scrubber, namespace).await;
    }

    #[tokio::test]
    async fn test_command_with_blob_check() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_string_lossy().to_string();

        let config_content = format!(
            r#"
            [blob_store.fs]
            root_dir = "{path}"

            [metadata_store.fs]
            root_dir = "{path}"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10

            [global.retention_policy]
            rules = []
            "#
        );

        let config: crate::configuration::Configuration = toml::from_str(&config_content).unwrap();

        let options = Options {
            dry_mode: true,
            upload_timeout: None,
            check_uploads: false,
            check_tags: false,
            check_revisions: false,
            check_blobs: true,
            enforce_retention_policies: false,
        };

        let command = Command::new(&options, &config).unwrap();
        assert!(command.enabled_checks.contains(&ScrubCheck::Blobs));

        let result = command.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_command_default_upload_timeout() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_string_lossy().to_string();

        let config_content = format!(
            r#"
            [blob_store.fs]
            root_dir = "{path}"

            [metadata_store.fs]
            root_dir = "{path}"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10

            [global.retention_policy]
            rules = []
            "#
        );

        let config: crate::configuration::Configuration = toml::from_str(&config_content).unwrap();

        let options = Options {
            dry_mode: false,
            upload_timeout: None,
            check_uploads: false,
            check_tags: false,
            check_revisions: false,
            check_blobs: false,
            enforce_retention_policies: false,
        };

        let command = Command::new(&options, &config).unwrap();

        assert_eq!(command.upload_timeout.num_seconds(), 86400);
    }
}
