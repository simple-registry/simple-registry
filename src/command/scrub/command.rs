use super::Scrubber;
use crate::configuration::registry::resolve_metadata_store_config;
use crate::configuration::Configuration;
use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::{Repository, RetentionPolicy};
use crate::{cache, command};
use argh::FromArgs;
use std::collections::HashMap;
use std::collections::HashSet;
use std::process::exit;
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

impl Command {
    pub fn new(options: &Options, config: &Configuration) -> Result<Self, command::Error> {
        let metadata_store_config =
            resolve_metadata_store_config(&config.blob_store, config.metadata_store.clone());

        let blob_store = config.blob_store.to_backend()?;
        let metadata_store = metadata_store_config.to_backend()?;

        let mut repositories_map = HashMap::new();
        let auth_token_cache: Arc<dyn cache::Cache> = Arc::new(cache::memory::Backend::new());

        for (repository_name, repository_config) in &config.repository {
            let res = Repository::new(
                repository_name.clone(),
                repository_config.clone(),
                &auth_token_cache,
            )?;
            repositories_map.insert(repository_name.clone(), res);
        }
        let repositories = Arc::new(repositories_map);

        let global_retention_policy = if config.global.retention_policy.rules.is_empty() {
            None
        } else {
            Some(Arc::new(RetentionPolicy::new(
                &config.global.retention_policy,
            )?))
        };

        let upload_timeout = options
            .upload_timeout
            .map_or(Duration::from_secs(86400), Into::into);

        let upload_timeout =
            chrono::Duration::from_std(upload_timeout).expect("Upload timeout must be valid");

        info!(
            "Upload timeout set to {} second(s)",
            upload_timeout.num_seconds()
        );

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

    pub async fn run(&self) -> Result<(), command::Error> {
        let scrubber = Scrubber::new(
            self.blob_store.clone(),
            self.metadata_store.clone(),
            self.repositories.clone(),
            self.global_retention_policy.clone(),
            self.dry_run,
            self.upload_timeout,
        );

        let mut marker = None;
        loop {
            let Ok((namespaces, next_marker)) =
                self.metadata_store.list_namespaces(100, marker).await
            else {
                error!("Failed to read catalog");
                exit(1);
            };

            for namespace in namespaces {
                if self.enabled_checks.contains(&ScrubCheck::Retention) {
                    let _ = scrubber.enforce_retention(&namespace).await;
                }

                if self.enabled_checks.contains(&ScrubCheck::Uploads) {
                    let _ = scrubber.scrub_uploads(&namespace).await;
                }

                if self.enabled_checks.contains(&ScrubCheck::Tags) {
                    let _ = scrubber.scrub_tags(&namespace).await;
                }

                if self.enabled_checks.contains(&ScrubCheck::Revisions) {
                    let _ = scrubber.scrub_revisions(&namespace).await;
                }
            }

            if next_marker.is_none() {
                break;
            }

            marker = next_marker;
        }

        if self.enabled_checks.contains(&ScrubCheck::Blobs) {
            let _ = scrubber.cleanup_orphan_blobs().await;
        }

        Ok(())
    }
}
