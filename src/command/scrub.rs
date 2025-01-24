use crate::command;
use crate::registry::Registry;
use argh::FromArgs;
use chrono::Duration;
use std::collections::HashSet;
use std::process::exit;
use std::sync::Arc;
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
    pub upload_timeout: Option<u32>, // TODO: use something more human friendly
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
    registry: Arc<Registry>,
    enabled_checks: HashSet<ScrubCheck>,
}

impl Command {
    pub fn new(options: &Options, registry: Registry) -> Self {
        let upload_timeout = options
            .upload_timeout
            .map_or(Duration::days(1), |s| Duration::seconds(s.into()));

        let registry = registry
            .with_dry_run(options.dry_mode)
            .with_upload_timeout(upload_timeout);

        let registry = Arc::new(registry);

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

        Self {
            registry,
            enabled_checks,
        }
    }

    pub async fn run(&self) -> Result<(), command::Error> {
        let mut marker = None;
        loop {
            let Ok((namespaces, next_marker)) = self.registry.list_catalog(Some(100), marker).await
            else {
                error!("Failed to read catalog");
                exit(1);
            };

            for namespace in namespaces {
                if self.enabled_checks.contains(&ScrubCheck::Retention) {
                    let _ = self.registry.enforce_retention(&namespace).await;
                }

                if self.enabled_checks.contains(&ScrubCheck::Uploads) {
                    // Step 1: check upload directories
                    // - for incomplete uploads (threshold from config file)
                    // - delete corrupted upload directories (here we are incompatible with docker "distribution")
                    let _ = self.registry.scrub_uploads(&namespace).await;
                }

                if self.enabled_checks.contains(&ScrubCheck::Tags) {
                    // Step 2: for each manifest tags "_manifests/tags/<tag-name>/current/link", ensure the
                    // revision exists: "_manifests/revisions/sha256/<hash>/link"
                    let _ = self.registry.scrub_tags(&namespace).await;
                }

                if self.enabled_checks.contains(&ScrubCheck::Revisions) {
                    // Step 3: for each revision "_manifests/revisions/sha256/<hash>/link", read the manifest,
                    // and ensure related links exists
                    let _ = self.registry.scrub_revisions(&namespace).await;
                }
            }

            if next_marker.is_none() {
                break;
            }

            marker = next_marker;
        }

        if self.enabled_checks.contains(&ScrubCheck::Blobs) {
            // Step 4: blob garbage collection
            let _ = self.registry.cleanup_orphan_blobs().await;
        }

        Ok(())
    }
}
