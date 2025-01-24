mod retention_policy;

use crate::command;
use crate::command::scrub::retention_policy::manifest_should_be_purged;
use crate::oci::{Digest, Reference};
use crate::policy::ManifestImage;
use crate::registry::data_store::{DataLink, ReferenceInfo};
use crate::registry::{parse_manifest_digests, Registry};
use argh::FromArgs;
use chrono::{Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::process::exit;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

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
    dry_mode: bool,
    upload_timeout: Duration,
    enabled_checks: HashSet<ScrubCheck>,
}

impl Command {
    pub fn new(options: &Options, registry: Registry) -> Self {
        let registry = Arc::new(registry);

        let dry_mode = options.dry_mode;
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

        Self {
            registry,
            dry_mode,
            upload_timeout: options
                .upload_timeout
                .map_or(Duration::days(1), |s| Duration::seconds(s.into())),
            enabled_checks,
        }
    }

    pub async fn run(&self) -> Result<(), command::Error> {
        if self.dry_mode {
            info!("Dry-run mode: no changes will be made to the storage");
        }

        let mut marker = None;
        loop {
            let Ok((namespaces, next_marker)) = self
                .registry
                .storage_engine
                .list_namespaces(100, marker)
                .await
            else {
                error!("Failed to read catalog");
                exit(1);
            };

            for namespace in namespaces {
                if self.enabled_checks.contains(&ScrubCheck::Retention) {
                    let _ = self.enforce_retention(&namespace).await;
                }

                if self.enabled_checks.contains(&ScrubCheck::Uploads) {
                    // Step 1: check upload directories
                    // - for incomplete uploads (threshold from config file)
                    // - delete corrupted upload directories (here we are incompatible with docker "distribution")
                    let _ = self.scrub_uploads(&namespace).await;
                }

                if self.enabled_checks.contains(&ScrubCheck::Tags) {
                    // Step 2: for each manifest tags "_manifests/tags/<tag-name>/current/link", ensure the
                    // revision exists: "_manifests/revisions/sha256/<hash>/link"
                    let _ = self.scrub_tags(&namespace).await;
                }

                if self.enabled_checks.contains(&ScrubCheck::Revisions) {
                    // Step 3: for each revision "_manifests/revisions/sha256/<hash>/link", read the manifest,
                    // and ensure related links exists
                    let _ = self.scrub_revisions(&namespace).await;
                }
            }

            if next_marker.is_none() {
                break;
            }

            marker = next_marker;
        }

        if self.enabled_checks.contains(&ScrubCheck::Blobs) {
            // Step 4: blob garbage collection
            let _ = self.cleanup_orphan_blobs().await;
        }

        Ok(())
    }

    async fn enforce_retention(&self, namespace: &str) -> Result<(), command::Error> {
        info!("'{}': Enforcing retention policy", namespace);

        let mut marker = None;
        let mut tag_names = Vec::new();
        loop {
            let (tags, next_marker) = self
                .registry
                .storage_engine
                .list_tags(namespace, 1000, marker)
                .await?;
            tag_names.extend(tags);
            if next_marker.is_none() {
                break;
            }
            marker = next_marker;
        }

        let mut tags = HashMap::new();
        for tag in &tag_names {
            let info = self
                .registry
                .storage_engine
                .read_reference_info(namespace, &DataLink::Tag(tag.to_string()))
                .await?;
            tags.insert(tag.to_string(), info);
        }

        self.check_tag_retention(namespace, tags).await?;

        Ok(())
    }

    async fn check_tag_retention(
        &self,
        namespace: &str,
        mut tags: HashMap<String, ReferenceInfo>,
    ) -> Result<(), command::Error> {
        let tags: Vec<(String, ReferenceInfo)> = tags.drain().collect();

        let mut last_pushed = tags.clone();
        last_pushed.sort_by(|a, b| b.1.created_at.cmp(&a.1.created_at));
        let mut last_pushed = last_pushed
            .iter()
            .map(|(tag, _)| tag.clone())
            .collect::<Vec<String>>();

        let mut last_pulled = tags.clone();
        last_pulled.sort_by(|a, b| b.1.accessed_at.cmp(&a.1.accessed_at));
        let mut last_pulled = last_pulled
            .iter()
            .map(|(tag, _)| tag.clone())
            .collect::<Vec<String>>();

        for (tag, info) in &tags {
            debug!("'{}': Checking tag '{}' for retention", namespace, tag);

            let Some((_, found_repository)) = self
                .registry
                .repositories
                .iter()
                .find(|(repository, _)| namespace.starts_with(*repository))
            else {
                warn!("Unable to find repository for namespace: {}", namespace);
                return Ok(());
            };

            let manifest = ManifestImage {
                tag: Some(tag.to_string()),
                pushed_at: info.created_at.timestamp(),
                last_pulled_at: info.accessed_at.timestamp(),
            };

            if manifest_should_be_purged(
                &found_repository.retention_rules,
                &manifest,
                &last_pushed,
                &last_pulled,
            )? {
                info!("Available for cleanup: {}:{}", namespace, tag);
                if !self.dry_mode {
                    let reference = Reference::Tag(tag.to_string());
                    let _ = self.registry.delete_manifest(namespace, reference).await;

                    last_pushed.retain(|t| t != tag);
                    last_pulled.retain(|t| t != tag);
                }
            }
        }

        Ok(())
    }

    async fn scrub_uploads(&self, namespace: &str) -> Result<(), command::Error> {
        info!("'{}': Checking for obsolete uploads", namespace);

        let mut marker = None;
        loop {
            let (uploads, next_marker) = self
                .registry
                .storage_engine
                .list_uploads(namespace, 100, marker)
                .await?;

            for uuid in uploads {
                if let Err(error) = self.check_upload(namespace, &uuid).await {
                    error!("Failed to check upload '{}': {}", uuid, error);
                }
            }

            if next_marker.is_none() {
                break;
            }
            marker = next_marker;
        }

        Ok(())
    }

    async fn check_upload(&self, namespace: &str, uuid: &str) -> Result<(), command::Error> {
        let (_, _, start_date) = self
            .registry
            .storage_engine
            .read_upload_summary(namespace, uuid)
            .await?;

        let now = Utc::now();
        let duration = now.signed_duration_since(start_date);

        if duration <= self.upload_timeout {
            return Ok(());
        }

        warn!("'{}': upload '{}' is obsolete", namespace, uuid);
        if !self.dry_mode {
            if let Err(err) = self
                .registry
                .storage_engine
                .delete_upload(namespace, uuid)
                .await
            {
                error!("Failed to delete upload '{}': {}", uuid, err);
            }
        }

        Ok(())
    }

    async fn scrub_tags(&self, namespace: &str) -> Result<(), command::Error> {
        info!("'{}': Checking tags/revision inconsistencies", namespace);

        let mut marker = None;
        loop {
            let (tags, next_marker) = self
                .registry
                .storage_engine
                .list_tags(namespace, 100, marker)
                .await?;

            for tag in tags {
                if let Err(error) = self.check_tag(namespace, &tag).await {
                    error!("Failed to check tag '{}': {}", tag, error);
                }
            }

            if next_marker.is_none() {
                break;
            }
            marker = next_marker;
        }

        Ok(())
    }

    async fn check_tag(&self, namespace: &str, tag: &str) -> Result<(), command::Error> {
        debug!(
            "Checking {}:{} for revision inconsistencies",
            namespace, tag
        );
        let digest = self
            .registry
            .storage_engine
            .read_link(namespace, &DataLink::Tag(tag.to_string()))
            .await?;

        let link_reference = DataLink::Digest(digest.clone());
        if let Err(e) = self.ensure_link(namespace, &link_reference, &digest).await {
            warn!("Failed to ensure link: {}", e);
        }

        Ok(())
    }

    async fn scrub_revisions(&self, namespace: &str) -> Result<(), command::Error> {
        info!("'{}': Checking for revision inconsistencies", namespace);

        let mut marker = None;

        loop {
            let (revisions, next_marker) = self
                .registry
                .storage_engine
                .list_revisions(namespace, 0, marker)
                .await?;

            for revision in revisions {
                let content = self.registry.storage_engine.read_blob(&revision).await?;
                let manifest = parse_manifest_digests(&content, None)?;

                self.check_layers(namespace, &revision, &manifest.layers)
                    .await?;
                self.check_config(namespace, &revision, manifest.config)
                    .await?;
                self.check_subject(namespace, &revision, manifest.subject)
                    .await?;
            }

            if next_marker.is_none() {
                break;
            }

            marker = next_marker;
        }

        Ok(())
    }

    async fn check_config(
        &self,
        namespace: &str,
        revision: &Digest,
        config: Option<Digest>,
    ) -> Result<(), command::Error> {
        let Some(config_digest) = config else {
            return Ok(());
        };

        debug!(
            "Checking {}@{} config link: {}",
            namespace, revision, config_digest
        );

        let link_reference = DataLink::Config(config_digest.clone());
        self.ensure_link(namespace, &link_reference, &config_digest)
            .await?;

        Ok(())
    }

    async fn check_subject(
        &self,
        namespace: &str,
        revision: &Digest,
        subject_digest: Option<Digest>,
    ) -> Result<(), command::Error> {
        let Some(subject_digest) = subject_digest else {
            return Ok(());
        };

        debug!(
            "Checking {}@{} subject link: {}",
            namespace, revision, subject_digest
        );
        let link_reference = DataLink::Referrer(subject_digest.clone(), revision.clone());
        self.ensure_link(namespace, &link_reference, revision)
            .await?;

        Ok(())
    }

    async fn check_layers(
        &self,
        namespace: &str,
        revision: &Digest,
        layers: &Vec<Digest>,
    ) -> Result<(), command::Error> {
        for layer_digest in layers {
            debug!(
                "Checking {}@{} layer link: {}",
                namespace, revision, layer_digest
            );

            let link_reference = DataLink::Layer(layer_digest.clone());
            self.ensure_link(namespace, &link_reference, layer_digest)
                .await?;
        }

        Ok(())
    }

    async fn ensure_link(
        &self,
        namespace: &str,
        link_reference: &DataLink,
        digest: &Digest,
    ) -> Result<(), command::Error> {
        let blob_digest = self
            .registry
            .storage_engine
            .read_link(namespace, link_reference)
            .await
            .ok();

        if let Some(link_digest) = blob_digest {
            if &link_digest == digest {
                debug!("Link {:?} -> {:?} is valid", link_reference, digest);
                return Ok(());
            }
        }

        warn!(
            "Missing or invalid link: {:?} -> {:?}",
            link_reference, digest
        );
        if !self.dry_mode {
            self.registry
                .storage_engine
                .create_link(namespace, link_reference, digest)
                .await?;
        }

        Ok(())
    }

    async fn cleanup_orphan_blobs(&self) -> Result<(), command::Error> {
        info!("Checking for orphan blobs");

        let mut marker = None;
        loop {
            let Ok((blobs, next_marker)) =
                self.registry.storage_engine.list_blobs(100, marker).await
            else {
                error!("Failed to list blobs");
                exit(1);
            };

            for blob in blobs {
                self.check_blob(&blob).await?;
            }

            if next_marker.is_none() {
                break;
            }
            marker = next_marker;
        }

        Ok(())
    }

    async fn check_blob(&self, blob: &Digest) -> Result<(), command::Error> {
        let mut blob_index = self.registry.storage_engine.read_blob_index(blob).await?;

        for (namespace, references) in blob_index.namespace.clone() {
            for link_reference in references {
                if self
                    .registry
                    .storage_engine
                    .read_link(&namespace, &link_reference)
                    .await
                    .is_err()
                {
                    let Some(index) = blob_index.namespace.get_mut(&namespace) else {
                        error!("Failed to get namespace index: {}", namespace);
                        continue;
                    };

                    warn!(
                        "Orphan link: {}@{} -> {:?}",
                        namespace, blob, link_reference
                    );
                    if !self.dry_mode {
                        index.remove(&link_reference);
                    }
                }
            }
        }

        blob_index
            .namespace
            .retain(|_, references| !references.is_empty());

        if blob_index.namespace.is_empty() {
            warn!("Orphan blob: {}", blob);
            if !self.dry_mode {
                if let Err(err) = self.registry.storage_engine.delete_blob(blob).await {
                    error!("Failed to delete blob: {}", err);
                }
            }
        }
        Ok(())
    }
}
