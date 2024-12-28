use crate::error::RegistryError;
use crate::oci::Digest;
use crate::registry::{parse_manifest_digests, LinkReference, Registry};
use chrono::{Duration, Utc};
use std::io;
use std::process::exit;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

pub struct RegistryScrub {
    registry: Arc<Registry>,
    dry_mode: bool,
    upload_timeout: Duration,
    check_uploads: bool,
    check_tags: bool,
    check_revisions: bool,
    check_blobs: bool,
}

impl RegistryScrub {
    pub fn new(registry: Arc<Registry>, dry_mode: bool) -> Self {
        // TODO: customizable options
        Self {
            registry,
            dry_mode,
            upload_timeout: Duration::hours(24),
            check_uploads: true,
            check_tags: true,
            check_revisions: true,
            check_blobs: true,
        }
    }

    pub async fn scrub(&self) -> io::Result<()> {
        if self.dry_mode {
            info!("Dry-run mode: no changes will be made to the storage");
        }

        let mut marker = None;
        loop {
            let Ok((namespaces, next_marker)) =
                self.registry.storage.list_namespaces(100, marker).await
            else {
                error!("Failed to read catalog");
                exit(1);
            };

            for namespace in namespaces {
                if self.check_uploads {
                    // Step 1: check upload directories
                    // - for incomplete uploads (threshold from config file)
                    // - delete corrupted upload directories (here we are incompatible with docker "distribution")
                    let _ = self.scrub_uploads(&namespace).await;
                }

                if self.check_tags {
                    // Step 2: for each manifest tags "_manifests/tags/<tag-name>/current/link", ensure the
                    // revision exists: "_manifests/revisions/sha256/<hash>/link"
                    let _ = self.scrub_tags(&namespace).await;
                }

                if self.check_revisions {
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

        if self.check_blobs {
            // Step 4: blob garbage collection
            let _ = self.cleanup_orphan_blobs().await;
        }

        Ok(())
    }

    async fn scrub_uploads(&self, namespace: &str) -> Result<(), RegistryError> {
        info!("'{}': Checking for obsolete uploads", namespace);

        let mut marker = None;
        loop {
            let (uploads, next_marker) = self
                .registry
                .storage
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

    async fn check_upload(&self, namespace: &str, uuid: &str) -> Result<(), RegistryError> {
        let summary = self
            .registry
            .storage
            .read_upload_summary(namespace, uuid)
            .await?;

        let now = Utc::now();
        let duration = now.signed_duration_since(summary.start_date);

        if duration <= self.upload_timeout {
            return Ok(());
        }

        warn!("'{}': upload '{}' is obsolete", namespace, uuid);
        if !self.dry_mode {
            if let Err(err) = self.registry.storage.delete_upload(namespace, uuid).await {
                error!("Failed to delete upload '{}': {}", uuid, err);
            }
        }

        Ok(())
    }

    async fn scrub_tags(&self, namespace: &str) -> Result<(), RegistryError> {
        info!("'{}': Checking tags/revision inconsistencies", namespace);

        let mut marker = None;
        loop {
            let (tags, next_marker) = self
                .registry
                .storage
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

    async fn check_tag(&self, namespace: &str, tag: &str) -> Result<(), RegistryError> {
        debug!(
            "Checking {}:{} for revision inconsistencies",
            namespace, tag
        );
        let digest = self
            .registry
            .storage
            .read_link(namespace, &LinkReference::Tag(tag.to_string()))
            .await?;

        let link_reference = LinkReference::Digest(digest.clone());
        if let Err(e) = self.ensure_link(namespace, &link_reference, &digest).await {
            warn!("Failed to ensure link: {}", e);
        }

        Ok(())
    }

    async fn scrub_revisions(&self, namespace: &str) -> Result<(), RegistryError> {
        info!("'{}': Checking for revision inconsistencies", namespace);

        let mut marker = None;

        loop {
            let (revisions, next_marker) = self
                .registry
                .storage
                .list_revisions(namespace, 0, marker)
                .await?;

            for revision in revisions {
                let content = self.registry.storage.read_blob(&revision).await?;
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
    ) -> Result<(), RegistryError> {
        let Some(config_digest) = config else {
            return Ok(());
        };

        debug!(
            "Checking {}@{} config link: {}",
            namespace, revision, config_digest
        );

        let link_reference = LinkReference::Config(config_digest.clone());
        self.ensure_link(namespace, &link_reference, &config_digest)
            .await?;

        Ok(())
    }

    async fn check_subject(
        &self,
        namespace: &str,
        revision: &Digest,
        subject_digest: Option<Digest>,
    ) -> Result<(), RegistryError> {
        let Some(subject_digest) = subject_digest else {
            return Ok(());
        };

        debug!(
            "Checking {}@{} subject link: {}",
            namespace, revision, subject_digest
        );
        let link_reference = LinkReference::Referrer(subject_digest.clone(), revision.clone());
        self.ensure_link(namespace, &link_reference, revision)
            .await?;

        Ok(())
    }

    async fn check_layers(
        &self,
        namespace: &str,
        revision: &Digest,
        layers: &Vec<Digest>,
    ) -> Result<(), RegistryError> {
        for layer_digest in layers {
            debug!(
                "Checking {}@{} layer link: {}",
                namespace, revision, layer_digest
            );

            let link_reference = LinkReference::Layer(layer_digest.clone());
            self.ensure_link(namespace, &link_reference, layer_digest)
                .await?;
        }

        Ok(())
    }

    async fn ensure_link(
        &self,
        namespace: &str,
        link_reference: &LinkReference,
        digest: &Digest,
    ) -> Result<(), RegistryError> {
        let blob_digest = self
            .registry
            .storage
            .read_link(namespace, link_reference)
            .await
            .ok();

        if blob_digest != Some(digest.clone()) {
            warn!(
                "Invalid revision: expected '{:?}', found '{:?}'",
                digest, blob_digest
            );
            if !self.dry_mode {
                self.registry
                    .storage
                    .create_link(namespace, link_reference, digest)
                    .await?;
            }
        }
        Ok(())
    }

    async fn cleanup_orphan_blobs(&self) -> Result<(), RegistryError> {
        info!("Checking for orphan blobs");

        let mut marker = None;
        loop {
            let Ok((blobs, next_marker)) = self.registry.storage.list_blobs(100, marker).await
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

    async fn check_blob(&self, blob: &Digest) -> Result<(), RegistryError> {
        let mut blob_index = self.registry.storage.read_blob_index(blob).await?;

        for (namespace, references) in blob_index.namespace.clone() {
            for link_reference in references {
                if self
                    .registry
                    .storage
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
                if let Err(err) = self.registry.storage.delete_blob(blob).await {
                    error!("Failed to delete blob: {}", err);
                }
            }
        }
        Ok(())
    }
}
