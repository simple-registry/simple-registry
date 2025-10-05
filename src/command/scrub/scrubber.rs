use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::link_kind::LinkKind;
use crate::registry::metadata_store::{LinkMetadata, MetadataStore};
use crate::registry::oci::Digest;
use crate::registry::repository::retention_policy::ManifestImage;
use crate::registry::repository::{Repository, RetentionPolicy};
use crate::registry::{parse_manifest_digests, Error};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

pub struct Scrubber {
    blob_store: Arc<dyn BlobStore + Send + Sync>,
    metadata_store: Arc<dyn MetadataStore + Send + Sync>,
    global_retention_policy: Option<Arc<RetentionPolicy>>,
    repositories: Arc<HashMap<String, Repository>>,
    dry_run: bool,
    upload_timeout: Duration,
}

impl Scrubber {
    pub fn new(
        blob_store: Arc<dyn BlobStore + Send + Sync>,
        metadata_store: Arc<dyn MetadataStore + Send + Sync>,
        repositories: Arc<HashMap<String, Repository>>,
        global_retention_policy: Option<Arc<RetentionPolicy>>,
        dry_run: bool,
        upload_timeout: Duration,
    ) -> Self {
        Self {
            blob_store,
            metadata_store,
            global_retention_policy,
            repositories,
            dry_run,
            upload_timeout,
        }
    }

    pub async fn enforce_retention(&self, namespace: &str) -> Result<(), Error> {
        info!("'{namespace}': Enforcing retention policy");

        let mut marker = None;
        let mut tag_names = Vec::new();
        loop {
            let (tags, next_marker) = self
                .metadata_store
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
                .metadata_store
                .read_link(namespace, &LinkKind::Tag(tag.to_string()), false)
                .await?;
            tags.insert(tag.to_string(), info);
        }

        self.check_tag_retention(namespace, tags).await?;

        Ok(())
    }

    async fn check_tag_retention(
        &self,
        namespace: &str,
        mut tags: HashMap<String, LinkMetadata>,
    ) -> Result<(), Error> {
        let tags: Vec<(String, LinkMetadata)> = tags.drain().collect();

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
            debug!("'{namespace}': Checking tag '{tag}' for retention");

            let manifest = ManifestImage {
                tag: Some(tag.to_string()),
                pushed_at: info.created_at.map(|t| t.timestamp()).unwrap_or_default(),
                last_pulled_at: info.accessed_at.map(|t| t.timestamp()).unwrap_or_default(),
            };

            let mut should_retain = false;

            if let Some(global_policy) = self.global_retention_policy.as_ref() {
                debug!("Evaluating global retention policy for {namespace}:{tag}");
                if global_policy.should_retain(&manifest, &last_pushed, &last_pulled)? {
                    debug!("Global retention policy says to retain {namespace}:{tag}");
                    should_retain = true;
                }
            }

            let mut has_repo_policy = false;
            if let Some(found_repository) = self
                .repositories
                .iter()
                .find(|(repository, _)| {
                    namespace == repository.as_str()
                        || namespace.starts_with(&format!("{repository}/"))
                })
                .map(|(_, repository)| repository)
            {
                if found_repository.retention_policy.has_rules() {
                    has_repo_policy = true;
                    debug!("Evaluating repository retention policy for {namespace}:{tag}");
                    if found_repository.retention_policy.should_retain(
                        &manifest,
                        &last_pushed,
                        &last_pulled,
                    )? {
                        debug!("Repository retention policy says to retain {namespace}:{tag}");
                        should_retain = true;
                    }
                }
            }

            if self.global_retention_policy.as_ref().is_none() && !has_repo_policy {
                debug!("No retention policies defined, keeping {namespace}:{tag} by default");
                should_retain = true;
            }

            if !should_retain {
                info!("Available for cleanup: {namespace}:{tag}");
                if !self.dry_run {
                    let link = LinkKind::Tag(tag.to_string());
                    let _ = self.metadata_store.delete_link(namespace, &link).await;

                    last_pushed.retain(|t| t != tag);
                    last_pulled.retain(|t| t != tag);
                }
            }
        }

        Ok(())
    }

    pub async fn scrub_uploads(&self, namespace: &str) -> Result<(), Error> {
        info!("'{namespace}': Checking for obsolete uploads");

        let mut marker = None;
        loop {
            let (uploads, next_marker) =
                self.blob_store.list_uploads(namespace, 100, marker).await?;

            for uuid in uploads {
                if let Err(error) = self.check_upload(namespace, &uuid).await {
                    error!("Failed to check upload '{uuid}': {error}");
                }
            }

            if next_marker.is_none() {
                break;
            }
            marker = next_marker;
        }

        Ok(())
    }

    async fn check_upload(&self, namespace: &str, uuid: &str) -> Result<(), Error> {
        let (_, _, start_date) = self.blob_store.read_upload_summary(namespace, uuid).await?;

        let now = Utc::now();
        let duration = now.signed_duration_since(start_date);

        if duration <= self.upload_timeout {
            return Ok(());
        }

        warn!("'{namespace}': upload '{uuid}' is obsolete");
        if !self.dry_run {
            if let Err(error) = self.blob_store.delete_upload(namespace, uuid).await {
                error!("Failed to delete upload '{uuid}': {error}");
            }
        }

        Ok(())
    }

    pub async fn scrub_tags(&self, namespace: &str) -> Result<(), Error> {
        info!("'{namespace}': Checking tags/revision inconsistencies");

        let mut marker = None;
        loop {
            let (tags, next_marker) = self
                .metadata_store
                .list_tags(namespace, 100, marker)
                .await?;

            for tag in tags {
                if let Err(error) = self.check_tag(namespace, &tag).await {
                    error!("Failed to check tag '{tag}': {error}");
                }
            }

            if next_marker.is_none() {
                break;
            }
            marker = next_marker;
        }

        Ok(())
    }

    async fn check_tag(&self, namespace: &str, tag: &str) -> Result<(), Error> {
        debug!("Checking {namespace}:{tag} for revision inconsistencies");
        let digest = self
            .metadata_store
            .read_link(namespace, &LinkKind::Tag(tag.to_string()), false)
            .await?;

        let link_reference = LinkKind::Digest(digest.target.clone());
        if let Err(error) = self
            .ensure_link(namespace, &link_reference, &digest.target)
            .await
        {
            warn!("Failed to ensure link: {error}");
        }

        Ok(())
    }

    pub async fn scrub_revisions(&self, namespace: &str) -> Result<(), Error> {
        info!("'{namespace}': Checking for revision inconsistencies");

        let mut marker = None;

        loop {
            let (revisions, next_marker) = self
                .metadata_store
                .list_revisions(namespace, 100, marker)
                .await?;

            for revision in revisions {
                let content = self.blob_store.read_blob(&revision).await?;
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
    ) -> Result<(), Error> {
        let Some(config_digest) = config else {
            return Ok(());
        };

        debug!("Checking {namespace}/{revision} config link: {config_digest}");
        let link_reference = LinkKind::Config(config_digest.clone());
        self.ensure_link(namespace, &link_reference, &config_digest)
            .await?;

        Ok(())
    }

    async fn check_subject(
        &self,
        namespace: &str,
        revision: &Digest,
        subject_digest: Option<Digest>,
    ) -> Result<(), Error> {
        let Some(subject_digest) = subject_digest else {
            return Ok(());
        };

        debug!("Checking {namespace}/{revision} subject link: {subject_digest}");
        let link_reference = LinkKind::Referrer(subject_digest.clone(), revision.clone());
        self.ensure_link(namespace, &link_reference, revision)
            .await?;

        Ok(())
    }

    async fn check_layers(
        &self,
        namespace: &str,
        revision: &Digest,
        layers: &Vec<Digest>,
    ) -> Result<(), Error> {
        for layer_digest in layers {
            debug!("Checking {namespace}/{revision} layer link: {layer_digest}",);

            let link_reference = LinkKind::Layer(layer_digest.clone());
            self.ensure_link(namespace, &link_reference, layer_digest)
                .await?;
        }

        Ok(())
    }

    async fn ensure_link(
        &self,
        namespace: &str,
        link_reference: &LinkKind,
        digest: &Digest,
    ) -> Result<(), Error> {
        let blob_digest = self
            .metadata_store
            .read_link(namespace, link_reference, false)
            .await;

        match blob_digest {
            Ok(link) if &link.target == digest => {
                debug!("Link {link_reference} -> {digest} is valid");
                return Ok(());
            }
            _ => {
                warn!("Missing or invalid link: {link_reference} -> {digest}");
                if !self.dry_run {
                    if let Err(error) = self
                        .metadata_store
                        .delete_link(namespace, link_reference)
                        .await
                    {
                        warn!("Failed to delete old link: {error}");
                    }
                    self.metadata_store
                        .create_link(namespace, link_reference, digest)
                        .await?;
                }
            }
        }

        Ok(())
    }

    pub async fn cleanup_orphan_blobs(&self) -> Result<(), Error> {
        info!("Checking for orphan blobs");

        let mut marker = None;
        loop {
            let Ok((blobs, next_marker)) = self.blob_store.list_blobs(100, marker).await else {
                error!("Failed to list blobs");
                return Err(Error::Internal(
                    "Failed to list blobs while checking for orphan blobs".to_string(),
                ));
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

    async fn check_blob(&self, blob: &Digest) -> Result<(), Error> {
        let blob_index = self.metadata_store.read_blob_index(blob).await?;

        for (namespace, references) in blob_index.namespace {
            for link_reference in references {
                if self
                    .metadata_store
                    .read_link(&namespace, &link_reference, false)
                    .await
                    .is_err()
                {
                    warn!("Missing link from blob index: {namespace}/{blob} <- {link_reference}");
                    if !self.dry_run {
                        if let Err(error) = self
                            .metadata_store
                            .update_blob_index(
                                &namespace,
                                blob,
                                crate::registry::metadata_store::BlobIndexOperation::Remove(
                                    link_reference.clone(),
                                ),
                            )
                            .await
                        {
                            error!("Failed to update blob index: {error}");
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
