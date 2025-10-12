use crate::oci::Digest;
use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::link_kind::LinkKind;
use crate::registry::metadata_store::{LinkMetadata, MetadataStore};
use crate::registry::repository::Repository;
use crate::registry::{parse_manifest_digests, Error, ManifestImage, RetentionPolicy};
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
        info!("Enforcing retention policy on '{namespace}'");

        let tags = self.collect_all_tags(namespace).await?;
        self.check_tag_retention(namespace, tags).await?;

        Ok(())
    }

    async fn collect_all_tags(
        &self,
        namespace: &str,
    ) -> Result<HashMap<String, LinkMetadata>, Error> {
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

        Ok(tags)
    }

    async fn check_tag_retention(
        &self,
        namespace: &str,
        mut tags: HashMap<String, LinkMetadata>,
    ) -> Result<(), Error> {
        let tags: Vec<(String, LinkMetadata)> = tags.drain().collect();

        let (mut last_pushed, mut last_pulled) = Self::sort_tags_by_time(&tags);

        for (tag, info) in &tags {
            debug!("'{namespace}': Checking tag '{tag}' for retention");

            let manifest = ManifestImage {
                tag: Some(tag.to_string()),
                pushed_at: info.created_at.map(|t| t.timestamp()).unwrap_or_default(),
                last_pulled_at: info.accessed_at.map(|t| t.timestamp()).unwrap_or_default(),
            };

            let should_retain = self.evaluate_retention_policies(
                namespace,
                tag,
                &manifest,
                &last_pushed,
                &last_pulled,
            )?;

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

    fn sort_tags_by_time(tags: &[(String, LinkMetadata)]) -> (Vec<String>, Vec<String>) {
        let mut last_pushed = tags.to_vec();
        last_pushed.sort_by(|a, b| b.1.created_at.cmp(&a.1.created_at));
        let last_pushed = last_pushed
            .iter()
            .map(|(tag, _)| tag.clone())
            .collect::<Vec<String>>();

        let mut last_pulled = tags.to_vec();
        last_pulled.sort_by(|a, b| b.1.accessed_at.cmp(&a.1.accessed_at));
        let last_pulled = last_pulled
            .iter()
            .map(|(tag, _)| tag.clone())
            .collect::<Vec<String>>();

        (last_pushed, last_pulled)
    }

    fn evaluate_retention_policies(
        &self,
        namespace: &str,
        tag: &str,
        manifest: &ManifestImage,
        last_pushed: &[String],
        last_pulled: &[String],
    ) -> Result<bool, Error> {
        let mut should_retain = false;

        if let Some(global_policy) = self.global_retention_policy.as_ref() {
            debug!("Evaluating global retention policy for {namespace}:{tag}");
            if global_policy.should_retain(manifest, last_pushed, last_pulled)? {
                debug!("Global retention policy says to retain {namespace}:{tag}");
                should_retain = true;
            }
        }

        let mut has_repo_policy = false;
        if let Some(found_repository) = self
            .repositories
            .iter()
            .find(|(repository, _)| {
                namespace == repository.as_str() || namespace.starts_with(&format!("{repository}/"))
            })
            .map(|(_, repository)| repository)
        {
            if found_repository.retention_policy.has_rules() {
                has_repo_policy = true;
                debug!("Evaluating repository retention policy for {namespace}:{tag}");
                if found_repository.retention_policy.should_retain(
                    manifest,
                    last_pushed,
                    last_pulled,
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

        Ok(should_retain)
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

        if !self.is_upload_obsolete(start_date) {
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

    fn is_upload_obsolete(&self, start_date: chrono::DateTime<chrono::Utc>) -> bool {
        let now = Utc::now();
        let duration = now.signed_duration_since(start_date);
        duration > self.upload_timeout
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
        layers: &[Digest],
    ) -> Result<(), Error> {
        for layer_digest in layers {
            debug!("Checking {namespace}/{revision} layer link: {layer_digest}");

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
                Ok(())
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
                Ok(())
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache;
    use crate::registry::metadata_store::link_kind::LinkKind;
    use crate::registry::{blob_store, data_store, metadata_store, Registry};
    use crate::registry::{repository, test_utils};
    use chrono::Utc;
    use std::str::FromStr;
    use tempfile::TempDir;

    struct TestCase {
        blob_store: Arc<blob_store::fs::Backend>,
        metadata_store: Arc<metadata_store::fs::Backend>,
        registry: Registry,
        _temp_dir: TempDir,
    }

    impl TestCase {
        fn new() -> Self {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let path = temp_dir.path().to_string_lossy().to_string();

            let blob_store = blob_store::fs::Backend::new(&data_store::fs::BackendConfig {
                root_dir: path.clone(),
                sync_to_disk: false,
            });
            let blob_store = Arc::new(blob_store);

            let metadata_store =
                metadata_store::fs::Backend::new(&metadata_store::fs::BackendConfig {
                    root_dir: path,
                    sync_to_disk: false,
                    redis: None,
                })
                .unwrap();
            let metadata_store = Arc::new(metadata_store);

            let registry =
                test_utils::create_test_registry(blob_store.clone(), metadata_store.clone());

            Self {
                blob_store,
                metadata_store,
                registry,
                _temp_dir: temp_dir,
            }
        }

        fn blob_store(&self) -> &Arc<blob_store::fs::Backend> {
            &self.blob_store
        }

        fn metadata_store(&self) -> &Arc<metadata_store::fs::Backend> {
            &self.metadata_store
        }

        fn registry(&self) -> &Registry {
            &self.registry
        }
    }

    fn create_scrubber(
        blob_store: Arc<dyn BlobStore + Send + Sync>,
        metadata_store: Arc<dyn MetadataStore + Send + Sync>,
        dry_run: bool,
        upload_timeout: Duration,
    ) -> Scrubber {
        let repositories = test_utils::create_test_repositories();
        Scrubber::new(
            blob_store,
            metadata_store,
            repositories,
            None,
            dry_run,
            upload_timeout,
        )
    }

    #[tokio::test]
    async fn test_scrub_uploads_removes_obsolete() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";

        let upload_uuid = uuid::Uuid::new_v4().to_string();
        test_case
            .blob_store()
            .create_upload(namespace, &upload_uuid)
            .await
            .unwrap();

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::zero(),
        );

        scrubber.scrub_uploads(namespace).await.unwrap();

        let result = test_case
            .blob_store()
            .read_upload_summary(namespace, &upload_uuid)
            .await;
        assert!(result.is_err(), "Obsolete upload should be deleted");
    }

    #[tokio::test]
    async fn test_scrub_uploads_keeps_recent() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";

        let upload_uuid = uuid::Uuid::new_v4().to_string();
        test_case
            .blob_store()
            .create_upload(namespace, &upload_uuid)
            .await
            .unwrap();

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        scrubber.scrub_uploads(namespace).await.unwrap();

        let result = test_case
            .blob_store()
            .read_upload_summary(namespace, &upload_uuid)
            .await;
        assert!(result.is_ok(), "Recent upload should be kept");
    }

    #[tokio::test]
    async fn test_scrub_uploads_dry_run() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";

        let upload_uuid = uuid::Uuid::new_v4().to_string();
        test_case
            .blob_store()
            .create_upload(namespace, &upload_uuid)
            .await
            .unwrap();

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            true,
            Duration::zero(),
        );

        scrubber.scrub_uploads(namespace).await.unwrap();

        let result = test_case
            .blob_store()
            .read_upload_summary(namespace, &upload_uuid)
            .await;
        assert!(result.is_ok(), "Dry run should not delete obsolete upload");
    }

    #[tokio::test]
    async fn test_is_upload_obsolete() {
        let test_case = TestCase::new();
        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::hours(1),
        );

        let recent_time = Utc::now();
        assert!(!scrubber.is_upload_obsolete(recent_time));

        let old_time = Utc::now() - Duration::hours(2);
        assert!(scrubber.is_upload_obsolete(old_time));

        let exact_time = Utc::now() - Duration::hours(1);
        assert!(!scrubber.is_upload_obsolete(exact_time));
    }

    #[tokio::test]
    async fn test_check_tag_creates_missing_digest_link() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";
        let tag_name = "v1.0.0";

        let (blob_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"test manifest content")
                .await;

        test_case
            .metadata_store()
            .create_link(
                namespace,
                &LinkKind::Tag(tag_name.to_string()),
                &blob_digest,
            )
            .await
            .unwrap();

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        scrubber.check_tag(namespace, tag_name).await.unwrap();

        let digest_link = test_case
            .metadata_store()
            .read_link(namespace, &LinkKind::Digest(blob_digest.clone()), false)
            .await;

        assert!(
            digest_link.is_ok(),
            "Digest link should be created if missing"
        );
        assert_eq!(digest_link.unwrap().target, blob_digest);
    }

    #[tokio::test]
    async fn test_cleanup_orphan_blobs_removes_invalid_index_entries() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";

        let (blob_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"test content").await;

        let orphan_layer_link = LinkKind::Layer(
            Digest::from_str(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
        );
        test_case
            .metadata_store()
            .update_blob_index(
                namespace,
                &blob_digest,
                crate::registry::metadata_store::BlobIndexOperation::Insert(
                    orphan_layer_link.clone(),
                ),
            )
            .await
            .unwrap();

        let blob_index_before = test_case
            .metadata_store()
            .read_blob_index(&blob_digest)
            .await
            .unwrap();

        let initial_refs = blob_index_before
            .namespace
            .get(namespace)
            .map_or(0, std::collections::HashSet::len);

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        scrubber.cleanup_orphan_blobs().await.unwrap();

        let blob_index_after = test_case
            .metadata_store()
            .read_blob_index(&blob_digest)
            .await
            .unwrap();

        let final_refs = blob_index_after
            .namespace
            .get(namespace)
            .map_or(0, std::collections::HashSet::len);

        assert!(
            final_refs < initial_refs,
            "Invalid blob index entry should be removed. Before: {initial_refs}, After: {final_refs}"
        );
    }

    #[tokio::test]
    async fn test_ensure_link_validates_correct_link() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";

        let (blob_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"test content").await;

        let link_kind = LinkKind::Layer(blob_digest.clone());
        test_case
            .metadata_store()
            .create_link(namespace, &link_kind, &blob_digest)
            .await
            .unwrap();

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        let result = scrubber
            .ensure_link(namespace, &link_kind, &blob_digest)
            .await;

        assert!(result.is_ok(), "Valid link should pass validation");

        let link = test_case
            .metadata_store()
            .read_link(namespace, &link_kind, false)
            .await
            .unwrap();
        assert_eq!(link.target, blob_digest, "Link should remain unchanged");
    }

    #[tokio::test]
    async fn test_ensure_link_recreates_invalid_link() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";

        let (blob_digest1, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"content 1").await;
        let (blob_digest2, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"content 2").await;

        let link_kind = LinkKind::Layer(blob_digest1.clone());
        test_case
            .metadata_store()
            .create_link(namespace, &link_kind, &blob_digest2)
            .await
            .unwrap();

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        scrubber
            .ensure_link(namespace, &link_kind, &blob_digest1)
            .await
            .unwrap();

        let link = test_case
            .metadata_store()
            .read_link(namespace, &link_kind, false)
            .await
            .unwrap();
        assert_eq!(
            link.target, blob_digest1,
            "Invalid link should be corrected"
        );
    }

    #[tokio::test]
    async fn test_sort_tags_by_time() {
        let test_case = TestCase::new();
        let _scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        let now = Utc::now();
        let tags = vec![
            (
                "tag1".to_string(),
                LinkMetadata {
                    target: Digest::from_str(
                        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    )
                    .unwrap(),
                    created_at: Some(now - Duration::days(3)),
                    accessed_at: Some(now - Duration::days(1)),
                },
            ),
            (
                "tag2".to_string(),
                LinkMetadata {
                    target: Digest::from_str(
                        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    )
                    .unwrap(),
                    created_at: Some(now - Duration::days(1)),
                    accessed_at: Some(now - Duration::days(3)),
                },
            ),
            (
                "tag3".to_string(),
                LinkMetadata {
                    target: Digest::from_str(
                        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                    )
                    .unwrap(),
                    created_at: Some(now - Duration::days(2)),
                    accessed_at: Some(now - Duration::days(2)),
                },
            ),
        ];

        let (last_pushed, last_pulled) = Scrubber::sort_tags_by_time(&tags);

        assert_eq!(last_pushed, vec!["tag2", "tag3", "tag1"]);
        assert_eq!(last_pulled, vec!["tag1", "tag3", "tag2"]);
    }

    #[tokio::test]
    async fn test_scrub_tags_creates_digest_links() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";

        let (blob_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"test manifest").await;

        test_case
            .metadata_store()
            .create_link(
                namespace,
                &LinkKind::Tag("v1.0.0".to_string()),
                &blob_digest,
            )
            .await
            .unwrap();

        test_case
            .metadata_store()
            .delete_link(namespace, &LinkKind::Digest(blob_digest.clone()))
            .await
            .ok();

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        scrubber.scrub_tags(namespace).await.unwrap();

        let digest_link = test_case
            .metadata_store()
            .read_link(namespace, &LinkKind::Digest(blob_digest.clone()), false)
            .await;

        assert!(
            digest_link.is_ok(),
            "scrub_tags should create missing digest links"
        );
    }

    #[tokio::test]
    async fn test_check_config_creates_link() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";
        let revision = Digest::from_str(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();

        let (config_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"config content").await;

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        scrubber
            .check_config(namespace, &revision, Some(config_digest.clone()))
            .await
            .unwrap();

        let config_link = test_case
            .metadata_store()
            .read_link(namespace, &LinkKind::Config(config_digest.clone()), false)
            .await;

        assert!(
            config_link.is_ok(),
            "check_config should ensure config link exists"
        );
        assert_eq!(config_link.unwrap().target, config_digest);
    }

    #[tokio::test]
    async fn test_check_config_with_none() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";
        let revision = Digest::from_str(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        let result = scrubber.check_config(namespace, &revision, None).await;

        assert!(
            result.is_ok(),
            "check_config should succeed with None config"
        );
    }

    #[tokio::test]
    async fn test_check_subject_creates_referrer_link() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";

        let (subject_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"subject manifest")
                .await;

        let (revision_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"referrer manifest")
                .await;

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        scrubber
            .check_subject(namespace, &revision_digest, Some(subject_digest.clone()))
            .await
            .unwrap();

        let referrer_link = test_case
            .metadata_store()
            .read_link(
                namespace,
                &LinkKind::Referrer(subject_digest.clone(), revision_digest.clone()),
                false,
            )
            .await;

        assert!(
            referrer_link.is_ok(),
            "check_subject should ensure referrer link exists"
        );
        assert_eq!(referrer_link.unwrap().target, revision_digest);
    }

    #[tokio::test]
    async fn test_check_subject_with_none() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";
        let revision = Digest::from_str(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        let result = scrubber.check_subject(namespace, &revision, None).await;

        assert!(
            result.is_ok(),
            "check_subject should succeed with None subject"
        );
    }

    #[tokio::test]
    async fn test_check_layers_creates_links() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";
        let revision = Digest::from_str(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();

        let (layer1_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"layer 1 content").await;

        let (layer2_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"layer 2 content").await;

        let layers = vec![layer1_digest.clone(), layer2_digest.clone()];

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        scrubber
            .check_layers(namespace, &revision, &layers)
            .await
            .unwrap();

        let layer1_link = test_case
            .metadata_store()
            .read_link(namespace, &LinkKind::Layer(layer1_digest.clone()), false)
            .await;

        let layer2_link = test_case
            .metadata_store()
            .read_link(namespace, &LinkKind::Layer(layer2_digest.clone()), false)
            .await;

        assert!(
            layer1_link.is_ok(),
            "check_layers should ensure layer 1 link exists"
        );
        assert!(
            layer2_link.is_ok(),
            "check_layers should ensure layer 2 link exists"
        );
        assert_eq!(layer1_link.unwrap().target, layer1_digest);
        assert_eq!(layer2_link.unwrap().target, layer2_digest);
    }

    #[tokio::test]
    async fn test_check_layers_with_empty() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";
        let revision = Digest::from_str(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        let result = scrubber.check_layers(namespace, &revision, &[]).await;

        assert!(
            result.is_ok(),
            "check_layers should succeed with empty layers"
        );
    }

    #[tokio::test]
    async fn test_scrub_revisions_validates_manifest_links() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";

        let (config_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"config content").await;

        let (layer_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"layer content").await;

        let manifest_content = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {{
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "{config_digest}",
                    "size": 123
                }},
                "layers": [
                    {{
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": "{layer_digest}",
                        "size": 456
                    }}
                ]
            }}"#
        );

        let manifest_digest = test_case
            .blob_store()
            .create_blob(manifest_content.as_bytes())
            .await
            .unwrap();

        test_case
            .metadata_store()
            .create_link(
                namespace,
                &LinkKind::Digest(manifest_digest.clone()),
                &manifest_digest,
            )
            .await
            .unwrap();

        let scrubber = create_scrubber(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            false,
            Duration::days(1),
        );

        scrubber.scrub_revisions(namespace).await.unwrap();

        let config_link = test_case
            .metadata_store()
            .read_link(namespace, &LinkKind::Config(config_digest.clone()), false)
            .await;

        let layer_link = test_case
            .metadata_store()
            .read_link(namespace, &LinkKind::Layer(layer_digest.clone()), false)
            .await;

        assert!(
            config_link.is_ok(),
            "scrub_revisions should ensure config link exists"
        );
        assert!(
            layer_link.is_ok(),
            "scrub_revisions should ensure layer link exists"
        );
    }

    #[tokio::test]
    async fn test_enforce_retention_with_policy() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";

        let (blob_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"test manifest").await;

        test_case
            .metadata_store()
            .create_link(
                namespace,
                &LinkKind::Tag("v1.0.0".to_string()),
                &blob_digest,
            )
            .await
            .unwrap();

        let retention_config = crate::registry::RetentionPolicyConfig {
            rules: vec!["top(image.tag, last_pushed, 10)".to_string()],
        };

        let retention_policy =
            Arc::new(crate::registry::RetentionPolicy::new(&retention_config).unwrap());

        let scrubber = Scrubber::new(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            test_utils::create_test_repositories(),
            Some(retention_policy),
            false,
            Duration::days(1),
        );

        scrubber.enforce_retention(namespace).await.unwrap();

        let tag_link = test_case
            .metadata_store()
            .read_link(namespace, &LinkKind::Tag("v1.0.0".to_string()), false)
            .await;

        assert!(
            tag_link.is_ok(),
            "enforce_retention should keep tags matching the top 10 policy"
        );
    }

    #[tokio::test]
    async fn test_enforce_retention_no_policy() {
        let test_case = TestCase::new();
        let namespace = "test-repo/app";

        let (blob_digest, _) =
            test_utils::create_test_blob(test_case.registry(), namespace, b"test manifest").await;

        test_case
            .metadata_store()
            .create_link(
                namespace,
                &LinkKind::Tag("any-tag".to_string()),
                &blob_digest,
            )
            .await
            .unwrap();

        let scrubber = Scrubber::new(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            test_utils::create_test_repositories(),
            None,
            false,
            Duration::days(1),
        );

        scrubber.enforce_retention(namespace).await.unwrap();

        let tag_link = test_case
            .metadata_store()
            .read_link(namespace, &LinkKind::Tag("any-tag".to_string()), false)
            .await;

        assert!(
            tag_link.is_ok(),
            "enforce_retention without policy should keep all tags"
        );
    }

    #[tokio::test]
    async fn test_evaluate_retention_policies_with_global_policy() {
        let test_case = TestCase::new();

        let retention_config = crate::registry::RetentionPolicyConfig {
            rules: vec!["image.pushed_at > now() - days(30)".to_string()],
        };

        let retention_policy =
            Arc::new(crate::registry::RetentionPolicy::new(&retention_config).unwrap());

        let scrubber = Scrubber::new(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            test_utils::create_test_repositories(),
            Some(retention_policy),
            false,
            Duration::days(1),
        );

        let now = Utc::now();
        let recent_manifest = ManifestImage {
            tag: Some("v1.0.0".to_string()),
            pushed_at: now.timestamp(),
            last_pulled_at: now.timestamp(),
        };

        let old_manifest = ManifestImage {
            tag: Some("v0.1.0".to_string()),
            pushed_at: (now - Duration::days(60)).timestamp(),
            last_pulled_at: (now - Duration::days(60)).timestamp(),
        };

        let last_pushed = vec!["v1.0.0".to_string(), "v0.1.0".to_string()];
        let last_pulled = vec!["v1.0.0".to_string(), "v0.1.0".to_string()];

        let should_retain_recent = scrubber
            .evaluate_retention_policies(
                "test-repo",
                "v1.0.0",
                &recent_manifest,
                &last_pushed,
                &last_pulled,
            )
            .unwrap();

        let should_retain_old = scrubber
            .evaluate_retention_policies(
                "test-repo",
                "v0.1.0",
                &old_manifest,
                &last_pushed,
                &last_pulled,
            )
            .unwrap();

        assert!(
            should_retain_recent,
            "Recent manifest should be retained by global policy"
        );
        assert!(
            !should_retain_old,
            "Old manifest should not be retained by global policy"
        );
    }

    #[tokio::test]
    async fn test_evaluate_retention_policies_with_repository_policy() {
        let test_case = TestCase::new();

        let retention_config = crate::registry::RetentionPolicyConfig {
            rules: vec!["top(image.tag, last_pushed, 5)".to_string()],
        };

        let repo_config = repository::Config {
            retention_policy: retention_config,
            ..Default::default()
        };

        let token_cache = cache::Config::default().to_backend().unwrap();
        let repository = Repository::new("test-repo", &repo_config, &token_cache).unwrap();

        let mut repositories = std::collections::HashMap::new();
        repositories.insert("test-repo".to_string(), repository);

        let scrubber = Scrubber::new(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            Arc::new(repositories),
            None,
            false,
            Duration::days(1),
        );

        let now = Utc::now();
        let manifest = ManifestImage {
            tag: Some("v1.0.0".to_string()),
            pushed_at: now.timestamp(),
            last_pulled_at: now.timestamp(),
        };

        let last_pushed = vec![
            "v1.0.0".to_string(),
            "v0.9.0".to_string(),
            "v0.8.0".to_string(),
        ];
        let last_pulled = vec![
            "v1.0.0".to_string(),
            "v0.9.0".to_string(),
            "v0.8.0".to_string(),
        ];

        let should_retain = scrubber
            .evaluate_retention_policies(
                "test-repo",
                "v1.0.0",
                &manifest,
                &last_pushed,
                &last_pulled,
            )
            .unwrap();

        assert!(
            should_retain,
            "Manifest in top 5 should be retained by repository policy"
        );
    }

    #[tokio::test]
    async fn test_evaluate_retention_policies_no_policies() {
        let test_case = TestCase::new();

        let scrubber = Scrubber::new(
            test_case.blob_store().clone(),
            test_case.metadata_store().clone(),
            test_utils::create_test_repositories(),
            None,
            false,
            Duration::days(1),
        );

        let now = Utc::now();
        let manifest = ManifestImage {
            tag: Some("v1.0.0".to_string()),
            pushed_at: now.timestamp(),
            last_pulled_at: now.timestamp(),
        };

        let last_pushed = vec!["v1.0.0".to_string()];
        let last_pulled = vec!["v1.0.0".to_string()];

        let should_retain = scrubber
            .evaluate_retention_policies(
                "test-repo",
                "v1.0.0",
                &manifest,
                &last_pushed,
                &last_pulled,
            )
            .unwrap();

        assert!(
            should_retain,
            "Without policies, all manifests should be retained by default"
        );
    }
}
