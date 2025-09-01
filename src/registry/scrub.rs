use crate::registry::blob_store::{BlobStore, LinkMetadata};
use crate::registry::oci_types::{Digest, Reference};
use crate::registry::policy_types::ManifestImage;
use crate::registry::utils::BlobLink;
use crate::registry::{parse_manifest_digests, Error, Registry};
use cel_interpreter::{Context, Program, Value};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Checks if a rule validates and if therefore the specified manifest should be purged
///
/// # Arguments
/// - `rules` - The retention rules to evaluate
/// - `manifest` - The manifest to evaluate
/// - `last_pushed` - The list of last pushed tags ordered by push date desc
/// - `last_pulled` - The list of last pulled tags ordered by pull date desc
///
/// # Returns
/// - `Ok(true)` if the manifest should be purged
/// - `Ok(false)` if the manifest should be retained
/// - `Err` if an error occurred during evaluation
pub fn manifest_should_be_purged(
    rules: &[Program],
    manifest: &ManifestImage,
    last_pushed: &Vec<String>,
    last_pulled: &Vec<String>,
) -> Result<bool, Error> {
    let mut context = Context::default();
    debug!("Policy context (image) : {manifest:?}");

    context.add_variable("image", manifest)?;
    context.add_variable("last_pushed", last_pushed)?;
    context.add_variable("last_pulled", last_pulled)?;

    context.add_function("now", || Utc::now().timestamp());
    context.add_function("days", |d: i64| d * 86400);
    context.add_function(
        "top",
        |s: Arc<String>, collection: Arc<Vec<Value>>, k: i64| {
            let mut i = 0;
            for e in collection.iter() {
                let Value::String(e) = e else { continue };

                if e.as_str() == s.as_str() {
                    return true;
                }
                i += 1;
                if i >= k {
                    break;
                }
            }

            false
        },
    );

    for policy in rules {
        let evaluation_result = policy.execute(&context)?;

        debug!("CEL program '{policy:?}' evaluates to {evaluation_result:?}");
        match evaluation_result {
            Value::Bool(true) => {
                debug!("Retention policy matched");
                return Ok(false);
            }
            Value::Bool(false) => { // Not validated, continue checking
            }
            _ => {
                debug!("Not eligible for cleanup");
                return Ok(false);
            }
        }
    }

    Ok(!rules.is_empty())
}

impl<D: BlobStore> Registry<D> {
    pub async fn enforce_retention(&self, namespace: &str) -> Result<(), Error> {
        info!("'{namespace}': Enforcing retention policy");

        let mut marker = None;
        let mut tag_names = Vec::new();
        loop {
            let (tags, next_marker) = self.store.list_tags(namespace, 1000, marker).await?;
            tag_names.extend(tags);
            if next_marker.is_none() {
                break;
            }
            marker = next_marker;
        }

        let mut tags = HashMap::new();
        for tag in &tag_names {
            let info = self
                .read_link(namespace, &BlobLink::Tag(tag.to_string()))
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

            let Some((_, found_repository)) = self
                .repositories
                .iter()
                .find(|(repository, _)| namespace.starts_with(*repository))
            else {
                warn!("Unable to find repository for namespace: {namespace}");
                return Ok(());
            };

            let manifest = ManifestImage {
                tag: Some(tag.to_string()),
                pushed_at: info.created_at.map(|t| t.timestamp()).unwrap_or_default(),
                last_pulled_at: info.accessed_at.map(|t| t.timestamp()).unwrap_or_default(),
            };

            if manifest_should_be_purged(
                &found_repository.retention_rules,
                &manifest,
                &last_pushed,
                &last_pulled,
            )? {
                info!("Available for cleanup: {namespace}:{tag}");
                if !self.scrub_dry_run {
                    let reference = Reference::Tag(tag.to_string());
                    let _ = self.delete_manifest(namespace, reference).await;

                    last_pushed.retain(|t| t != tag);
                    last_pulled.retain(|t| t != tag);
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn scrub_uploads(&self, namespace: &str) -> Result<(), Error> {
        info!("'{namespace}': Checking for obsolete uploads");

        let mut marker = None;
        loop {
            let (uploads, next_marker) = self.store.list_uploads(namespace, 100, marker).await?;

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
        let (_, _, start_date) = self.store.read_upload_summary(namespace, uuid).await?;

        let now = Utc::now();
        let duration = now.signed_duration_since(start_date);

        if duration <= self.upload_timeout {
            return Ok(());
        }

        warn!("'{namespace}': upload '{uuid}' is obsolete");
        if !self.scrub_dry_run {
            if let Err(error) = self.store.delete_upload(namespace, uuid).await {
                error!("Failed to delete upload '{uuid}': {error}");
            }
        }

        Ok(())
    }

    pub(crate) async fn scrub_tags(&self, namespace: &str) -> Result<(), Error> {
        info!("'{namespace}': Checking tags/revision inconsistencies");

        let mut marker = None;
        loop {
            let (tags, next_marker) = self.store.list_tags(namespace, 100, marker).await?;

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
            .read_link(namespace, &BlobLink::Tag(tag.to_string()))
            .await?;

        let link_reference = BlobLink::Digest(digest.target.clone());
        if let Err(error) = self
            .ensure_link(namespace, &link_reference, &digest.target)
            .await
        {
            warn!("Failed to ensure link: {error}");
        }

        Ok(())
    }

    pub(crate) async fn scrub_revisions(&self, namespace: &str) -> Result<(), Error> {
        info!("'{namespace}': Checking for revision inconsistencies");

        let mut marker = None;

        loop {
            let (revisions, next_marker) =
                self.store.list_revisions(namespace, 100, marker).await?;

            for revision in revisions {
                let content = self.store.read_blob(&revision).await?;
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
        let link_reference = BlobLink::Config(config_digest.clone());
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
        let link_reference = BlobLink::Referrer(subject_digest.clone(), revision.clone());
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

            let link_reference = BlobLink::Layer(layer_digest.clone());
            self.ensure_link(namespace, &link_reference, layer_digest)
                .await?;
        }

        Ok(())
    }

    async fn ensure_link(
        &self,
        namespace: &str,
        link_reference: &BlobLink,
        digest: &Digest,
    ) -> Result<(), Error> {
        let blob_digest = self.read_link(namespace, link_reference).await;

        match blob_digest {
            Ok(link) if &link.target == digest => {
                debug!("Link {link_reference} -> {digest} is valid");
                return Ok(());
            }
            _ => {
                warn!("Missing or invalid link: {link_reference} -> {digest}");
                if !self.scrub_dry_run {
                    if let Err(error) = self.delete_link(namespace, link_reference).await {
                        warn!("Failed to delete old link: {error}");
                    }
                    self.create_link(namespace, link_reference, digest).await?;
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn cleanup_orphan_blobs(&self) -> Result<(), Error> {
        info!("Checking for orphan blobs");

        let mut marker = None;
        loop {
            let Ok((blobs, next_marker)) = self.store.list_blobs(100, marker).await else {
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
        let blob_index = self.store.read_blob_index(blob).await?;

        for (namespace, references) in blob_index.namespace {
            for link_reference in references {
                if self.read_link(&namespace, &link_reference).await.is_err() {
                    warn!("Missing link from blob index: {namespace}/{blob} <- {link_reference}");
                    if !self.scrub_dry_run {
                        if let Err(error) = self
                            .store
                            .update_blob_index(&namespace, blob, |index| {
                                index.remove(&link_reference);
                            })
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
    use crate::configuration::{CacheStoreConfig, GlobalConfig, LockStoreConfig};
    use crate::registry::test_utils::{
        create_test_fs_backend, create_test_manifest, create_test_repository_config,
        create_test_s3_backend,
    };
    use crate::registry::utils::BlobLink;
    use chrono::Duration;
    use uuid::Uuid;

    #[test]
    fn test_retention_policy_no_rules() {
        let policies = vec![];
        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1_710_441_600,
            last_pulled_at: 1_710_441_600,
        };
        assert!(!manifest_should_be_purged(&policies, &manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_retention_policy_not_purged() {
        let policies = vec![Program::compile("image.tag == 'latest'").unwrap()];
        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1_710_441_600,
            last_pulled_at: 1_710_441_600,
        };
        assert!(!manifest_should_be_purged(&policies, &manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_retention_policy_purged() {
        let policies = vec![Program::compile("image.tag == 'latest'").unwrap()];
        let manifest = ManifestImage {
            tag: Some("x".to_string()),
            pushed_at: 1_710_441_600,
            last_pulled_at: 1_710_441_600,
        };
        assert!(manifest_should_be_purged(&policies, &manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_retention_policy_invalid() {
        let policies = vec![Program::compile("image.tag").unwrap()];
        let manifest = ManifestImage {
            tag: None,
            pushed_at: 1_710_441_600,
            last_pulled_at: 1_710_441_600,
        };
        assert!(!manifest_should_be_purged(&policies, &manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_function_now_days() {
        let policies = vec![Program::compile("now() + days(15) == now() + 86400 * 15").unwrap()];
        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1_710_441_600,
            last_pulled_at: 1_710_441_600,
        };

        assert!(!manifest_should_be_purged(&policies, &manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_function_top_last_pushed() {
        let policies = vec![Program::compile("top(image.tag, last_pushed, 1)").unwrap()];

        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1_710_441_600,
            last_pulled_at: 1_710_441_600,
        };

        assert!(!manifest_should_be_purged(
            &policies,
            &manifest,
            &vec!["latest".to_string()],
            &vec![]
        )
        .unwrap());

        let manifest = ManifestImage {
            tag: Some("x".to_string()),
            pushed_at: 1_710_441_600,
            last_pulled_at: 1_710_441_600,
        };
        assert!(manifest_should_be_purged(
            &policies,
            &manifest,
            &vec!["latest".to_string()],
            &vec![]
        )
        .unwrap());
    }

    #[test]
    fn test_function_top_last_pulled() {
        let policies = vec![Program::compile("top(image.tag, last_pulled, 1)").unwrap()];

        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1_710_441_600,
            last_pulled_at: 1_710_441_600,
        };

        assert!(!manifest_should_be_purged(
            &policies,
            &manifest,
            &vec![],
            &vec!["latest".to_string()]
        )
        .unwrap());

        let manifest = ManifestImage {
            tag: Some("x".to_string()),
            pushed_at: 1_710_441_600,
            last_pulled_at: 1_710_441_600,
        };
        assert!(manifest_should_be_purged(
            &policies,
            &manifest,
            &vec![],
            &vec!["latest".to_string()]
        )
        .unwrap());
    }

    async fn test_enforce_retention_impl<D: BlobStore + 'static>(registry: Registry<D>) {
        let namespace = "test-repo";
        let (content, media_type) = create_test_manifest();

        // Create a repository config with retention rules
        let mut repositories_config = create_test_repository_config();
        repositories_config
            .get_mut("test-repo")
            .unwrap()
            .retention_policy
            .rules = vec!["image.tag == 'latest'".to_string()];

        // Create a new registry with the retention rules and dry run disabled
        let registry = registry
            .with_repositories_config(repositories_config)
            .unwrap()
            .with_scrub_dry_run(false);

        // Create multiple tags with different names
        let tags = ["latest", "v1.0", "v2.0", "old-tag"];
        let mut tag_digests = Vec::new();

        for tag in tags {
            let response = registry
                .put_manifest(
                    namespace,
                    Reference::Tag(tag.to_string()),
                    Some(&media_type),
                    &content,
                )
                .await
                .unwrap();
            tag_digests.push((tag.to_string(), response.digest));
        }

        // Save the first digest for later verification
        let first_digest = tag_digests[0].1.clone();

        // Test enforce retention
        registry.enforce_retention(namespace).await.unwrap();

        // Verify that only the 'latest' tag remains (due to retention rule)
        for (tag, digest) in tag_digests {
            let result = registry
                .get_manifest(
                    registry.validate_namespace(namespace).unwrap(),
                    &[media_type.clone()],
                    namespace,
                    Reference::Tag(tag.clone()),
                )
                .await;

            if tag == "latest" {
                // Latest tag should still exist
                assert!(result.is_ok());
                let manifest = result.unwrap();
                assert_eq!(manifest.digest, digest);
            } else {
                // Other tags should be deleted
                assert!(result.is_err());
            }
        }

        // Verify that the manifest blob still exists (since it's referenced by the 'latest' tag)
        assert!(registry.store.read_blob(&first_digest).await.is_ok());
    }

    #[tokio::test]
    async fn test_enforce_retention_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_enforce_retention_impl(registry).await;
    }

    #[tokio::test]
    async fn test_enforce_retention_s3() {
        let registry = create_test_s3_backend().await;
        test_enforce_retention_impl(registry).await;
    }

    async fn test_scrub_uploads_impl<D: BlobStore + 'static>(registry: Registry<D>) {
        let namespace = "test-repo";
        let session_id = Uuid::new_v4().to_string();

        // Create an upload
        registry
            .store
            .create_upload(namespace, &session_id)
            .await
            .unwrap();

        // Create a new registry with 0 timeout
        let registry = registry
            .with_upload_timeout(Duration::seconds(0))
            .with_scrub_dry_run(false);

        // Test scrub uploads
        registry.scrub_uploads(namespace).await.unwrap();

        // Verify upload is deleted
        assert!(registry
            .store
            .read_upload_summary(namespace, &session_id)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_scrub_uploads_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_scrub_uploads_impl(registry).await;
    }

    #[tokio::test]
    async fn test_scrub_uploads_s3() {
        let registry = create_test_s3_backend().await;
        test_scrub_uploads_impl(registry).await;
    }

    async fn test_scrub_tags_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let response = registry
            .put_manifest(
                namespace,
                Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        // Test scrub tags
        registry.scrub_tags(namespace).await.unwrap();

        // Verify manifest still exists
        let manifest = registry
            .get_manifest(
                registry.validate_namespace(namespace).unwrap(),
                &[media_type.clone()],
                namespace,
                Reference::Tag(tag.to_string()),
            )
            .await
            .unwrap();

        assert_eq!(manifest.digest, response.digest);
    }

    #[tokio::test]
    async fn test_scrub_tags_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_scrub_tags_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_scrub_tags_s3() {
        let registry = create_test_s3_backend().await;
        test_scrub_tags_impl(&registry).await;
    }

    #[allow(clippy::too_many_lines)]
    async fn test_scrub_revisions_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";

        // Create test blobs
        let config_digest = registry.store.create_blob(b"test config").await.unwrap();
        let layer_digest1 = registry.store.create_blob(b"test layer 1").await.unwrap();
        let layer_digest2 = registry.store.create_blob(b"test layer 2").await.unwrap();
        let subject_digest = registry.store.create_blob(b"test subject").await.unwrap();

        // Create some incorrect blobs to test link fixing
        let wrong_config_digest = registry.store.create_blob(b"wrong config").await.unwrap();
        let wrong_layer_digest = registry.store.create_blob(b"wrong layer").await.unwrap();

        // Create manifest content with correct digests
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "digest": config_digest.to_string(),
                "size": 1234
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": layer_digest1.to_string(),
                    "size": 5678
                },
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": layer_digest2.to_string(),
                    "size": 5678
                }
            ]
        });
        let content = serde_json::to_vec(&manifest).unwrap();

        // Create manifest with subject content
        let manifest_with_subject = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "subject": {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "digest": subject_digest.to_string(),
                "size": 1234
            },
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "digest": config_digest.to_string(),
                "size": 1234
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": layer_digest1.to_string(),
                    "size": 5678
                }
            ]
        });
        let content_with_subject = serde_json::to_vec(&manifest_with_subject).unwrap();

        // Create manifest blobs
        let manifest_digest = registry.store.create_blob(&content).await.unwrap();
        let manifest_with_subject_digest = registry
            .store
            .create_blob(&content_with_subject)
            .await
            .unwrap();

        // Create correct config link first
        registry
            .create_link(
                namespace,
                &BlobLink::Config(config_digest.clone()),
                &config_digest,
            )
            .await
            .unwrap();

        // Create manifest revision links and tag
        registry
            .create_link(
                namespace,
                &BlobLink::Digest(manifest_digest.clone()),
                &manifest_digest,
            )
            .await
            .unwrap();
        registry
            .create_link(
                namespace,
                &BlobLink::Digest(manifest_with_subject_digest.clone()),
                &manifest_with_subject_digest,
            )
            .await
            .unwrap();
        registry
            .create_link(
                namespace,
                &BlobLink::Tag("latest".to_string()),
                &manifest_digest,
            )
            .await
            .unwrap();

        // Create incorrect links
        registry
            .create_link(
                namespace,
                &BlobLink::Config(wrong_config_digest.clone()),
                &wrong_config_digest,
            )
            .await
            .unwrap();
        registry
            .create_link(
                namespace,
                &BlobLink::Layer(wrong_layer_digest.clone()),
                &wrong_layer_digest,
            )
            .await
            .unwrap();

        // Create a new registry with dry run disabled
        let new_registry = Registry::new(
            registry.store.clone(),
            create_test_repository_config(),
            &GlobalConfig::default(),
            CacheStoreConfig::default(),
            LockStoreConfig::default(),
        )
        .unwrap()
        .with_scrub_dry_run(false);

        // Test scrub revisions
        new_registry.scrub_revisions(namespace).await.unwrap();

        // Verify links point to correct digests
        assert_eq!(
            new_registry
                .read_link(namespace, &BlobLink::Config(config_digest.clone()))
                .await
                .unwrap()
                .target,
            config_digest,
            "Config link should point to correct digest"
        );

        assert_eq!(
            new_registry
                .read_link(namespace, &BlobLink::Layer(layer_digest1.clone()))
                .await
                .unwrap()
                .target,
            layer_digest1,
            "Layer1 link should point to correct digest"
        );

        assert_eq!(
            new_registry
                .read_link(namespace, &BlobLink::Layer(layer_digest2.clone()))
                .await
                .unwrap()
                .target,
            layer_digest2,
            "Layer2 link should be created and point to correct digest"
        );

        assert_eq!(
            new_registry
                .read_link(
                    namespace,
                    &BlobLink::Referrer(
                        subject_digest.clone(),
                        manifest_with_subject_digest.clone()
                    )
                )
                .await
                .unwrap()
                .target,
            manifest_with_subject_digest,
            "Subject link should point to correct digest"
        );

        // Test error case with invalid manifest content
        let invalid_content = b"invalid manifest content";
        let invalid_digest = new_registry
            .store
            .create_blob(invalid_content)
            .await
            .unwrap();
        new_registry
            .create_link(
                namespace,
                &BlobLink::Digest(invalid_digest.clone()),
                &invalid_digest,
            )
            .await
            .unwrap();
        assert!(new_registry.scrub_revisions(namespace).await.is_ok()); // Should handle invalid manifest gracefully
    }

    async fn test_ensure_link_impl<D: BlobStore + 'static>(registry: Registry<D>) {
        let namespace = "test-repo";
        let digest = registry.store.create_blob(b"test content").await.unwrap();
        let link = BlobLink::Tag("test-tag".to_string());

        let registry = registry.with_scrub_dry_run(false);

        // Test creating a new link
        registry
            .ensure_link(namespace, &link, &digest)
            .await
            .unwrap();
        assert!(registry.read_link(namespace, &link).await.is_ok());

        // Test updating an existing link
        let new_digest = registry.store.create_blob(b"new content").await.unwrap();
        registry
            .ensure_link(namespace, &link, &new_digest)
            .await
            .unwrap();
        let stored_link = registry.read_link(namespace, &link).await.unwrap();
        assert_eq!(stored_link.target, new_digest);

        // Test with invalid link
        let invalid_link = BlobLink::Tag("invalid-tag".to_string());
        registry
            .ensure_link(namespace, &invalid_link, &digest)
            .await
            .unwrap();
        assert!(registry.read_link(namespace, &invalid_link).await.is_ok());
    }

    async fn test_cleanup_orphan_blobs_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace1 = "test-repo1";
        let namespace2 = "test-repo2";
        let content = b"test orphan blob content";

        // Create multiple blobs
        let digest1 = registry.store.create_blob(content).await.unwrap();
        let digest2 = registry.store.create_blob(content).await.unwrap();
        let digest3 = registry.store.create_blob(content).await.unwrap();
        let digest4 = registry.store.create_blob(content).await.unwrap();

        // Create valid links for blobs in different namespaces
        let valid_link1 = BlobLink::Tag("valid-tag1".to_string());
        let valid_link2 = BlobLink::Layer(digest2.clone());
        let valid_link3 = BlobLink::Config(digest3.clone());
        let valid_link4 = BlobLink::Referrer(digest1.clone(), digest4.clone());

        registry
            .create_link(namespace1, &valid_link1, &digest1)
            .await
            .unwrap();
        registry
            .create_link(namespace1, &valid_link2, &digest2)
            .await
            .unwrap();
        registry
            .create_link(namespace2, &valid_link3, &digest3)
            .await
            .unwrap();
        registry
            .create_link(namespace2, &valid_link4, &digest4)
            .await
            .unwrap();

        // Create invalid link by adding to blob index but not creating the actual link
        let invalid_link = BlobLink::Tag("invalid-tag".to_string());
        registry
            .store
            .update_blob_index(namespace1, &digest2, |index| {
                index.insert(invalid_link.clone());
            })
            .await
            .unwrap();

        // Create a new registry with dry run disabled
        let new_registry = Registry::new(
            registry.store.clone(),
            create_test_repository_config(),
            &GlobalConfig::default(),
            CacheStoreConfig::default(),
            LockStoreConfig::default(),
        )
        .unwrap()
        .with_scrub_dry_run(false);

        // Test cleanup orphan blobs
        new_registry.cleanup_orphan_blobs().await.unwrap();

        // Verify results
        assert!(new_registry.store.read_blob(&digest1).await.is_ok()); // Should exist (has valid tag link)
        assert!(new_registry.store.read_blob(&digest2).await.is_ok()); // Should exist (has valid layer link)
        assert!(new_registry.store.read_blob(&digest3).await.is_ok()); // Should exist (has valid config link)
        assert!(new_registry.store.read_blob(&digest4).await.is_ok()); // Should exist (has valid referrer link)
    }

    #[tokio::test]
    async fn test_scrub_revisions_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_scrub_revisions_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_scrub_revisions_s3() {
        let registry = create_test_s3_backend().await;
        test_scrub_revisions_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_ensure_link_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_ensure_link_impl(registry).await;
    }

    #[tokio::test]
    async fn test_ensure_link_s3() {
        let registry = create_test_s3_backend().await;
        test_ensure_link_impl(registry).await;
    }

    #[tokio::test]
    async fn test_cleanup_orphan_blobs_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_cleanup_orphan_blobs_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_cleanup_orphan_blobs_s3() {
        let registry = create_test_s3_backend().await;
        test_cleanup_orphan_blobs_impl(&registry).await;
    }
}
