use crate::policy::ManifestImage;
use crate::registry::data_store::ReferenceInfo;
use crate::registry::oci_types::{Digest, Reference};
use crate::registry::utils::DataLink;
use crate::registry::{parse_manifest_digests, Error, Registry};
use cel_interpreter::{Context, Program, Value};
use chrono::Utc;
use std::collections::HashMap;
use std::process::exit;
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
    debug!("Policy context (image) : {:?}", manifest);

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

        debug!(
            "CEL program '{:?}' evaluates to {:?}",
            policy, evaluation_result
        );
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

impl Registry {
    pub async fn enforce_retention(&self, namespace: &str) -> Result<(), Error> {
        info!("'{}': Enforcing retention policy", namespace);

        let mut marker = None;
        let mut tag_names = Vec::new();
        loop {
            let (tags, next_marker) = self
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
    ) -> Result<(), Error> {
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
        info!("'{}': Checking for obsolete uploads", namespace);

        let mut marker = None;
        loop {
            let (uploads, next_marker) = self
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

    async fn check_upload(&self, namespace: &str, uuid: &str) -> Result<(), Error> {
        let (_, _, start_date) = self
            .storage_engine
            .read_upload_summary(namespace, uuid)
            .await?;

        let now = Utc::now();
        let duration = now.signed_duration_since(start_date);

        if duration <= self.scrub_upload_timeout {
            return Ok(());
        }

        warn!("'{}': upload '{}' is obsolete", namespace, uuid);
        if !self.scrub_dry_run {
            if let Err(err) = self.storage_engine.delete_upload(namespace, uuid).await {
                error!("Failed to delete upload '{}': {}", uuid, err);
            }
        }

        Ok(())
    }

    pub(crate) async fn scrub_tags(&self, namespace: &str) -> Result<(), Error> {
        info!("'{}': Checking tags/revision inconsistencies", namespace);

        let mut marker = None;
        loop {
            let (tags, next_marker) = self
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

    async fn check_tag(&self, namespace: &str, tag: &str) -> Result<(), Error> {
        debug!(
            "Checking {}:{} for revision inconsistencies",
            namespace, tag
        );
        let digest = self
            .storage_engine
            .read_link(namespace, &DataLink::Tag(tag.to_string()))
            .await?;

        let link_reference = DataLink::Digest(digest.clone());
        if let Err(e) = self.ensure_link(namespace, &link_reference, &digest).await {
            warn!("Failed to ensure link: {}", e);
        }

        Ok(())
    }

    pub(crate) async fn scrub_revisions(&self, namespace: &str) -> Result<(), Error> {
        info!("'{}': Checking for revision inconsistencies", namespace);

        let mut marker = None;

        loop {
            let (revisions, next_marker) = self
                .storage_engine
                .list_revisions(namespace, 0, marker)
                .await?;

            for revision in revisions {
                let content = self.storage_engine.read_blob(&revision).await?;
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
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
        let blob_digest = self
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
        if !self.scrub_dry_run {
            self.storage_engine
                .create_link(namespace, link_reference, digest)
                .await?;
        }

        Ok(())
    }

    pub(crate) async fn cleanup_orphan_blobs(&self) -> Result<(), Error> {
        info!("Checking for orphan blobs");

        let mut marker = None;
        loop {
            let Ok((blobs, next_marker)) = self.storage_engine.list_blobs(100, marker).await else {
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

    async fn check_blob(&self, blob: &Digest) -> Result<(), Error> {
        let mut blob_index = self.storage_engine.read_blob_index(blob).await?;

        for (namespace, references) in blob_index.namespace.clone() {
            for link_reference in references {
                if self
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
                    if !self.scrub_dry_run {
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
            if !self.scrub_dry_run {
                if let Err(err) = self.storage_engine.delete_blob(blob).await {
                    error!("Failed to delete blob: {}", err);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retention_policy_no_rules() {
        let policies = vec![];
        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };
        assert!(!manifest_should_be_purged(&policies, &manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_retention_policy_not_purged() {
        let policies = vec![Program::compile("image.tag == 'latest'").unwrap()];
        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };
        assert!(!manifest_should_be_purged(&policies, &manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_retention_policy_purged() {
        let policies = vec![Program::compile("image.tag == 'latest'").unwrap()];
        let manifest = ManifestImage {
            tag: Some("x".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };
        assert!(manifest_should_be_purged(&policies, &manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_retention_policy_invalid() {
        let policies = vec![Program::compile("image.tag").unwrap()];
        let manifest = ManifestImage {
            tag: None,
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };
        assert!(!manifest_should_be_purged(&policies, &manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_function_now_days() {
        let policies = vec![Program::compile("now() + days(15) == now() + 86400 * 15").unwrap()];
        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };

        assert!(!manifest_should_be_purged(&policies, &manifest, &vec![], &vec![]).unwrap());
    }

    #[test]
    fn test_function_top_last_pushed() {
        let policies = vec![Program::compile("top(image.tag, last_pushed, 1)").unwrap()];

        let manifest = ManifestImage {
            tag: Some("latest".to_string()),
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
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
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
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
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
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
            pushed_at: 1710441600,
            last_pulled_at: 1710441600,
        };
        assert!(manifest_should_be_purged(
            &policies,
            &manifest,
            &vec![],
            &vec!["latest".to_string()]
        )
        .unwrap());
    }
}
