use crate::registry::blob_store::Error;
use crate::registry::oci_types::{Descriptor, Digest};
use crate::registry::utils::BlobMetadata;
use crate::registry::BlobLink;
use async_trait::async_trait;
use std::collections::HashSet;

pub mod fs;
mod link;
mod lock;
pub mod s3;

pub use link::LinkMetadata;

#[async_trait]
pub trait MetadataStore: Send + Sync {
    async fn list_namespaces(
        &self,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error>;

    async fn list_tags(
        &self,
        namespace: &str,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error>;

    async fn list_referrers(
        &self,
        namespace: &str,
        digest: &Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, Error>;

    async fn list_revisions(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error>;

    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobMetadata, Error>;

    async fn update_blob_index<O>(
        &self,
        namespace: &str,
        digest: &Digest,
        operation: O,
    ) -> Result<(), Error>
    where
        O: FnOnce(&mut HashSet<BlobLink>) + Send;

    async fn create_link(
        &self,
        namespace: &str,
        link: &BlobLink,
        digest: &Digest,
    ) -> Result<LinkMetadata, Error>;

    async fn read_link(
        &self,
        namespace: &str,
        link: &BlobLink,
        update_access_time: bool,
    ) -> Result<LinkMetadata, Error>;

    async fn delete_link(&self, namespace: &str, link: &BlobLink) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use super::MetadataStore;
    use crate::registry::blob_store::BlobStore;
    use crate::registry::oci_types::Descriptor;
    use crate::registry::utils::sha256_ext::Sha256Ext;
    use crate::registry::BlobLink;
    use chrono::{Duration, Utc};
    use sha2::digest::Update;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;

    pub async fn test_datastore_list_namespaces(store: &impl MetadataStore) {
        let namespaces = ["repo1", "repo2", "repo3/nested"];
        let digest = Sha256::new().digest();

        for namespace in &namespaces {
            let tag_link = BlobLink::Tag("latest".to_string());
            store
                .create_link(namespace, &tag_link, &digest)
                .await
                .unwrap();
        }

        // Test listing all namespaces
        let (listed_namespaces, token) = store.list_namespaces(10, None).await.unwrap();
        assert_eq!(listed_namespaces, namespaces);
        assert!(token.is_none() || listed_namespaces.len() >= namespaces.len());

        // Test pagination (2 items per pages)
        let (page1, token1) = store.list_namespaces(2, None).await.unwrap();
        assert_eq!(page1, ["repo1", "repo2"]);
        assert!(token1.is_some());

        let (page2, token2) = store.list_namespaces(2, token1).await.unwrap();
        assert_eq!(page2, ["repo3/nested"]);
        assert!(token2.is_none());

        // Test pagination (1 item per pages)
        let (page1, token1) = store.list_namespaces(1, None).await.unwrap();
        assert_eq!(page1, ["repo1"]);
        assert!(token1.is_some());

        let (page2, token2) = store.list_namespaces(1, token1).await.unwrap();
        assert_eq!(page2, ["repo2"]);

        let (page3, token3) = store.list_namespaces(1, token2).await.unwrap();
        assert_eq!(page3, ["repo3/nested"]);
        assert!(token3.is_none());

        let mut all_namespaces = page1;
        all_namespaces.extend(page2);
        all_namespaces.extend(page3);

        assert_eq!(all_namespaces, namespaces);
    }

    pub async fn test_datastore_list_tags(store: &impl MetadataStore) {
        let namespace = "test-repo";
        let digest = Sha256::new().digest();

        let tags = ["latest", "v1.0", "v2.0"];
        for tag in tags {
            let tag_link = BlobLink::Tag(tag.to_string());
            store
                .create_link(namespace, &tag_link, &digest)
                .await
                .unwrap();
        }

        // Test listing all tags
        let (all_tags, token) = store.list_tags(namespace, 10, None).await.unwrap();
        assert_eq!(all_tags.len(), tags.len());
        for tag in tags {
            assert!(all_tags.contains(&tag.to_string()));
        }
        assert!(token.is_none());

        // Test pagination (2 items per page)
        let (page1, token1) = store.list_tags(namespace, 2, None).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert!(token1.is_some());

        let (page2, token2) = store.list_tags(namespace, 2, token1).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert!(token2.is_none());

        // Test pagination (1 item per page)
        let (page1, token1) = store.list_tags(namespace, 1, None).await.unwrap();
        assert_eq!(page1.len(), 1);
        assert!(token1.is_some());

        let (page2, token2) = store.list_tags(namespace, 1, token1).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert!(token2.is_some());

        let (page3, token3) = store.list_tags(namespace, 1, token2).await.unwrap();
        assert_eq!(page3.len(), 1);
        assert!(token3.is_none());

        // Test tag deletion
        let delete_tag = "v1.0";
        let tag_link = BlobLink::Tag(delete_tag.to_string());
        store.delete_link(namespace, &tag_link).await.unwrap();

        let (tags_after_delete, _) = store.list_tags(namespace, 10, None).await.unwrap();
        assert_eq!(tags_after_delete.len(), tags.len() - 1);
        assert!(!tags_after_delete.contains(&delete_tag.to_string()));
    }

    pub async fn test_datastore_list_referrers(
        blob_store: &impl BlobStore,
        metadata_store: &impl MetadataStore,
    ) {
        let namespace = "test-repo";
        // Create base manifest that will be referenced
        let base_content = b"base manifest content";
        let base_digest = blob_store.create_blob(base_content).await.unwrap();
        let base_link = BlobLink::Digest(base_digest.clone());

        metadata_store
            .create_link(namespace, &base_link, &base_digest)
            .await
            .unwrap();

        // Create artifacts that reference the base manifest
        let referrer_content = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "subject": {{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "{base_digest}",
                    "size": 123
                }},
                "artifactType": "application/vnd.example.test-artifact",
                "config": {{
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:0123456789abcdef0123456789abcdef",
                    "size": 7023
                }},
                "layers": []
            }}"#
        );

        let referrer_digest = blob_store
            .create_blob(referrer_content.as_bytes())
            .await
            .unwrap();
        let link = BlobLink::Digest(referrer_digest.clone());

        metadata_store
            .create_link(namespace, &link, &referrer_digest)
            .await
            .unwrap();

        // Also add it to the referrers index
        let referrers_link = BlobLink::Referrer(base_digest.clone(), referrer_digest.clone());

        metadata_store
            .create_link(namespace, &referrers_link, &referrer_digest)
            .await
            .unwrap();

        // Test listing referrers
        let referrers = metadata_store
            .list_referrers(namespace, &base_digest, None)
            .await;

        let expected = vec![Descriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            digest: referrer_digest.to_string(),
            size: 722,
            annotations: HashMap::new(),
            artifact_type: Some("application/vnd.example.test-artifact".to_string()),
        }];

        assert_eq!(Ok(expected), referrers);

        // Test with artifact type filter
        let filtered_referrers = metadata_store
            .list_referrers(
                namespace,
                &base_digest,
                Some("application/vnd.example.test-artifact".to_string()),
            )
            .await
            .unwrap();

        assert!(!filtered_referrers.is_empty());

        // Test with non-matching artifact type
        let non_matching_referrers = metadata_store
            .list_referrers(
                namespace,
                &base_digest,
                Some("application/vnd.non-existent".to_string()),
            )
            .await
            .unwrap();

        assert!(non_matching_referrers.is_empty());
    }

    pub async fn test_datastore_list_revisions(store: &impl MetadataStore) {
        let namespace = "test-repo";

        let manifest_contents = [
            b"manifest content 1".to_vec(),
            b"manifest content 2".to_vec(),
            b"manifest content 3".to_vec(),
        ];

        let mut digests = Vec::new();
        for content in &manifest_contents {
            let digest = Sha256::new().chain(content).digest();
            digests.push(digest.clone());

            let digest_link = BlobLink::Digest(digest.clone());
            store
                .create_link(namespace, &digest_link, &digest)
                .await
                .unwrap();
        }

        // Test listing all revisions
        let (revisions, token) = store.list_revisions(namespace, 10, None).await.unwrap();
        assert_eq!(revisions.len(), digests.len());
        assert!(token.is_none());
        for digest in &digests {
            assert!(revisions.contains(digest));
        }

        // Test pagination (2 items per page)
        let (page1, token1) = store.list_revisions(namespace, 2, None).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert!(token1.is_some());

        let (page2, token2) = store.list_revisions(namespace, 2, token1).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert!(token2.is_none());

        // Test basic pagination (1 item per page)
        let (page1, token1) = store.list_revisions(namespace, 1, None).await.unwrap();
        assert_eq!(page1.len(), 1);
        assert!(token1.is_some());

        let (page2, token2) = store.list_revisions(namespace, 1, token1).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert!(token2.is_some());

        let (page3, token3) = store.list_revisions(namespace, 1, token2).await.unwrap();
        assert_eq!(page3.len(), 1);
        assert!(token3.is_none());
    }

    pub async fn test_datastore_link_operations(store: &impl MetadataStore) {
        let namespace = "test-namespace";
        let digest = Sha256::new().digest();

        // Test creating and reading tag link
        let tag = "latest";
        let tag_link = BlobLink::Tag(tag.to_string());

        store
            .create_link(namespace, &tag_link, &digest)
            .await
            .unwrap();

        let read_digest = store.read_link(namespace, &tag_link, false).await.unwrap();
        assert_eq!(read_digest.target, digest);

        // Test reading reference info
        let ref_info = store.read_link(namespace, &tag_link, false).await.unwrap();
        let created_at = ref_info.created_at.unwrap();
        assert!(Utc::now().signed_duration_since(created_at) < Duration::seconds(1));
    }
}
