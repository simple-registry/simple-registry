mod error;
mod fs_backend;
mod s3_backend;

use crate::registry::oci_types::{Descriptor, Digest};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use tokio::io::AsyncRead;

pub use fs_backend::FSBackend;
pub use s3_backend::S3Backend;

use crate::registry::utils::DataLink;
pub use error::Error;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BlobEntityLinkIndex {
    pub namespace: HashMap<String, HashSet<DataLink>>,
}

#[derive(Clone, Debug)]
pub struct ReferenceInfo {
    pub created_at: DateTime<Utc>,
    pub accessed_at: DateTime<Utc>,
}

pub trait Reader: AsyncRead + Unpin + Send {}
impl<T> Reader for T where T: AsyncRead + Unpin + Send {}

#[async_trait]
pub trait DataStore: Send + Sync {
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

    async fn list_uploads(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error>;

    async fn list_blobs(
        &self,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error>;

    async fn list_revisions(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error>;

    async fn create_upload(&self, namespace: &str, uuid: &str) -> Result<String, Error>;

    async fn write_upload<S: AsyncRead + Unpin + Send + Sync>(
        &self,
        namespace: &str,
        uuid: &str,
        stream: S,
        append: bool,
    ) -> Result<(), Error>;

    async fn read_upload_summary(
        &self,
        namespace: &str,
        uuid: &str,
    ) -> Result<(Digest, u64, DateTime<Utc>), Error>;

    async fn complete_upload(
        &self,
        namespace: &str,
        uuid: &str,
        digest: Option<Digest>,
    ) -> Result<Digest, Error>;

    async fn delete_upload(&self, namespace: &str, uuid: &str) -> Result<(), Error>;

    async fn create_blob(&self, content: &[u8]) -> Result<Digest, Error>;

    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, Error>;

    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobEntityLinkIndex, Error>;

    async fn update_blob_index<O>(
        &self,
        namespace: &str,
        digest: &Digest,
        operation: O,
    ) -> Result<(), Error>
    where
        O: FnOnce(&mut HashSet<DataLink>) + Send;

    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, Error>;

    async fn read_reference_info(
        &self,
        name: &str,
        reference: &DataLink,
    ) -> Result<ReferenceInfo, Error>;

    async fn build_blob_reader(
        &self,
        digest: &Digest,
        start_offset: Option<u64>,
    ) -> Result<Box<dyn Reader>, Error>;

    async fn update_last_pulled(
        &self,
        name: &str,
        tag: Option<String>,
        digest: &Digest,
    ) -> Result<(), Error>;

    async fn read_link(&self, namespace: &str, reference: &DataLink) -> Result<Digest, Error>;

    async fn create_link(
        &self,
        namespace: &str,
        reference: &DataLink,
        digest: &Digest,
    ) -> Result<(), Error>;

    async fn delete_link(&self, namespace: &str, reference: &DataLink) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::io::Cursor;
    use uuid::Uuid;

    /// Helper function to test list_namespaces functionality on any DataStore implementation
    pub async fn test_datastore_list_namespaces(store: &impl DataStore) {
        // Create test data
        let namespaces = ["repo1", "repo2", "repo3/nested"];
        let test_content = b"test content";
        let digest = store.create_blob(test_content).await.unwrap();

        for namespace in &namespaces {
            let tag_link = DataLink::Tag("latest".to_string());
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

    pub async fn test_datastore_list_tags(store: &impl DataStore) {
        let namespace = "test-repo";

        let digest = store.create_blob(b"manifest content").await.unwrap();

        let tags = ["latest", "v1.0", "v2.0"];
        for tag in &tags {
            let tag_link = DataLink::Tag(tag.to_string());
            store
                .create_link(namespace, &tag_link, &digest)
                .await
                .unwrap();
        }

        // Test listing all tags
        let (all_tags, token) = store.list_tags(namespace, 10, None).await.unwrap();
        assert_eq!(all_tags.len(), tags.len());
        for tag in &tags {
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
        let tag_link = DataLink::Tag(delete_tag.to_string());
        store.delete_link(namespace, &tag_link).await.unwrap();

        let (tags_after_delete, _) = store.list_tags(namespace, 10, None).await.unwrap();
        assert_eq!(tags_after_delete.len(), tags.len() - 1);
        assert!(!tags_after_delete.contains(&delete_tag.to_string()));
    }

    pub async fn test_datastore_list_referrers(store: &impl DataStore) {
        let namespace = "test-repo";

        let base_digest = store.create_blob(b"base manifest content").await.unwrap();

        let base_link = DataLink::Digest(base_digest.clone());
        store
            .create_link(namespace, &base_link, &base_digest)
            .await
            .unwrap();

        let artifact_manifest = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": "application/vnd.example.test-artifact",
            "subject": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "%BASE_DIGEST%",
                "size": 123
            },
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size": 456
            },
            "layers": []
        }"#
        .replace("%BASE_DIGEST%", &base_digest.to_string());

        let referrer_digest = store
            .create_blob(artifact_manifest.as_bytes())
            .await
            .unwrap();

        let referrer_link = DataLink::Digest(referrer_digest.clone());
        store
            .create_link(namespace, &referrer_link, &referrer_digest)
            .await
            .unwrap();

        let referrers_link = DataLink::Referrer(base_digest.clone(), referrer_digest.clone());
        store
            .create_link(namespace, &referrers_link, &referrer_digest)
            .await
            .unwrap();

        // Test listing referrers
        let referrers = store
            .list_referrers(namespace, &base_digest, None)
            .await
            .unwrap();

        assert!(!referrers.is_empty());

        // Test with artifact type filter
        let filtered_referrers = store
            .list_referrers(
                namespace,
                &base_digest,
                Some("application/vnd.example.test-artifact".to_string()),
            )
            .await
            .unwrap();

        assert!(!filtered_referrers.is_empty());

        // Test with non-matching artifact type
        let non_matching_referrers = store
            .list_referrers(
                namespace,
                &base_digest,
                Some("application/vnd.non-existent".to_string()),
            )
            .await
            .unwrap();

        assert!(non_matching_referrers.is_empty());
    }

    pub async fn test_datastore_list_uploads(store: &impl DataStore) {
        let namespace = "test-repo";

        let upload_ids = ["upload1", "upload2", "upload3"];
        for id in &upload_ids {
            store.create_upload(namespace, id).await.unwrap();

            let content = format!("Content for upload {}", id);
            store
                .write_upload(namespace, id, &mut Cursor::new(content.as_bytes()), false)
                .await
                .unwrap();
        }

        // Verify we can list all uploads
        let (uploads, _token) = store.list_uploads(namespace, 10, None).await.unwrap();
        assert_eq!(uploads.len(), upload_ids.len());
        for id in &upload_ids {
            assert!(uploads.contains(&id.to_string()));
        }

        // Test pagination (2 items per page)
        let (page1, token1) = store.list_uploads(namespace, 2, None).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert!(token1.is_some());

        let (page2, token2) = store.list_uploads(namespace, 2, token1).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert!(token2.is_none());

        // Test pagination (1 item per page)
        let (page1, token1) = store.list_uploads(namespace, 1, None).await.unwrap();
        assert_eq!(page1.len(), 1);
        assert!(token1.is_some());

        let (page2, token2) = store.list_uploads(namespace, 1, token1).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert!(token2.is_some());

        let (page3, token3) = store.list_uploads(namespace, 1, token2).await.unwrap();
        assert_eq!(page3.len(), 1);
        assert!(token3.is_none());

        // Test upload operations - verify we can complete an upload
        let upload_to_complete = upload_ids[0];
        let (digest, _size, _) = store
            .read_upload_summary(namespace, upload_to_complete)
            .await
            .unwrap();
        let completed_digest = store
            .complete_upload(namespace, upload_to_complete, None)
            .await
            .unwrap();
        assert_eq!(completed_digest, digest);

        // The upload should be gone after completion
        let (uploads_after_complete, _) = store.list_uploads(namespace, 10, None).await.unwrap();
        assert_eq!(uploads_after_complete.len(), upload_ids.len() - 1);
        assert!(!uploads_after_complete.contains(&upload_to_complete.to_string()));
    }

    pub async fn test_datastore_list_blobs(store: &impl DataStore) {
        let blob_contents = [
            b"aaa_content_1".to_vec(),
            b"bbb_content_2".to_vec(),
            b"ccc_content_3".to_vec(),
        ];

        let mut digests = Vec::new();
        for content in &blob_contents {
            let digest = store.create_blob(content).await.unwrap();
            digests.push(digest);
        }

        // Test without pagination
        let (blobs, _token) = store.list_blobs(10, None).await.unwrap();
        assert!(blobs.len() >= blob_contents.len());
        for digest in &digests {
            assert!(blobs.contains(digest));
        }

        // Test pagination (2 items per page)
        let (page1, token1) = store.list_blobs(2, None).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert!(token1.is_some());

        let (page2, token2) = store.list_blobs(2, token1).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert!(token2.is_none());

        // Test pagination (1 item per page)
        let (page1, token1) = store.list_blobs(1, None).await.unwrap();
        assert_eq!(page1.len(), 1);
        assert!(token1.is_some());

        let (page2, token2) = store.list_blobs(1, token1).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert!(token2.is_some());

        let (page3, token3) = store.list_blobs(1, token2).await.unwrap();
        assert_eq!(page3.len(), 1);
        assert!(token3.is_none());
    }

    pub async fn test_datastore_list_revisions(store: &impl DataStore) {
        let namespace = "test-repo";

        let manifest_contents = [
            b"manifest content 1".to_vec(),
            b"manifest content 2".to_vec(),
            b"manifest content 3".to_vec(),
        ];

        let mut digests = Vec::new();
        for content in &manifest_contents {
            let digest = store.create_blob(content).await.unwrap();
            digests.push(digest.clone());

            let digest_link = DataLink::Digest(digest.clone());
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

    pub async fn test_datastore_blob_operations(store: &impl DataStore) {
        let test_content = b"Test blob content";
        let digest = store.create_blob(test_content).await.unwrap();

        let retrieved_content = store.read_blob(&digest).await.unwrap();
        assert_eq!(retrieved_content, test_content);

        let size = store.get_blob_size(&digest).await.unwrap();
        assert_eq!(size, test_content.len() as u64);

        // Test blob reader
        let mut reader = store.build_blob_reader(&digest, None).await.unwrap();
        let mut buffer = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buffer)
            .await
            .unwrap();
        assert_eq!(buffer, test_content);

        // Test blob index tracking
        let namespace = "test-namespace";
        let tag = "latest";
        let tag_link = DataLink::Tag(tag.to_string());

        store
            .create_link(namespace, &tag_link, &digest)
            .await
            .unwrap();
        let blob_index = store.read_blob_index(&digest).await.unwrap();
        assert!(blob_index.namespace.contains_key(namespace));

        let namespace_links = blob_index.namespace.get(namespace).unwrap();
        assert!(namespace_links.contains(&tag_link));

        store.delete_link(namespace, &tag_link).await.unwrap();

        // The blob should be deleted when all links are gone
        let blob_result = store.read_blob(&digest).await;
        assert!(blob_result.is_err());
    }

    pub async fn test_datastore_upload_operations(store: &impl DataStore) {
        let namespace = "test-namespace";
        let uuid = Uuid::new_v4().to_string();

        let upload_id = store.create_upload(namespace, &uuid).await.unwrap();
        assert_eq!(upload_id, uuid);

        let test_content = b"Test upload content";
        store
            .write_upload(
                namespace,
                &uuid,
                &mut Cursor::new(test_content.to_vec()),
                false,
            )
            .await
            .unwrap();

        let (digest, size, start_date) = store.read_upload_summary(namespace, &uuid).await.unwrap();
        assert_eq!(size, test_content.len() as u64);
        assert!(Utc::now().signed_duration_since(start_date) < Duration::hours(1));

        let final_digest = store.complete_upload(namespace, &uuid, None).await.unwrap();
        assert_eq!(final_digest, digest);

        let blob_content = store.read_blob(&final_digest).await.unwrap();
        assert_eq!(blob_content, test_content);

        // Test upload not found after completion
        let upload_result = store.read_upload_summary(namespace, &uuid).await;
        assert!(upload_result.is_err());
    }

    pub async fn test_datastore_link_operations(store: &impl DataStore) {
        let namespace = "test-namespace";
        let test_content = b"Test content for linking";
        let digest = store.create_blob(test_content).await.unwrap();

        // Test creating and reading tag link
        let tag = "latest";
        let tag_link = DataLink::Tag(tag.to_string());

        store
            .create_link(namespace, &tag_link, &digest)
            .await
            .unwrap();
        let read_digest = store.read_link(namespace, &tag_link).await.unwrap();
        assert_eq!(read_digest, digest);

        // Test reading reference info
        let ref_info = store
            .read_reference_info(namespace, &tag_link)
            .await
            .unwrap();
        assert!(Utc::now().signed_duration_since(ref_info.created_at) < Duration::hours(1));

        // Create multiple links to the same blob
        let tags = ["v1", "v2", "v3"];
        for tag in tags {
            let tag_link = DataLink::Tag(tag.to_string());
            store
                .create_link(namespace, &tag_link, &digest)
                .await
                .unwrap();
        }

        // Verify blob index contains all links
        let blob_index = store.read_blob_index(&digest).await.unwrap();
        let namespace_links = blob_index.namespace.get(namespace).unwrap();

        for tag in tags {
            let tag_link = DataLink::Tag(tag.to_string());
            assert!(namespace_links.contains(&tag_link));
        }

        // XXX: Test last pulled update
        // store.update_last_pulled(namespace, Some(tag.to_string()), &digest).await.unwrap();

        // Deleting links
        store.delete_link(namespace, &tag_link).await.unwrap();
        let result = store.read_link(namespace, &tag_link).await;
        assert!(result.is_err());

        // Delete all links
        for tag in &tags {
            let tag_link = DataLink::Tag(tag.to_string());
            store.delete_link(namespace, &tag_link).await.unwrap();
        }

        // Verify blob is deleted when all links are removed
        let result = store.read_blob(&digest).await;
        assert!(result.is_err());
    }
}
