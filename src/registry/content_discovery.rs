use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::oci_types::{Descriptor, Digest};
use crate::registry::{blob_store, Error, Registry};
use tracing::instrument;

impl<B, M> Registry<B, M>
where
    B: BlobStore,
    M: MetadataStore,
{
    #[instrument]
    pub async fn get_referrers(
        &self,
        namespace: &str,
        digest: Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, Error> {
        self.validate_namespace(namespace)?;

        match self
            .metadata_store
            .list_referrers(namespace, &digest, artifact_type)
            .await
        {
            Ok(referrers) => Ok(referrers),
            Err(blob_store::Error::BlobNotFound) => Ok(Vec::new()),
            Err(e) => Err(e)?,
        }
    }

    #[instrument]
    pub async fn list_catalog(
        &self,
        n: Option<u16>,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        let n = n.unwrap_or(100);

        let (namespaces, next_last) = self.metadata_store.list_namespaces(n, last).await?;
        let link = next_last.map(|next_last| format!("/v2/_catalog?n={n}&last={next_last}"));

        let namespaces = namespaces
            .into_iter()
            .map(|digest| digest.to_string())
            .collect();
        Ok((namespaces, link))
    }

    #[instrument]
    pub async fn list_tags(
        &self,
        namespace: &str,
        n: Option<u16>,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        self.validate_namespace(namespace)?;

        let n = n.unwrap_or(100);

        let (tags, next_last) = self.metadata_store.list_tags(namespace, n, last).await?;
        let link =
            next_last.map(|next_last| format!("/v2/{namespace}/tags/list?n={n}&last={next_last}"));

        Ok((tags, link))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::{FSRegistryTestCase, S3RegistryTestCase};
    use crate::registry::utils::BlobLink;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_get_referrers_fs() {
        let t = FSRegistryTestCase::new();
        test_get_referrers(t.registry()).await;
    }

    #[tokio::test]
    async fn test_get_referrers_s3() {
        let t = S3RegistryTestCase::new();
        test_get_referrers(t.registry()).await;
    }

    async fn test_get_referrers<B: BlobStore, M: MetadataStore>(registry: &Registry<B, M>) {
        let namespace = "test-repo";
        let digest = Digest::from_str(
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )
        .unwrap();

        // Create a link to make the namespace valid
        let test_content = b"test content";
        let test_digest = registry.blob_store.create_blob(test_content).await.unwrap();
        let tag_link = BlobLink::Tag("latest".to_string());
        registry
            .create_link(namespace, &tag_link, &test_digest)
            .await
            .unwrap();

        // Test empty referrers list
        let referrers = registry
            .get_referrers(namespace, digest.clone(), None)
            .await
            .unwrap();
        assert!(referrers.is_empty());

        // Test with artifact type filter
        let referrers = registry
            .get_referrers(namespace, digest.clone(), Some("test-type".to_string()))
            .await
            .unwrap();
        assert!(referrers.is_empty());
    }

    #[tokio::test]
    async fn test_list_catalog_fs() {
        let t = FSRegistryTestCase::new();
        test_list_catalog(t.registry()).await;
    }

    #[tokio::test]
    async fn test_list_catalog_s3() {
        let t = S3RegistryTestCase::new();
        test_list_catalog(t.registry()).await;
    }

    async fn test_list_catalog<B: BlobStore, M: MetadataStore>(registry: &Registry<B, M>) {
        // Test default pagination (n=100)
        let (namespaces, token) = registry.list_catalog(None, None).await.unwrap();
        assert!(namespaces.is_empty());
        assert!(token.is_none());

        // Test custom pagination
        let (namespaces, token) = registry.list_catalog(Some(10), None).await.unwrap();
        assert!(namespaces.is_empty());
        assert!(token.is_none());

        // Test with last token
        let (namespaces, token) = registry
            .list_catalog(Some(10), Some("test".to_string()))
            .await
            .unwrap();
        assert!(namespaces.is_empty());
        assert!(token.is_none());
    }

    #[tokio::test]
    async fn test_list_tags_fs() {
        let t = FSRegistryTestCase::new();
        test_list_tags(t.registry()).await;
    }

    #[tokio::test]
    async fn test_list_tags_s3() {
        let t = S3RegistryTestCase::new();
        test_list_tags(t.registry()).await;
    }

    async fn test_list_tags<B: BlobStore, M: MetadataStore>(registry: &Registry<B, M>) {
        let namespace = "test-repo";

        // Create some tags first
        let test_content = b"test content";
        let test_digest = registry.blob_store.create_blob(test_content).await.unwrap();
        let tags = ["latest", "v1.0", "v2.0"];
        for tag in tags {
            let tag_link = BlobLink::Tag(tag.to_string());
            registry
                .create_link(namespace, &tag_link, &test_digest)
                .await
                .unwrap();
        }

        // Test default pagination (n=100)
        let (tags, token) = registry.list_tags(namespace, None, None).await.unwrap();
        assert_eq!(tags.len(), 3);
        assert!(tags.contains(&"latest".to_string()));
        assert!(tags.contains(&"v1.0".to_string()));
        assert!(tags.contains(&"v2.0".to_string()));
        assert!(token.is_none());

        // Test custom pagination (2 items per page)
        let (page1, token1) = registry.list_tags(namespace, Some(2), None).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert!(token1.is_some());

        // Extract the last tag from the token URL
        let last_tag = token1.unwrap().split("last=").nth(1).unwrap().to_string();

        let (page2, token2) = registry
            .list_tags(namespace, Some(2), Some(last_tag))
            .await
            .unwrap();
        assert_eq!(page2.len(), 1);
        assert!(token2.is_none());

        // Test custom pagination (1 item per page)
        let (page1, token1) = registry.list_tags(namespace, Some(1), None).await.unwrap();
        assert_eq!(page1.len(), 1);
        assert!(token1.is_some());

        // Extract the last tag from the token URL
        let last_tag = token1.unwrap().split("last=").nth(1).unwrap().to_string();

        let (page2, token2) = registry
            .list_tags(namespace, Some(1), Some(last_tag))
            .await
            .unwrap();
        assert_eq!(page2.len(), 1);
        assert!(token2.is_some());

        // Extract the last tag from the token URL
        let last_tag = token2.unwrap().split("last=").nth(1).unwrap().to_string();

        let (page3, token3) = registry
            .list_tags(namespace, Some(1), Some(last_tag))
            .await
            .unwrap();
        assert_eq!(page3.len(), 1);
        assert!(token3.is_none());

        // Test with last token beyond the end
        let (tags, token) = registry
            .list_tags(namespace, Some(10), Some("latest".to_string()))
            .await
            .unwrap();
        assert_eq!(tags.len(), 2);
        assert!(token.is_none());
    }
}
