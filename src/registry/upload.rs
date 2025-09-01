use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::oci_types::Digest;
use crate::registry::{Error, Registry};
use tokio::io::AsyncRead;
use tracing::{error, instrument, warn};
use uuid::Uuid;

pub enum StartUploadResponse {
    ExistingBlob(Digest),
    Session(String, String),
}

impl<B, M> Registry<B, M>
where
    B: BlobStore,
    M: MetadataStore,
{
    #[instrument]
    pub async fn start_upload(
        &self,
        namespace: &str,
        digest: Option<Digest>,
    ) -> Result<StartUploadResponse, Error> {
        self.validate_namespace(namespace)?;

        if let Some(digest) = digest {
            if self.blob_store.get_blob_size(&digest).await.is_ok() {
                return Ok(StartUploadResponse::ExistingBlob(digest));
            }
        }

        let session_uuid = Uuid::new_v4().to_string();
        self.blob_store
            .create_upload(namespace, &session_uuid)
            .await?;

        let location = format!("/v2/{namespace}/blobs/uploads/{session_uuid}");
        Ok(StartUploadResponse::Session(location, session_uuid))
    }

    #[instrument(skip(stream))]
    pub async fn patch_upload<S>(
        &self,
        namespace: &str,
        session_id: Uuid,
        start_offset: Option<u64>,
        stream: S,
    ) -> Result<u64, Error>
    where
        S: AsyncRead + Unpin + Send + Sync,
    {
        self.validate_namespace(namespace)?;

        let session_id = session_id.to_string();
        if let Some(start_offset) = start_offset {
            let (_, size, _) = self
                .blob_store
                .read_upload_summary(namespace, &session_id)
                .await?;

            if start_offset != size {
                return Err(Error::RangeNotSatisfiable);
            }
        }

        self.blob_store
            .write_upload(namespace, &session_id, stream, true)
            .await?;

        let (_, size, _) = self
            .blob_store
            .read_upload_summary(namespace, &session_id)
            .await
            .map_err(|error| {
                error!("Error reading uploaded file: {error}");
                error
            })?;

        if size < 1 {
            return Ok(0);
        }

        Ok(size - 1)
    }

    #[instrument(skip(stream))]
    pub async fn complete_upload<S>(
        &self,
        namespace: &str,
        session_id: Uuid,
        digest: Digest,
        stream: S,
    ) -> Result<(), Error>
    where
        S: AsyncRead + Unpin + Send + Sync,
    {
        self.validate_namespace(namespace)?;

        let session_id = session_id.to_string();

        let append = self
            .blob_store
            .read_upload_summary(namespace, &session_id)
            .await
            .is_ok();

        self.blob_store
            .write_upload(namespace, &session_id, stream, append)
            .await?;

        let (upload_digest, _, _) = self
            .blob_store
            .read_upload_summary(namespace, &session_id)
            .await?;

        if upload_digest != digest {
            warn!("Expected digest '{digest}', got '{upload_digest}'");
            return Err(Error::DigestInvalid);
        }

        self.blob_store
            .complete_upload(namespace, &session_id, Some(digest))
            .await?;
        self.blob_store
            .delete_upload(namespace, &session_id)
            .await?;

        Ok(())
    }

    #[instrument]
    pub async fn delete_upload(&self, namespace: &str, session_id: Uuid) -> Result<(), Error> {
        self.validate_namespace(namespace)?;

        let uuid = session_id.to_string();
        self.blob_store.delete_upload(namespace, &uuid).await?;

        Ok(())
    }

    #[instrument]
    pub async fn get_upload_range_max(
        &self,
        namespace: &str,
        session_id: Uuid,
    ) -> Result<u64, Error> {
        self.validate_namespace(namespace)?;

        let uuid = session_id.to_string();
        let (_, size, _) = self
            .blob_store
            .read_upload_summary(namespace, &uuid)
            .await?;

        if size < 1 {
            return Ok(0);
        }

        Ok(size - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::test_utils::{create_test_fs_backend, create_test_s3_backend};
    use std::io::Cursor;

    async fn test_start_upload_impl<B: BlobStore + 'static, M: MetadataStore>(
        registry: &Registry<B, M>,
    ) {
        let namespace = "test-repo";
        let content = b"test upload content";

        // Test starting a new upload
        let response = registry.start_upload(namespace, None).await.unwrap();
        match response {
            StartUploadResponse::Session(location, session_id) => {
                assert!(location.starts_with(&format!("/v2/{namespace}/blobs/uploads/")));
                assert!(!session_id.is_empty());
            }
            StartUploadResponse::ExistingBlob(_) => panic!("Expected Session response"),
        }

        // Test starting upload with existing blob
        let digest = registry.blob_store.create_blob(content).await.unwrap();
        let response = registry
            .start_upload(namespace, Some(digest.clone()))
            .await
            .unwrap();
        match response {
            StartUploadResponse::ExistingBlob(existing_digest) => {
                assert_eq!(existing_digest, digest);
            }
            StartUploadResponse::Session(..) => panic!("Expected ExistingBlob response"),
        }
    }

    #[tokio::test]
    async fn test_start_upload_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_start_upload_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_start_upload_s3() {
        let registry = create_test_s3_backend().await;
        test_start_upload_impl(&registry).await;
    }

    async fn test_patch_upload_impl<B: BlobStore + 'static, M: MetadataStore>(
        registry: &Registry<B, M>,
    ) {
        let namespace = "test-repo";
        let content = b"test patch content";
        let session_id = Uuid::new_v4();

        // Create initial upload
        registry
            .blob_store
            .create_upload(namespace, &session_id.to_string())
            .await
            .unwrap();

        // Test patch upload
        let stream = Cursor::new(content);
        let bytes_written = registry
            .patch_upload(namespace, session_id, None, stream)
            .await
            .unwrap();
        assert_eq!(bytes_written, (content.len() - 1) as u64);

        // Test patch upload with offset
        let additional_content = b" additional";
        let stream = Cursor::new(additional_content);
        let bytes_written = registry
            .patch_upload(namespace, session_id, Some(content.len() as u64), stream)
            .await
            .unwrap();
        assert_eq!(
            bytes_written,
            (content.len() + additional_content.len() - 1) as u64
        );

        // Verify content
        let (_, size, _) = registry
            .blob_store
            .read_upload_summary(namespace, &session_id.to_string())
            .await
            .unwrap();
        assert_eq!(size, (content.len() + additional_content.len()) as u64);
    }

    #[tokio::test]
    async fn test_patch_upload_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_patch_upload_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_patch_upload_s3() {
        let registry = create_test_s3_backend().await;
        test_patch_upload_impl(&registry).await;
    }

    async fn test_complete_upload_impl<B: BlobStore + 'static, M: MetadataStore>(
        registry: &Registry<B, M>,
    ) {
        let namespace = "test-repo";
        let content = b"test complete content";
        let session_id = Uuid::new_v4();

        // Create initial upload
        registry
            .blob_store
            .create_upload(namespace, &session_id.to_string())
            .await
            .unwrap();

        // Write content
        let stream = Cursor::new(content);
        registry
            .patch_upload(namespace, session_id, None, stream)
            .await
            .unwrap();

        // Get the upload digest
        let (upload_digest, _, _) = registry
            .blob_store
            .read_upload_summary(namespace, &session_id.to_string())
            .await
            .unwrap();

        // Complete upload with empty stream since content is already written
        let empty_stream = Cursor::new(Vec::new());
        registry
            .complete_upload(namespace, session_id, upload_digest.clone(), empty_stream)
            .await
            .unwrap();

        // Verify blob exists
        let stored_content = registry.blob_store.read_blob(&upload_digest).await.unwrap();
        assert_eq!(stored_content, content);
    }

    #[tokio::test]
    async fn test_complete_upload_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_complete_upload_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_complete_upload_s3() {
        let registry = create_test_s3_backend().await;
        test_complete_upload_impl(&registry).await;
    }

    async fn test_delete_upload_impl<B: BlobStore + 'static, M: MetadataStore>(
        registry: &Registry<B, M>,
    ) {
        let namespace = "test-repo";
        let session_id = Uuid::new_v4();

        // Create upload
        registry
            .blob_store
            .create_upload(namespace, &session_id.to_string())
            .await
            .unwrap();

        // Verify upload exists
        assert!(registry
            .blob_store
            .read_upload_summary(namespace, &session_id.to_string())
            .await
            .is_ok());

        // Delete upload
        registry.delete_upload(namespace, session_id).await.unwrap();

        // Verify upload is deleted
        assert!(registry
            .blob_store
            .read_upload_summary(namespace, &session_id.to_string())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_delete_upload_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_delete_upload_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_delete_upload_s3() {
        let registry = create_test_s3_backend().await;
        test_delete_upload_impl(&registry).await;
    }

    async fn test_get_upload_range_max_impl<B: BlobStore + 'static, M: MetadataStore>(
        registry: &Registry<B, M>,
    ) {
        let namespace = "test-repo";
        let content = b"test range content";
        let session_id = Uuid::new_v4();

        // Create upload
        registry
            .blob_store
            .create_upload(namespace, &session_id.to_string())
            .await
            .unwrap();

        // Test empty upload
        let range_max = registry
            .get_upload_range_max(namespace, session_id)
            .await
            .unwrap();
        assert_eq!(range_max, 0);

        // Write content
        let stream = Cursor::new(content);
        registry
            .patch_upload(namespace, session_id, None, stream)
            .await
            .unwrap();

        // Test with content
        let range_max = registry
            .get_upload_range_max(namespace, session_id)
            .await
            .unwrap();
        assert_eq!(range_max, (content.len() - 1) as u64);
    }

    #[tokio::test]
    async fn test_get_upload_range_max_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_get_upload_range_max_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_get_upload_range_max_s3() {
        let registry = create_test_s3_backend().await;
        test_get_upload_range_max_impl(&registry).await;
    }
}
