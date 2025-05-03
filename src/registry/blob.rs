use crate::registry::api::hyper::response_ext::IntoAsyncRead;
use crate::registry::api::hyper::response_ext::ResponseExt;
use crate::registry::api::hyper::DOCKER_CONTENT_DIGEST;
use crate::registry::data_store::{DataStore, Reader};
use crate::registry::oci_types::Digest;
use crate::registry::utils::{tee_reader, BlobLink};
use crate::registry::{data_store, Error, Registry, Repository};
use hyper::header::CONTENT_LENGTH;
use hyper::Method;
use std::sync::Arc;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

pub enum GetBlobResponse<R>
where
    R: AsyncRead + Send + Unpin,
{
    Empty,
    Reader(R, u64),
    RangedReader(R, (u64, u64), u64),
}

pub struct HeadBlobResponse {
    pub digest: Digest,
    pub size: u64,
}

impl<D: DataStore + 'static> Registry<D> {
    #[instrument(skip(repository))]
    pub async fn head_blob(
        &self,
        repository: &Repository,
        accepted_mime_types: &[String],
        namespace: &str,
        digest: Digest,
    ) -> Result<HeadBlobResponse, Error> {
        if repository.is_pull_through() {
            let res = repository
                .query_upstream_blob(&Method::HEAD, accepted_mime_types, namespace, &digest)
                .await?;

            let digest = res.parse_header(DOCKER_CONTENT_DIGEST)?;
            let size = res.parse_header(CONTENT_LENGTH)?;
            return Ok(HeadBlobResponse { digest, size });
        }

        let size = self.store.get_blob_size(&digest).await?;

        Ok(HeadBlobResponse { digest, size })
    }

    #[instrument(skip(storage_engine, stream))]
    async fn copy_blob<E, S>(
        storage_engine: Arc<E>,
        stream: S,
        namespace: String,
        digest: Digest,
    ) -> Result<(), Error>
    where
        E: DataStore,
        S: AsyncRead + Send + Sync + Unpin,
    {
        let session_id = Uuid::new_v4().to_string();

        storage_engine
            .create_upload(&namespace, &session_id)
            .await?;

        storage_engine
            .write_upload(&namespace, &session_id, stream, false)
            .await?;

        if let Err(error) = storage_engine
            .complete_upload(&namespace, &session_id, Some(digest))
            .await
        {
            debug!("Failed to complete upload: {error}");
            return Err(error.into());
        }

        Ok::<(), Error>(())
    }

    #[instrument(skip(repository))]
    pub async fn get_blob(
        &self,
        repository: &Repository,
        accepted_mime_types: &[String],
        namespace: &str,
        digest: &Digest,
        range: Option<(u64, u64)>,
    ) -> Result<GetBlobResponse<impl Reader>, Error> {
        if repository.is_pull_through() {
            if range.is_some() {
                warn!("Range requests are not supported for pull-through repositories");
                return Err(Error::RangeNotSatisfiable);
            }

            match self.get_local_blob(digest, range).await {
                Ok(local_blob) => {
                    debug!("Returning blob from local store: {digest}");
                    return Ok(local_blob);
                }
                Err(error) => {
                    debug!("Failed to get blob from local store, pulling from upstream {digest}: {error}");
                }
            }

            let res = repository
                .query_upstream_blob(&Method::GET, accepted_mime_types, namespace, digest)
                .await?;

            let total_length = res.parse_header(CONTENT_LENGTH)?;

            let stream = res.into_async_read();
            let (response_reader, copy_reader) = tee_reader(stream).await?;

            tokio::spawn(Self::copy_blob(
                self.store.clone(),
                copy_reader,
                namespace.to_string(),
                digest.to_owned(),
            ));

            let reader: Box<dyn Reader> = Box::new(response_reader);
            return Ok(GetBlobResponse::Reader(reader, total_length));
        }

        self.get_local_blob(digest, range).await
    }

    async fn get_local_blob(
        &self,
        digest: &Digest,
        range: Option<(u64, u64)>,
    ) -> Result<GetBlobResponse<Box<dyn Reader>>, Error> {
        let total_length = self.store.get_blob_size(digest).await?;

        let start = if let Some((start, _)) = range {
            if start > total_length {
                warn!("Range start does not match content length");
                return Err(Error::RangeNotSatisfiable);
            }
            Some(start)
        } else {
            None
        };

        let reader = match self.store.build_blob_reader(digest, start).await {
            Ok(reader) => reader,
            Err(data_store::Error::BlobNotFound) => return Ok(GetBlobResponse::Empty),
            Err(err) => Err(err)?,
        };

        match range {
            Some((start, end)) => {
                let reader = Box::new(reader.take(end - start + 1));

                Ok(GetBlobResponse::RangedReader(
                    reader,
                    (start, end),
                    total_length,
                ))
            }
            None => Ok(GetBlobResponse::Reader(reader, total_length)),
        }
    }

    #[instrument]
    pub async fn delete_blob(&self, namespace: &str, digest: Digest) -> Result<(), Error> {
        self.validate_namespace(namespace)?;

        let link = BlobLink::Layer(digest.clone());
        if let Err(error) = self.delete_link(namespace, &link).await {
            warn!("Failed to delete layer link: {error}");
        }

        let link = BlobLink::Config(digest);
        if let Err(error) = self.delete_link(namespace, &link).await {
            warn!("Failed to delete config link: {error}");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::test_utils::{
        create_test_blob, create_test_fs_backend, create_test_s3_backend,
    };
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;

    async fn test_head_blob_impl<D: DataStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let content = b"test blob content";

        let (digest, repository) = create_test_blob(registry, namespace, content).await;
        let response = registry
            .head_blob(&repository, &[], namespace, digest.clone())
            .await
            .unwrap();

        assert_eq!(response.digest, digest);
        assert_eq!(response.size, content.len() as u64);
    }

    #[tokio::test]
    async fn test_head_blob_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_head_blob_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_head_blob_s3() {
        let registry = create_test_s3_backend().await;
        test_head_blob_impl(&registry).await;
    }

    async fn test_get_blob_impl<D: DataStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let content = b"test blob content";

        let (digest, repository) = create_test_blob(registry, namespace, content).await;
        let response = registry
            .get_blob(&repository, &[], namespace, &digest, None)
            .await
            .unwrap();

        match response {
            GetBlobResponse::Reader(mut reader, size) => {
                assert_eq!(size, content.len() as u64);
                let mut buf = Vec::new();
                reader.read_to_end(&mut buf).await.unwrap();
                assert_eq!(buf, content);
            }
            _ => panic!("Expected Reader response"),
        }
    }

    #[tokio::test]
    async fn test_get_blob_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_get_blob_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_get_blob_s3() {
        let registry = create_test_s3_backend().await;
        test_get_blob_impl(&registry).await;
    }

    async fn test_get_blob_with_range_impl<D: DataStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let content = b"test blob content";

        let (digest, repository) = create_test_blob(registry, namespace, content).await;
        let range = Some((5, 10)); // Get bytes 5-10 (inclusive)
        let response = registry
            .get_blob(&repository, &[], namespace, &digest, range)
            .await
            .unwrap();

        match response {
            GetBlobResponse::RangedReader(mut reader, (start, end), total_size) => {
                assert_eq!(start, 5);
                assert_eq!(end, 10);
                assert_eq!(total_size, content.len() as u64);

                let mut buf = Vec::new();
                reader.read_to_end(&mut buf).await.unwrap();
                assert_eq!(buf, &content[5..=10]); // Note: using inclusive range
            }
            _ => panic!("Expected RangedReader response"),
        }
    }

    #[tokio::test]
    async fn test_get_blob_with_range_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_get_blob_with_range_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_get_blob_with_range_s3() {
        let registry = create_test_s3_backend().await;
        test_get_blob_with_range_impl(&registry).await;
    }

    async fn test_delete_blob_impl<D: DataStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let content = b"test blob content";

        // Create the blob and ensure the namespace exists
        let (digest, _) = create_test_blob(registry, namespace, content).await;

        // Create test links
        let layer_link = BlobLink::Layer(digest.clone());
        let config_link = BlobLink::Config(digest.clone());
        registry
            .create_link(namespace, &layer_link, &digest)
            .await
            .unwrap();
        registry
            .create_link(namespace, &config_link, &digest)
            .await
            .unwrap();

        // Verify links exist
        assert!(registry.read_link(namespace, &layer_link).await.is_ok());
        assert!(registry.read_link(namespace, &config_link).await.is_ok());

        // Verify blob index is updated
        let blob_index = registry.store.read_blob_index(&digest).await.unwrap();
        assert!(blob_index.namespace.contains_key(namespace));
        let namespace_links = blob_index.namespace.get(namespace).unwrap();
        assert!(namespace_links.contains(&layer_link));
        assert!(namespace_links.contains(&config_link));

        // Delete the blob
        registry
            .delete_blob(namespace, digest.clone())
            .await
            .unwrap();

        // Verify links are deleted
        assert!(registry.read_link(namespace, &layer_link).await.is_err());
        assert!(registry.read_link(namespace, &config_link).await.is_err());
    }

    #[tokio::test]
    async fn test_delete_blob_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_delete_blob_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_delete_blob_s3() {
        let registry = create_test_s3_backend().await;
        test_delete_blob_impl(&registry).await;
    }

    async fn test_copy_blob_impl<D: DataStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let content = b"test blob content";

        let (digest, _) = create_test_blob(registry, namespace, content).await;

        // Create a test stream
        let stream = Cursor::new(content.to_vec());
        let storage_engine = registry.store.clone();

        // Test copy_blob
        Registry::<D>::copy_blob(
            storage_engine,
            stream,
            namespace.to_string(),
            digest.clone(),
        )
        .await
        .unwrap();

        // Verify the blob was copied correctly
        let stored_content = registry.store.read_blob(&digest).await.unwrap();
        assert_eq!(stored_content, content);
    }

    #[tokio::test]
    async fn test_copy_blob_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_copy_blob_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_copy_blob_s3() {
        let registry = create_test_s3_backend().await;
        test_copy_blob_impl(&registry).await;
    }
}
