use crate::registry::blob_store::{BlobStore, Reader};
use crate::registry::oci_types::Digest;
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::utils::request_ext::RequestExt;
use crate::registry::utils::response_ext::{IntoAsyncRead, ResponseExt};
use crate::registry::utils::BlobLink;
use crate::registry::{blob_store, task_queue, Error, Registry, Repository, ResponseBody};
use hyper::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use hyper::{Method, Request, Response, StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

pub const DOCKER_CONTENT_DIGEST: &str = "Docker-Content-Digest";

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

#[derive(Debug, Deserialize)]
pub struct QueryBlobParameters {
    pub name: String,
    pub digest: Digest,
}

impl Registry {
    #[instrument(skip(repository))]
    pub async fn head_blob(
        &self,
        repository: &Repository,
        accepted_mime_types: &[String],
        namespace: &str,
        digest: Digest,
    ) -> Result<HeadBlobResponse, Error> {
        let local_blob = self.blob_store.get_blob_size(&digest).await;

        if let Ok(size) = local_blob {
            return Ok(HeadBlobResponse { digest, size });
        } else if !repository.is_pull_through() {
            warn!("Blob not found locally: {}", digest);
            return Err(Error::BlobUnknown);
        }

        let res = repository
            .query_upstream_blob(
                &*self.auth_token_cache,
                &Method::HEAD,
                accepted_mime_types,
                namespace,
                &digest,
            )
            .await?;

        let digest = res.parse_header(DOCKER_CONTENT_DIGEST)?;
        let size = res.parse_header(CONTENT_LENGTH)?;
        Ok(HeadBlobResponse { digest, size })
    }

    #[instrument(skip(storage_engine, stream))]
    async fn copy_blob(
        storage_engine: Arc<dyn BlobStore + Send + Sync>,
        stream: impl AsyncRead + Send + Sync + Unpin + 'static,
        namespace: String,
        digest: Digest,
    ) -> Result<(), Error> {
        let session_id = Uuid::new_v4().to_string();

        storage_engine
            .create_upload(&namespace, &session_id)
            .await?;

        storage_engine
            .write_upload(&namespace, &session_id, Box::new(stream), false)
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
        range: Option<(u64, Option<u64>)>,
    ) -> Result<GetBlobResponse<impl Reader>, Error> {
        let local_blob = self.get_local_blob(digest, range).await;

        if let Ok(response) = local_blob {
            return Ok(response);
        } else if !repository.is_pull_through() {
            warn!("Blob not found locally: {}", digest);
            return Err(Error::BlobUnknown);
        }

        if range.is_some() {
            warn!("Range requests are not supported for pull-through repositories");
            return Err(Error::RangeNotSatisfiable);
        }

        // Proxying stream
        let client_stream = repository
            .query_upstream_blob(
                &*self.auth_token_cache,
                &Method::GET,
                accepted_mime_types,
                namespace,
                digest,
            )
            .await?;
        let total_length = client_stream.parse_header(CONTENT_LENGTH)?;
        let client_stream = client_stream.into_async_read();
        let client_stream: Box<dyn Reader> = Box::new(client_stream);

        // Caching stream
        let store = self.blob_store.clone();
        let cache_reader = repository
            .query_upstream_blob(
                &*self.auth_token_cache,
                &Method::GET,
                accepted_mime_types,
                namespace,
                digest,
            )
            .await?
            .into_async_read();
        let cache_namespace = namespace.to_string();
        let cache_digest = digest.clone();

        let task_key = format!("{cache_namespace}/{cache_digest}");
        self.task_queue.submit(&task_key, async {
            let digest_string = cache_digest.to_string();
            debug!("Fetching blob: {digest_string}");
            Self::copy_blob(store, cache_reader, cache_namespace, cache_digest)
                .await
                .map_err(|e| task_queue::Error::TaskExecution(e.to_string()))?;

            info!("Caching of {digest_string} completed");
            Ok(())
        })?;
        info!("Scheduled blob copy task '{task_key}'");
        //

        Ok(GetBlobResponse::Reader(client_stream, total_length))
    }

    async fn get_local_blob(
        &self,
        digest: &Digest,
        range: Option<(u64, Option<u64>)>,
    ) -> Result<GetBlobResponse<Box<dyn Reader>>, Error> {
        let total_length = self.blob_store.get_blob_size(digest).await?;

        let start = if let Some((start, _)) = range {
            if start > total_length {
                warn!("Range start does not match content length");
                return Err(Error::RangeNotSatisfiable);
            }
            Some(start)
        } else {
            None
        };

        let reader = match self.blob_store.build_blob_reader(digest, start).await {
            Ok(reader) => reader,
            Err(blob_store::Error::BlobNotFound) => return Ok(GetBlobResponse::Empty),
            Err(err) => Err(err)?,
        };

        match range {
            Some((0, None)) | None => Ok(GetBlobResponse::Reader(reader, total_length)),
            Some((start, end)) => {
                let end = end.unwrap_or(total_length - 1);
                let reader = Box::new(reader.take(end - start + 1));

                Ok(GetBlobResponse::RangedReader(
                    reader,
                    (start, end),
                    total_length,
                ))
            }
        }
    }

    #[instrument]
    pub async fn delete_blob(&self, namespace: &str, digest: Digest) -> Result<(), Error> {
        self.validate_namespace(namespace)?;

        let link = BlobLink::Layer(digest.clone());
        if let Err(error) = self.metadata_store.delete_link(namespace, &link).await {
            warn!("Failed to delete layer link: {error}");
        }

        let link = BlobLink::Config(digest);
        if let Err(error) = self.metadata_store.delete_link(namespace, &link).await {
            warn!("Failed to delete config link: {error}");
        }

        Ok(())
    }

    // API Handlers

    #[instrument(skip(self, request))]
    pub async fn handle_head_blob<T>(
        &self,
        request: Request<T>,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<ResponseBody>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::get_blob(&parameters.name, &parameters.digest),
            &identity,
        )?;

        let blob = self
            .head_blob(
                repository,
                &request.accepted_content_types(),
                &parameters.name,
                parameters.digest,
            )
            .await?;

        let res = Response::builder()
            .status(StatusCode::OK)
            .header(DOCKER_CONTENT_DIGEST, blob.digest.to_string())
            .header(CONTENT_LENGTH, blob.size.to_string())
            .body(ResponseBody::empty())?;

        Ok(res)
    }

    #[instrument(skip(self))]
    pub async fn handle_delete_blob(
        &self,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<ResponseBody>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::delete_blob(&parameters.name, &parameters.digest),
            &identity,
        )?;

        self.delete_blob(&parameters.name, parameters.digest)
            .await?;

        let res = Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(ResponseBody::empty())?;

        Ok(res)
    }

    #[instrument(skip(self, request))]
    pub async fn handle_get_blob<T>(
        &self,
        request: Request<T>,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<ResponseBody>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::get_blob(&parameters.name, &parameters.digest),
            &identity,
        )?;

        let res = match self
            .get_blob(
                repository,
                &request.accepted_content_types(),
                &parameters.name,
                &parameters.digest,
                request.range(RANGE)?,
            )
            .await?
        {
            GetBlobResponse::RangedReader(reader, (start, end), total_length) => {
                let length = end - start + 1;
                let stream = reader.take(length);
                let range = format!("bytes {start}-{end}/{total_length}");

                Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(DOCKER_CONTENT_DIGEST, parameters.digest.to_string())
                    .header(ACCEPT_RANGES, "bytes")
                    .header(CONTENT_LENGTH, length.to_string())
                    .header(CONTENT_RANGE, range)
                    .body(ResponseBody::streaming(stream))?
            }
            GetBlobResponse::Reader(stream, total_length) => Response::builder()
                .status(StatusCode::OK)
                .header(DOCKER_CONTENT_DIGEST, parameters.digest.to_string())
                .header(ACCEPT_RANGES, "bytes")
                .header(CONTENT_LENGTH, total_length)
                .body(ResponseBody::streaming(stream))?,
            GetBlobResponse::Empty => Response::builder()
                .status(StatusCode::OK)
                .header(ACCEPT_RANGES, "bytes")
                .header(CONTENT_LENGTH, 0)
                .body(ResponseBody::empty())?,
        };

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::test_utils::create_test_blob;
    use crate::registry::tests::{FSRegistryTestCase, S3RegistryTestCase};
    use crate::registry::utils::response_ext::{IntoAsyncRead, ResponseExt};
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;

    async fn test_head_blob_impl(registry: &Registry) {
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
        let t = FSRegistryTestCase::new();
        test_head_blob_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_head_blob_s3() {
        let t = S3RegistryTestCase::new();
        test_head_blob_impl(t.registry()).await;
    }

    async fn test_get_blob_impl(registry: &Registry) {
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
        let t = FSRegistryTestCase::new();
        test_get_blob_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_get_blob_s3() {
        let t = S3RegistryTestCase::new();
        test_get_blob_impl(t.registry()).await;
    }

    async fn test_get_blob_with_range_impl(registry: &Registry) {
        let namespace = "test-repo";
        let content = b"test blob content";

        let (digest, repository) = create_test_blob(registry, namespace, content).await;
        let range = Some((5, Some(10))); // Get bytes 5-10 (inclusive)
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
        let t = FSRegistryTestCase::new();
        test_get_blob_with_range_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_get_blob_with_range_s3() {
        let t = S3RegistryTestCase::new();
        test_get_blob_with_range_impl(t.registry()).await;
    }

    async fn test_delete_blob_impl(registry: &Registry) {
        let namespace = "test-repo";
        let content = b"test blob content";

        // Create the blob and ensure the namespace exists
        let (digest, _) = create_test_blob(registry, namespace, content).await;

        // Create test links
        let layer_link = BlobLink::Layer(digest.clone());
        let config_link = BlobLink::Config(digest.clone());
        registry
            .metadata_store
            .create_link(namespace, &layer_link, &digest)
            .await
            .unwrap();
        registry
            .metadata_store
            .create_link(namespace, &config_link, &digest)
            .await
            .unwrap();

        // Verify links exist
        assert!(registry
            .metadata_store
            .read_link(namespace, &layer_link, false)
            .await
            .is_ok());
        assert!(registry
            .metadata_store
            .read_link(namespace, &config_link, false)
            .await
            .is_ok());

        // Verify blob index is updated
        let blob_index = registry
            .metadata_store
            .read_blob_index(&digest)
            .await
            .unwrap();
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
        assert!(registry
            .metadata_store
            .read_link(namespace, &layer_link, false)
            .await
            .is_err());
        assert!(registry
            .metadata_store
            .read_link(namespace, &config_link, false)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_delete_blob_fs() {
        let t = FSRegistryTestCase::new();
        test_delete_blob_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_delete_blob_s3() {
        let t = S3RegistryTestCase::new();
        test_delete_blob_impl(t.registry()).await;
    }

    async fn test_copy_blob_impl(registry: &Registry) {
        let namespace = "test-repo";
        let content = b"test blob content";

        let (digest, _) = create_test_blob(registry, namespace, content).await;

        // Create a test stream
        let stream = Cursor::new(content.to_vec());
        let storage_engine = registry.blob_store.clone();

        // Test copy_blob
        Registry::copy_blob(
            storage_engine,
            stream,
            namespace.to_string(),
            digest.clone(),
        )
        .await
        .unwrap();

        // Verify the blob was copied correctly
        let stored_content = registry.blob_store.read_blob(&digest).await.unwrap();
        assert_eq!(stored_content, content);
    }

    #[tokio::test]
    async fn test_copy_blob_fs() {
        let t = FSRegistryTestCase::new();
        test_copy_blob_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_copy_blob_s3() {
        let t = S3RegistryTestCase::new();
        test_copy_blob_impl(t.registry()).await;
    }

    // Handler tests
    async fn test_handle_head_blob_impl(registry: &Registry) {
        let namespace = "test-repo";
        let content = b"test blob content";
        let (digest, _) = create_test_blob(registry, namespace, content).await;

        let uri = hyper::Uri::builder()
            .path_and_query(format!("/v2/{namespace}/blobs/{digest}"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::HEAD)
            .uri(uri)
            .body(ResponseBody::empty())
            .unwrap();

        let parameters = QueryBlobParameters {
            name: namespace.to_string(),
            digest: digest.clone(),
        };

        let response = registry
            .handle_head_blob(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.get_header(DOCKER_CONTENT_DIGEST),
            Some(digest.to_string())
        );
        assert_eq!(
            response.get_header(CONTENT_LENGTH),
            Some(content.len().to_string())
        );
    }

    #[tokio::test]
    async fn test_handle_head_blob_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_head_blob_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_head_blob_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_head_blob_impl(t.registry()).await;
    }

    async fn test_handle_delete_blob_impl(registry: &Registry) {
        let namespace = "test-repo";
        let content = b"test blob content";
        let (digest, _) = create_test_blob(registry, namespace, content).await;

        // Create test links
        let layer_link = BlobLink::Layer(digest.clone());
        let config_link = BlobLink::Config(digest.clone());
        let latest_link = BlobLink::Tag("latest".to_string());
        registry
            .metadata_store
            .create_link(namespace, &layer_link, &digest)
            .await
            .unwrap();
        registry
            .metadata_store
            .create_link(namespace, &config_link, &digest)
            .await
            .unwrap();

        // Verify links exist
        assert!(registry
            .metadata_store
            .read_link(namespace, &layer_link, false)
            .await
            .is_ok());
        assert!(registry
            .metadata_store
            .read_link(namespace, &config_link, false)
            .await
            .is_ok());
        assert!(registry
            .metadata_store
            .read_link(namespace, &latest_link, false)
            .await
            .is_ok());

        // Verify blob exists
        assert!(registry.blob_store.read_blob(&digest).await.is_ok());

        let parameters = QueryBlobParameters {
            name: namespace.to_string(),
            digest: digest.clone(),
        };

        let response = registry
            .handle_delete_blob(parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        // Delete the latest tag link
        registry
            .metadata_store
            .delete_link(namespace, &latest_link)
            .await
            .unwrap();

        // Verify links are deleted
        assert!(registry
            .metadata_store
            .read_link(namespace, &layer_link, false)
            .await
            .is_err());
        assert!(registry
            .metadata_store
            .read_link(namespace, &config_link, false)
            .await
            .is_err());
        assert!(registry
            .metadata_store
            .read_link(namespace, &latest_link, false)
            .await
            .is_err());

        // Verify blob index is empty
        let blob_index = registry.metadata_store.read_blob_index(&digest).await;
        assert!(blob_index.is_err());

        // Verify blob is deleted (since all links are removed)
        assert!(registry.blob_store.read_blob(&digest).await.is_err());
    }

    #[tokio::test]
    async fn test_handle_delete_blob_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_delete_blob_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_delete_blob_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_delete_blob_impl(t.registry()).await;
    }

    async fn test_handle_get_blob_impl(registry: &Registry) {
        let namespace = "test-repo";
        let content = b"test blob content";
        let (digest, _) = create_test_blob(registry, namespace, content).await;

        let uri = hyper::Uri::builder()
            .path_and_query(format!("/v2/{namespace}/blobs/{digest}"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(ResponseBody::empty())
            .unwrap();

        let parameters = QueryBlobParameters {
            name: namespace.to_string(),
            digest: digest.clone(),
        };

        let response = registry
            .handle_get_blob(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.get_header(DOCKER_CONTENT_DIGEST),
            Some(digest.to_string())
        );
        assert_eq!(
            response.get_header(CONTENT_LENGTH),
            Some(content.len().to_string())
        );

        // Read response body
        let mut reader = response.into_async_read();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, content);
    }

    #[tokio::test]
    async fn test_handle_get_blob_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_get_blob_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_get_blob_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_get_blob_impl(t.registry()).await;
    }

    async fn test_handle_get_blob_with_range_impl(registry: &Registry) {
        let namespace = "test-repo";
        let content = b"test blob content";
        let (digest, _) = create_test_blob(registry, namespace, content).await;

        let uri = hyper::Uri::builder()
            .path_and_query(format!("/v2/{namespace}/blobs/{digest}"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(RANGE, "bytes=5-10")
            .body(ResponseBody::empty())
            .unwrap();

        let parameters = QueryBlobParameters {
            name: namespace.to_string(),
            digest: digest.clone(),
        };

        let response = registry
            .handle_get_blob(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response.get_header(DOCKER_CONTENT_DIGEST),
            Some(digest.to_string())
        );
        assert_eq!(
            response.get_header(CONTENT_LENGTH),
            Some("6".to_string()) // 10 - 5 + 1
        );
        assert_eq!(
            response.get_header(CONTENT_RANGE),
            Some(format!("bytes 5-10/{}", content.len()))
        );

        // Read response body
        let mut reader = response.into_async_read();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, &content[5..=10]);
    }

    #[tokio::test]
    async fn test_handle_get_blob_with_range_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_get_blob_with_range_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_get_blob_with_range_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_get_blob_with_range_impl(t.registry()).await;
    }
}
