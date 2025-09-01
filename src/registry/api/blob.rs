use crate::registry::api::body::Body;
use crate::registry::api::hyper::request_ext::RequestExt;
use crate::registry::api::hyper::DOCKER_CONTENT_DIGEST;
use crate::registry::blob::GetBlobResponse;
use crate::registry::blob_store::BlobStore;
use crate::registry::oci_types::Digest;
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry};
use hyper::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tracing::instrument;

#[derive(Debug, Deserialize)]
pub struct QueryBlobParameters {
    pub name: String,
    pub digest: Digest,
}

pub trait RegistryAPIBlobHandlersExt {
    async fn handle_head_blob<T>(
        &self,
        request: Request<T>,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
    async fn handle_delete_blob(
        &self,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
    async fn handle_get_blob<T>(
        &self,
        request: Request<T>,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
}

impl<D: BlobStore + 'static> RegistryAPIBlobHandlersExt for Registry<D> {
    #[instrument(skip(self, request))]
    async fn handle_head_blob<T>(
        &self,
        request: Request<T>,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
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
            .body(Body::empty())?;

        Ok(res)
    }

    #[instrument(skip(self))]
    async fn handle_delete_blob(
        &self,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
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
            .body(Body::empty())?;

        Ok(res)
    }

    #[instrument(skip(self, request))]
    async fn handle_get_blob<T>(
        &self,
        request: Request<T>,
        parameters: QueryBlobParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
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
                    .body(Body::streaming(stream))?
            }
            GetBlobResponse::Reader(stream, total_length) => Response::builder()
                .status(StatusCode::OK)
                .header(DOCKER_CONTENT_DIGEST, parameters.digest.to_string())
                .header(ACCEPT_RANGES, "bytes")
                .header(CONTENT_LENGTH, total_length)
                .body(Body::streaming(stream))?,
            GetBlobResponse::Empty => Response::builder()
                .status(StatusCode::OK)
                .header(ACCEPT_RANGES, "bytes")
                .header(CONTENT_LENGTH, 0)
                .body(Body::empty())?,
        };

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::api::hyper::response_ext::IntoAsyncRead;
    use crate::registry::api::hyper::response_ext::ResponseExt;
    use crate::registry::test_utils::{
        create_test_blob, create_test_fs_backend, create_test_s3_backend,
    };
    use crate::registry::utils::BlobLink;
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::Method;
    use hyper::Uri;

    async fn test_handle_head_blob_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let content = b"test blob content";
        let (digest, _) = create_test_blob(registry, namespace, content).await;

        let uri = Uri::builder()
            .path_and_query(format!("/v2/{namespace}/blobs/{digest}"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::HEAD)
            .uri(uri)
            .body(Empty::<Bytes>::new())
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
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_head_blob_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_head_blob_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_head_blob_impl(&registry).await;
    }

    async fn test_handle_delete_blob_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let content = b"test blob content";
        let (digest, _) = create_test_blob(registry, namespace, content).await;

        // Create test links
        let layer_link = BlobLink::Layer(digest.clone());
        let config_link = BlobLink::Config(digest.clone());
        let latest_link = BlobLink::Tag("latest".to_string());
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
        assert!(registry.read_link(namespace, &latest_link).await.is_ok());

        // Verify blob exists
        assert!(registry.store.read_blob(&digest).await.is_ok());

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
        registry.delete_link(namespace, &latest_link).await.unwrap();

        // Verify links are deleted
        assert!(registry.read_link(namespace, &layer_link).await.is_err());
        assert!(registry.read_link(namespace, &config_link).await.is_err());
        assert!(registry.read_link(namespace, &latest_link).await.is_err());

        // Verify blob index is empty
        let blob_index = registry.store.read_blob_index(&digest).await;
        assert!(blob_index.is_err());

        // Verify blob is deleted (since all links are removed)
        assert!(registry.store.read_blob(&digest).await.is_err());
    }

    #[tokio::test]
    async fn test_handle_delete_blob_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_delete_blob_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_delete_blob_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_delete_blob_impl(&registry).await;
    }

    async fn test_handle_get_blob_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let content = b"test blob content";
        let (digest, _) = create_test_blob(registry, namespace, content).await;

        let uri = Uri::builder()
            .path_and_query(format!("/v2/{namespace}/blobs/{digest}"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Empty::<Bytes>::new())
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
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_get_blob_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_get_blob_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_get_blob_impl(&registry).await;
    }

    async fn test_handle_get_blob_with_range_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let content = b"test blob content";
        let (digest, _) = create_test_blob(registry, namespace, content).await;

        let uri = Uri::builder()
            .path_and_query(format!("/v2/{namespace}/blobs/{digest}"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(RANGE, "bytes=5-10")
            .body(Empty::<Bytes>::new())
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
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_get_blob_with_range_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_get_blob_with_range_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_get_blob_with_range_impl(&registry).await;
    }
}
