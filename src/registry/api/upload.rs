use crate::registry::api::body::Body;
use crate::registry::api::hyper::request_ext::{IntoAsyncRead, RequestExt};
use crate::registry::api::hyper::{DOCKER_CONTENT_DIGEST, DOCKER_UPLOAD_UUID};
use crate::registry::blob_store::BlobStore;
use crate::registry::oci_types::Digest;
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry, StartUploadResponse};
use hyper::header::{CONTENT_LENGTH, CONTENT_RANGE, LOCATION, RANGE};
use hyper::{body, Request, Response, StatusCode};
use serde::Deserialize;
use tracing::instrument;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct QueryNewUploadParameters {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct QueryUploadParameters {
    pub name: String,
    pub uuid: Uuid,
}

pub trait RegistryAPIUploadHandlersExt {
    async fn handle_start_upload<T>(
        &self,
        request: Request<T>,
        parameters: QueryNewUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
    async fn handle_get_upload(
        &self,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
    async fn handle_patch_upload<T>(
        &self,
        request: Request<T>,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>
    where
        T: body::Body + Unpin + Sync + Send,
        T::Data: Send + Sync,
        T::Error: Send + Sync + std::error::Error + 'static;

    async fn handle_put_upload<T>(
        &self,
        request: Request<T>,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>
    where
        T: body::Body + Unpin + Sync + Send,
        T::Data: Send + Sync,
        T::Error: Send + Sync + std::error::Error + 'static;

    async fn handle_delete_upload(
        &self,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
}

impl<D: BlobStore> RegistryAPIUploadHandlersExt for Registry<D> {
    #[instrument(skip(self, request))]
    async fn handle_start_upload<T>(
        &self,
        request: Request<T>,
        parameters: QueryNewUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        #[derive(Deserialize, Default)]
        struct UploadQuery {
            digest: Option<String>,
        }

        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::start_upload(&parameters.name),
            &identity,
        )?;

        let query: UploadQuery = request.query_parameters()?;
        let digest = query
            .digest
            .map(|s| Digest::try_from(s.as_str()))
            .transpose()?;

        let res = match self.start_upload(&parameters.name, digest).await? {
            StartUploadResponse::ExistingBlob(digest) => Response::builder()
                .status(StatusCode::CREATED)
                .header(LOCATION, format!("/v2/{}/blobs/{digest}", parameters.name))
                .header(DOCKER_CONTENT_DIGEST, digest.to_string())
                .body(Body::empty())?,
            StartUploadResponse::Session(location, session_uuid) => Response::builder()
                .status(StatusCode::ACCEPTED)
                .header(LOCATION, location)
                .header(RANGE, "0-0")
                .header(DOCKER_UPLOAD_UUID, session_uuid.to_string())
                .body(Body::empty())?,
        };

        Ok(res)
    }

    #[instrument(skip(self))]
    async fn handle_get_upload(
        &self,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::get_upload(&parameters.name),
            &identity,
        )?;

        let location = format!("/v2/{}/blobs/uploads/{}", parameters.name, parameters.uuid);

        let range_max = self
            .get_upload_range_max(&parameters.name, parameters.uuid)
            .await?;
        let range_max = format!("0-{range_max}");

        let res = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(LOCATION, location)
            .header(RANGE, range_max)
            .header(DOCKER_UPLOAD_UUID, parameters.uuid.to_string())
            .body(Body::empty())?;

        Ok(res)
    }

    #[instrument(skip(self, request))]
    async fn handle_patch_upload<T>(
        &self,
        request: Request<T>,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>
    where
        T: body::Body + Unpin + Sync + Send,
        T::Data: Send + Sync,
        T::Error: Send + Sync + std::error::Error + 'static,
    {
        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::update_upload(&parameters.name),
            &identity,
        )?;

        let start_offset = request.range(CONTENT_RANGE)?.map(|(start, _)| start);

        let location = format!("/v2/{}/blobs/uploads/{}", &parameters.name, parameters.uuid);

        let range_max = self
            .patch_upload(
                &parameters.name,
                parameters.uuid,
                start_offset,
                request.into_async_read(),
            )
            .await?;
        let range_max = format!("0-{range_max}");

        let res = Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(LOCATION, location)
            .header(RANGE, range_max)
            .header(CONTENT_LENGTH, 0)
            .header(DOCKER_UPLOAD_UUID, parameters.uuid.to_string())
            .body(Body::empty())?;

        Ok(res)
    }

    #[instrument(skip(self, request))]
    async fn handle_put_upload<T>(
        &self,
        request: Request<T>,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>
    where
        T: body::Body + Unpin + Sync + Send,
        T::Data: Send + Sync,
        T::Error: Send + Sync + std::error::Error + 'static,
    {
        #[derive(Deserialize, Default)]
        struct CompleteUploadQuery {
            digest: String,
        }

        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::complete_upload(&parameters.name),
            &identity,
        )?;

        let query: CompleteUploadQuery = request.query_parameters()?;
        let digest = Digest::try_from(query.digest.as_str())?;

        self.complete_upload(
            &parameters.name,
            parameters.uuid,
            digest,
            request.into_async_read(),
        )
        .await?;

        let location = format!("/v2/{}/blobs/{}", &parameters.name, query.digest);

        let res = Response::builder()
            .status(StatusCode::CREATED)
            .header(LOCATION, location)
            .header(DOCKER_CONTENT_DIGEST, query.digest)
            .body(Body::empty())?;

        Ok(res)
    }

    #[instrument(skip(self))]
    async fn handle_delete_upload(
        &self,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::cancel_upload(&parameters.name),
            &identity,
        )?;

        self.delete_upload(&parameters.name, parameters.uuid)
            .await?;

        let res = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::api::hyper::response_ext::ResponseExt;
    use crate::registry::test_utils::{create_test_fs_backend, create_test_s3_backend};
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::Method;
    use hyper::Uri;
    use uuid::Uuid;

    async fn test_handle_start_upload_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";

        // Test start upload without digest
        let uri = Uri::builder()
            .path_and_query(format!("/v2/{namespace}/blobs/uploads/"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let parameters = QueryNewUploadParameters {
            name: namespace.to_string(),
        };

        let response = registry
            .handle_start_upload(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let location = response.get_header(LOCATION).unwrap();
        assert!(location.starts_with(&format!("/v2/{namespace}/blobs/uploads/")));
        let uuid = response.get_header(DOCKER_UPLOAD_UUID).unwrap();
        assert!(!uuid.is_empty());
        assert_eq!(response.get_header(RANGE), Some("0-0".to_string()));

        // Test start upload with existing blob
        let content = b"test content";
        let digest = registry.store.create_blob(content).await.unwrap();

        let uri = Uri::builder()
            .path_and_query(format!("/v2/{namespace}/blobs/uploads/?digest={digest}"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let parameters = QueryNewUploadParameters {
            name: namespace.to_string(),
        };

        let response = registry
            .handle_start_upload(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.get_header(LOCATION),
            Some(format!("/v2/{namespace}/blobs/{digest}"))
        );
        assert_eq!(
            response.get_header(DOCKER_CONTENT_DIGEST),
            Some(digest.to_string())
        );
    }

    #[tokio::test]
    async fn test_handle_start_upload_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_start_upload_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_start_upload_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_start_upload_impl(&registry).await;
    }

    async fn test_handle_get_upload_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let uuid = Uuid::new_v4();

        // Create initial upload
        registry
            .store
            .create_upload(namespace, &uuid.to_string())
            .await
            .unwrap();

        let parameters = QueryUploadParameters {
            name: namespace.to_string(),
            uuid,
        };

        let response = registry
            .handle_get_upload(parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response.get_header(LOCATION),
            Some(format!("/v2/{namespace}/blobs/uploads/{uuid}"))
        );
        assert_eq!(response.get_header(RANGE), Some("0-0".to_string()));
        assert_eq!(
            response.get_header(DOCKER_UPLOAD_UUID),
            Some(uuid.to_string())
        );
    }

    #[tokio::test]
    async fn test_handle_get_upload_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_get_upload_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_get_upload_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_get_upload_impl(&registry).await;
    }

    async fn test_handle_patch_upload_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let uuid = Uuid::new_v4();

        // Create initial upload
        registry
            .store
            .create_upload(namespace, &uuid.to_string())
            .await
            .unwrap();

        let uri = Uri::builder()
            .path_and_query(format!("/v2/{namespace}/blobs/uploads/{uuid}"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::PATCH)
            .uri(uri)
            .header(CONTENT_RANGE, "0-0")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let parameters = QueryUploadParameters {
            name: namespace.to_string(),
            uuid,
        };

        let response = registry
            .handle_patch_upload(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            response.get_header(LOCATION),
            Some(format!("/v2/{namespace}/blobs/uploads/{uuid}"))
        );
        assert_eq!(response.get_header(RANGE), Some("0-0".to_string()));
        assert_eq!(response.get_header(CONTENT_LENGTH), Some("0".to_string()));
        assert_eq!(
            response.get_header(DOCKER_UPLOAD_UUID),
            Some(uuid.to_string())
        );
    }

    #[tokio::test]
    async fn test_handle_patch_upload_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_patch_upload_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_patch_upload_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_patch_upload_impl(&registry).await;
    }

    async fn test_handle_put_upload_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let uuid = Uuid::new_v4();
        let content = b"test content";

        // Create initial upload
        registry
            .store
            .create_upload(namespace, &uuid.to_string())
            .await
            .unwrap();

        // Write content first
        let stream = std::io::Cursor::new(content.to_vec());
        registry
            .patch_upload(namespace, uuid, None, stream)
            .await
            .unwrap();

        // Get the upload digest
        let (digest, _, _) = registry
            .store
            .read_upload_summary(namespace, &uuid.to_string())
            .await
            .unwrap();

        let uri = Uri::builder()
            .path_and_query(format!(
                "/v2/{namespace}/blobs/uploads/{uuid}?digest={digest}"
            ))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let parameters = QueryUploadParameters {
            name: namespace.to_string(),
            uuid,
        };

        let response = registry
            .handle_put_upload(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.get_header(LOCATION),
            Some(format!("/v2/{namespace}/blobs/{digest}"))
        );
        assert_eq!(
            response.get_header(DOCKER_CONTENT_DIGEST),
            Some(digest.to_string())
        );

        // Verify blob exists
        let stored_content = registry.store.read_blob(&digest).await.unwrap();
        assert_eq!(stored_content, content);
    }

    #[tokio::test]
    async fn test_handle_put_upload_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_put_upload_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_put_upload_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_put_upload_impl(&registry).await;
    }

    async fn test_handle_delete_upload_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let uuid = Uuid::new_v4();

        // Create initial upload
        registry
            .store
            .create_upload(namespace, &uuid.to_string())
            .await
            .unwrap();

        let parameters = QueryUploadParameters {
            name: namespace.to_string(),
            uuid,
        };

        let response = registry
            .handle_delete_upload(parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Verify upload is deleted
        assert!(registry
            .store
            .read_upload_summary(namespace, &uuid.to_string())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_handle_delete_upload_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_delete_upload_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_delete_upload_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_delete_upload_impl(&registry).await;
    }
}
