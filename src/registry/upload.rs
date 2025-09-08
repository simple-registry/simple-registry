use crate::registry::oci_types::Digest;
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::utils::request_ext::{IntoAsyncRead, RequestExt};
use crate::registry::{Error, Registry, ResponseBody};
use hyper::header::{CONTENT_LENGTH, CONTENT_RANGE, LOCATION, RANGE};
use hyper::{body, Request, Response, StatusCode};
use serde::Deserialize;
use tokio::io::AsyncRead;
use tracing::{error, instrument, warn};
use uuid::Uuid;

pub const DOCKER_UPLOAD_UUID: &str = "Docker-Upload-UUID";
pub const DOCKER_CONTENT_DIGEST: &str = "Docker-Content-Digest";

pub enum StartUploadResponse {
    ExistingBlob(Digest),
    Session(String, String),
}

#[derive(Debug, Deserialize)]
pub struct QueryNewUploadParameters {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct QueryUploadParameters {
    pub name: String,
    pub uuid: Uuid,
}

impl Registry {
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
        S: AsyncRead + Unpin + Send + Sync + 'static,
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
            .write_upload(namespace, &session_id, Box::new(stream), true)
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
        S: AsyncRead + Unpin + Send + Sync + 'static,
    {
        self.validate_namespace(namespace)?;

        let session_id = session_id.to_string();

        let append = self
            .blob_store
            .read_upload_summary(namespace, &session_id)
            .await
            .is_ok();

        self.blob_store
            .write_upload(namespace, &session_id, Box::new(stream), append)
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

    // API Handlers
    #[instrument(skip(self, request))]
    pub async fn handle_start_upload<T>(
        &self,
        request: Request<T>,
        parameters: QueryNewUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<ResponseBody>, Error> {
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
                .body(ResponseBody::empty())?,
            StartUploadResponse::Session(location, session_uuid) => Response::builder()
                .status(StatusCode::ACCEPTED)
                .header(LOCATION, location)
                .header(RANGE, "0-0")
                .header(DOCKER_UPLOAD_UUID, session_uuid.to_string())
                .body(ResponseBody::empty())?,
        };

        Ok(res)
    }

    #[instrument(skip(self))]
    pub async fn handle_get_upload(
        &self,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<ResponseBody>, Error> {
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
            .body(ResponseBody::empty())?;

        Ok(res)
    }

    #[instrument(skip(self, request))]
    pub async fn handle_patch_upload<T>(
        &self,
        request: Request<T>,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<ResponseBody>, Error>
    where
        T: body::Body + Unpin + Sync + Send + 'static,
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
            .body(ResponseBody::empty())?;

        Ok(res)
    }

    #[instrument(skip(self, request))]
    pub async fn handle_put_upload<T>(
        &self,
        request: Request<T>,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<ResponseBody>, Error>
    where
        T: body::Body + Unpin + Sync + Send + 'static,
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
            .body(ResponseBody::empty())?;

        Ok(res)
    }

    #[instrument(skip(self))]
    pub async fn handle_delete_upload(
        &self,
        parameters: QueryUploadParameters,
        identity: ClientIdentity,
    ) -> Result<Response<ResponseBody>, Error> {
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
            .body(ResponseBody::empty())?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::policy_types::ClientIdentity;
    use crate::registry::tests::{FSRegistryTestCase, S3RegistryTestCase};
    use crate::registry::utils::response_ext::ResponseExt;
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::Method;
    use hyper::Uri;
    use std::io::Cursor;
    use uuid::Uuid;

    async fn test_start_upload_impl(registry: &Registry) {
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
        let t = FSRegistryTestCase::new();
        test_start_upload_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_start_upload_s3() {
        let t = S3RegistryTestCase::new();
        test_start_upload_impl(t.registry()).await;
    }

    async fn test_patch_upload_impl(registry: &Registry) {
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
        let t = FSRegistryTestCase::new();
        test_patch_upload_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_patch_upload_s3() {
        let t = S3RegistryTestCase::new();
        test_patch_upload_impl(t.registry()).await;
    }

    async fn test_complete_upload_impl(registry: &Registry) {
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
        let t = FSRegistryTestCase::new();
        test_complete_upload_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_complete_upload_s3() {
        let t = S3RegistryTestCase::new();
        test_complete_upload_impl(t.registry()).await;
    }

    async fn test_delete_upload_impl(registry: &Registry) {
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
        let t = FSRegistryTestCase::new();
        test_delete_upload_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_delete_upload_s3() {
        let t = S3RegistryTestCase::new();
        test_delete_upload_impl(t.registry()).await;
    }

    async fn test_get_upload_range_max_impl(registry: &Registry) {
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
        let t = FSRegistryTestCase::new();
        test_get_upload_range_max_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_get_upload_range_max_s3() {
        let t = S3RegistryTestCase::new();
        test_get_upload_range_max_impl(t.registry()).await;
    }

    // API Handler Tests
    async fn test_handle_start_upload_impl(registry: &Registry) {
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
        let digest = registry.blob_store.create_blob(content).await.unwrap();

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
        let t = FSRegistryTestCase::new();
        test_handle_start_upload_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_start_upload_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_start_upload_impl(t.registry()).await;
    }

    async fn test_handle_get_upload_impl(registry: &Registry) {
        let namespace = "test-repo";
        let uuid = Uuid::new_v4();

        // Create initial upload
        registry
            .blob_store
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
        let t = FSRegistryTestCase::new();
        test_handle_get_upload_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_get_upload_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_get_upload_impl(t.registry()).await;
    }

    async fn test_handle_patch_upload_impl(registry: &Registry) {
        let namespace = "test-repo";
        let uuid = Uuid::new_v4();

        // Create initial upload
        registry
            .blob_store
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
        let t = FSRegistryTestCase::new();
        test_handle_patch_upload_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_patch_upload_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_patch_upload_impl(t.registry()).await;
    }

    async fn test_handle_put_upload_impl(registry: &Registry) {
        let namespace = "test-repo";
        let uuid = Uuid::new_v4();
        let content = b"test content";

        // Create initial upload
        registry
            .blob_store
            .create_upload(namespace, &uuid.to_string())
            .await
            .unwrap();

        // Write content first
        let stream = Cursor::new(content.to_vec());
        registry
            .patch_upload(namespace, uuid, None, stream)
            .await
            .unwrap();

        // Get the upload digest
        let (digest, _, _) = registry
            .blob_store
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
        let stored_content = registry.blob_store.read_blob(&digest).await.unwrap();
        assert_eq!(stored_content, content);
    }

    #[tokio::test]
    async fn test_handle_put_upload_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_put_upload_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_put_upload_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_put_upload_impl(t.registry()).await;
    }

    async fn test_handle_delete_upload_impl(registry: &Registry) {
        let namespace = "test-repo";
        let uuid = Uuid::new_v4();

        // Create initial upload
        registry
            .blob_store
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
            .blob_store
            .read_upload_summary(namespace, &uuid.to_string())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_handle_delete_upload_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_delete_upload_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_delete_upload_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_delete_upload_impl(t.registry()).await;
    }
}
