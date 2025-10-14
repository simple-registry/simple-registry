use crate::command::server::response_body::ResponseBody;
use crate::oci::Digest;
use crate::registry::{Error, Registry};
use hyper::header::{CONTENT_LENGTH, LOCATION, RANGE};
use hyper::{Response, StatusCode};
use tokio::io::AsyncRead;
use tracing::{error, instrument, warn};
use uuid::Uuid;

pub const DOCKER_UPLOAD_UUID: &str = "Docker-Upload-UUID";
pub const DOCKER_CONTENT_DIGEST: &str = "Docker-Content-Digest";

pub enum StartUploadResponse {
    ExistingBlob(Digest),
    Session(String, String),
}

impl Registry {
    #[instrument]
    pub async fn start_upload(
        &self,
        namespace: &str,
        digest: Option<Digest>,
    ) -> Result<StartUploadResponse, Error> {
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
        digest: &Digest,
        stream: S,
    ) -> Result<(), Error>
    where
        S: AsyncRead + Unpin + Send + Sync + 'static,
    {
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

        if &upload_digest != digest {
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
    #[instrument(skip(self))]
    pub async fn handle_start_upload(
        &self,
        namespace: &str,
        digest: Option<Digest>,
    ) -> Result<Response<ResponseBody>, Error> {
        let res = match self.start_upload(namespace, digest).await? {
            StartUploadResponse::ExistingBlob(digest) => Response::builder()
                .status(StatusCode::CREATED)
                .header(LOCATION, format!("/v2/{namespace}/blobs/{digest}"))
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
        namespace: &str,
        uuid: Uuid,
    ) -> Result<Response<ResponseBody>, Error> {
        let range_max = self.get_upload_range_max(namespace, uuid).await?;

        let res = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(LOCATION, format!("/v2/{namespace}/blobs/uploads/{uuid}"))
            .header(RANGE, format!("0-{range_max}"))
            .header(DOCKER_UPLOAD_UUID, uuid.to_string())
            .body(ResponseBody::empty())?;

        Ok(res)
    }

    #[instrument(skip(self, body_stream))]
    pub async fn handle_patch_upload<S>(
        &self,
        namespace: &str,
        uuid: Uuid,
        start_offset: Option<u64>,
        body_stream: S,
    ) -> Result<Response<ResponseBody>, Error>
    where
        S: AsyncRead + Unpin + Send + Sync + 'static,
    {
        let range_max = self
            .patch_upload(namespace, uuid, start_offset, body_stream)
            .await?;

        let res = Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(LOCATION, format!("/v2/{namespace}/blobs/uploads/{uuid}"))
            .header(RANGE, format!("0-{range_max}"))
            .header(CONTENT_LENGTH, 0)
            .header(DOCKER_UPLOAD_UUID, uuid.to_string())
            .body(ResponseBody::empty())?;

        Ok(res)
    }

    #[instrument(skip(self, body_reader))]
    pub async fn handle_put_upload<S>(
        &self,
        namespace: &str,
        uuid: Uuid,
        digest: &Digest,
        body_reader: S,
    ) -> Result<Response<ResponseBody>, Error>
    where
        S: AsyncRead + Unpin + Send + Sync + 'static,
    {
        self.complete_upload(namespace, uuid, digest, body_reader)
            .await?;

        let res = Response::builder()
            .status(StatusCode::CREATED)
            .header(LOCATION, format!("/v2/{namespace}/blobs/{digest}"))
            .header(DOCKER_CONTENT_DIGEST, digest.to_string())
            .body(ResponseBody::empty())?;

        Ok(res)
    }

    #[instrument(skip(self))]
    pub async fn handle_delete_upload(
        &self,
        namespace: &str,
        uuid: Uuid,
    ) -> Result<Response<ResponseBody>, Error> {
        self.delete_upload(namespace, uuid).await?;

        let res = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(ResponseBody::empty())?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::backends;
    use std::io::Cursor;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_start_upload() {
        for test_case in backends() {
            let registry = test_case.registry();
            let namespace = "test-repo";
            let content = b"test upload content";

            let response = registry.start_upload(namespace, None).await.unwrap();
            match response {
                StartUploadResponse::Session(location, session_id) => {
                    assert!(location.starts_with(&format!("/v2/{namespace}/blobs/uploads/")));
                    assert!(!session_id.is_empty());
                }
                StartUploadResponse::ExistingBlob(_) => panic!("Expected Session response"),
            }

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
    }

    #[tokio::test]
    async fn test_patch_upload() {
        for test_case in backends() {
            let registry = test_case.registry();
            let namespace = "test-repo";
            let content = b"test patch content";
            let session_id = Uuid::new_v4();

            registry
                .blob_store
                .create_upload(namespace, &session_id.to_string())
                .await
                .unwrap();

            let stream = Cursor::new(content);
            let bytes_written = registry
                .patch_upload(namespace, session_id, None, stream)
                .await
                .unwrap();
            assert_eq!(bytes_written, (content.len() - 1) as u64);

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

            let (_, size, _) = registry
                .blob_store
                .read_upload_summary(namespace, &session_id.to_string())
                .await
                .unwrap();
            assert_eq!(size, (content.len() + additional_content.len()) as u64);
        }
    }

    #[tokio::test]
    async fn test_complete_upload() {
        for test_case in backends() {
            let registry = test_case.registry();
            let namespace = "test-repo";
            let content = b"test complete content";
            let session_id = Uuid::new_v4();

            registry
                .blob_store
                .create_upload(namespace, &session_id.to_string())
                .await
                .unwrap();

            let stream = Cursor::new(content);
            registry
                .patch_upload(namespace, session_id, None, stream)
                .await
                .unwrap();

            let (upload_digest, _, _) = registry
                .blob_store
                .read_upload_summary(namespace, &session_id.to_string())
                .await
                .unwrap();

            let empty_stream = Cursor::new(Vec::new());
            registry
                .complete_upload(namespace, session_id, &upload_digest, empty_stream)
                .await
                .unwrap();

            let stored_content = registry.blob_store.read_blob(&upload_digest).await.unwrap();
            assert_eq!(stored_content, content);
        }
    }

    #[tokio::test]
    async fn test_delete_upload() {
        for test_case in backends() {
            let registry = test_case.registry();
            let namespace = "test-repo";
            let session_id = Uuid::new_v4();

            registry
                .blob_store
                .create_upload(namespace, &session_id.to_string())
                .await
                .unwrap();

            assert!(registry
                .blob_store
                .read_upload_summary(namespace, &session_id.to_string())
                .await
                .is_ok());

            registry.delete_upload(namespace, session_id).await.unwrap();

            assert!(registry
                .blob_store
                .read_upload_summary(namespace, &session_id.to_string())
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn test_get_upload_range_max() {
        for test_case in backends() {
            let registry = test_case.registry();
            let namespace = "test-repo";
            let content = b"test range content";
            let session_id = Uuid::new_v4();

            registry
                .blob_store
                .create_upload(namespace, &session_id.to_string())
                .await
                .unwrap();

            let range_max = registry
                .get_upload_range_max(namespace, session_id)
                .await
                .unwrap();
            assert_eq!(range_max, 0);

            let stream = Cursor::new(content);
            registry
                .patch_upload(namespace, session_id, None, stream)
                .await
                .unwrap();

            let range_max = registry
                .get_upload_range_max(namespace, session_id)
                .await
                .unwrap();
            assert_eq!(range_max, (content.len() - 1) as u64);
        }
    }
    #[tokio::test]
    async fn test_handle_start_upload() {
        for test_case in backends() {
            let registry = test_case.registry();
            let namespace = "test-repo";

            let response = registry.handle_start_upload(namespace, None).await.unwrap();

            assert_eq!(response.status(), StatusCode::ACCEPTED);
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|h| h.to_str().ok())
                .map(std::string::ToString::to_string)
                .unwrap();
            assert!(location.starts_with(&format!("/v2/{namespace}/blobs/uploads/")));
            let uuid = response
                .headers()
                .get(DOCKER_UPLOAD_UUID)
                .and_then(|h| h.to_str().ok())
                .map(std::string::ToString::to_string)
                .unwrap();
            assert!(!uuid.is_empty());
            assert_eq!(
                response
                    .headers()
                    .get(RANGE)
                    .and_then(|h| h.to_str().ok())
                    .map(std::string::ToString::to_string),
                Some("0-0".to_string())
            );

            let content = b"test content";
            let digest = registry.blob_store.create_blob(content).await.unwrap();

            let response = registry
                .handle_start_upload(namespace, Some(digest.clone()))
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::CREATED);
            assert_eq!(
                response
                    .headers()
                    .get(LOCATION)
                    .and_then(|h| h.to_str().ok())
                    .map(std::string::ToString::to_string),
                Some(format!("/v2/{namespace}/blobs/{digest}"))
            );
            assert_eq!(
                response
                    .headers()
                    .get(DOCKER_CONTENT_DIGEST)
                    .and_then(|h| h.to_str().ok())
                    .map(std::string::ToString::to_string),
                Some(digest.to_string())
            );
        }
    }

    #[tokio::test]
    async fn test_handle_get_upload() {
        for test_case in backends() {
            let registry = test_case.registry();
            let namespace = "test-repo";
            let uuid = Uuid::new_v4();

            registry
                .blob_store
                .create_upload(namespace, &uuid.to_string())
                .await
                .unwrap();

            let response = registry.handle_get_upload(namespace, uuid).await.unwrap();

            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(
                response
                    .headers()
                    .get(LOCATION)
                    .and_then(|h| h.to_str().ok())
                    .map(std::string::ToString::to_string),
                Some(format!("/v2/{namespace}/blobs/uploads/{uuid}"))
            );
            assert_eq!(
                response
                    .headers()
                    .get(RANGE)
                    .and_then(|h| h.to_str().ok())
                    .map(std::string::ToString::to_string),
                Some("0-0".to_string())
            );
            assert_eq!(
                response
                    .headers()
                    .get(DOCKER_UPLOAD_UUID)
                    .and_then(|h| h.to_str().ok())
                    .map(std::string::ToString::to_string),
                Some(uuid.to_string())
            );
        }
    }

    #[tokio::test]
    async fn test_handle_patch_upload() {
        for test_case in backends() {
            let registry = test_case.registry();
            let namespace = "test-repo";
            let uuid = Uuid::new_v4();

            registry
                .blob_store
                .create_upload(namespace, &uuid.to_string())
                .await
                .unwrap();

            let response = registry
                .handle_patch_upload(namespace, uuid, Some(0), Cursor::new(Vec::new()))
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::ACCEPTED);
            assert_eq!(
                response
                    .headers()
                    .get(LOCATION)
                    .and_then(|h| h.to_str().ok())
                    .map(std::string::ToString::to_string),
                Some(format!("/v2/{namespace}/blobs/uploads/{uuid}"))
            );
            assert_eq!(
                response
                    .headers()
                    .get(RANGE)
                    .and_then(|h| h.to_str().ok())
                    .map(std::string::ToString::to_string),
                Some("0-0".to_string())
            );
            assert_eq!(
                response
                    .headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|h| h.to_str().ok())
                    .map(std::string::ToString::to_string),
                Some("0".to_string())
            );
            assert_eq!(
                response
                    .headers()
                    .get(DOCKER_UPLOAD_UUID)
                    .and_then(|h| h.to_str().ok())
                    .map(std::string::ToString::to_string),
                Some(uuid.to_string())
            );
        }
    }

    #[tokio::test]
    async fn test_handle_put_upload() {
        for test_case in backends() {
            let registry = test_case.registry();
            let namespace = "test-repo";
            let uuid = Uuid::new_v4();
            let content = b"test content";

            registry
                .blob_store
                .create_upload(namespace, &uuid.to_string())
                .await
                .unwrap();

            let stream = Cursor::new(content.to_vec());
            registry
                .patch_upload(namespace, uuid, None, stream)
                .await
                .unwrap();

            let (digest, _, _) = registry
                .blob_store
                .read_upload_summary(namespace, &uuid.to_string())
                .await
                .unwrap();

            let body_stream = Cursor::new(Vec::new());

            let response = registry
                .handle_put_upload(namespace, uuid, &digest, body_stream)
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::CREATED);

            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|h| h.to_str().ok())
                .map(std::string::ToString::to_string);
            assert_eq!(location, Some(format!("/v2/{namespace}/blobs/{digest}")));

            let response_digest = response
                .headers()
                .get(DOCKER_CONTENT_DIGEST)
                .and_then(|h| h.to_str().ok())
                .map(std::string::ToString::to_string);
            assert_eq!(response_digest, Some(digest.to_string()));

            let stored_content = registry.blob_store.read_blob(&digest).await.unwrap();
            assert_eq!(stored_content, content);
        }
    }

    #[tokio::test]
    async fn test_handle_delete_upload() {
        for test_case in backends() {
            let registry = test_case.registry();
            let namespace = "test-repo";
            let uuid = Uuid::new_v4();

            registry
                .blob_store
                .create_upload(namespace, &uuid.to_string())
                .await
                .unwrap();

            let response = registry
                .handle_delete_upload(namespace, uuid)
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            assert!(registry
                .blob_store
                .read_upload_summary(namespace, &uuid.to_string())
                .await
                .is_err());
        }
    }
}
