use crate::registry::api::body::Body;
use crate::registry::api::hyper::request_ext::RequestExt;
use crate::registry::api::hyper::{DOCKER_CONTENT_DIGEST, OCI_SUBJECT};
use crate::registry::blob_store::BlobStore;
use crate::registry::oci_types::Reference;
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry};
use http_body_util::BodyExt;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use hyper::{body, Request, Response, StatusCode};
use serde::Deserialize;
use tracing::instrument;

#[derive(Debug, Deserialize)]
pub struct QueryManifestParameters {
    pub name: String,
    pub reference: Reference,
}

pub trait RegistryAPIManifestHandlersExt {
    async fn handle_head_manifest<T>(
        &self,
        request: Request<T>,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
    async fn handle_get_manifest<T>(
        &self,
        request: Request<T>,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;

    async fn handle_put_manifest<T>(
        &self,
        request: Request<T>,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>
    where
        T: body::Body;

    async fn handle_delete_manifest(
        &self,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
}

impl<D: BlobStore> RegistryAPIManifestHandlersExt for Registry<D> {
    #[instrument(skip(self, request))]
    async fn handle_head_manifest<T>(
        &self,
        request: Request<T>,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::get_manifest(&parameters.name, &parameters.reference),
            &identity,
        )?;

        let manifest = self
            .head_manifest(
                repository,
                &request.accepted_content_types(),
                &parameters.name,
                parameters.reference,
            )
            .await?;

        let res = if let Some(media_type) = manifest.media_type {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, media_type)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .header(CONTENT_LENGTH, manifest.size)
                .body(Body::empty())?
        } else {
            Response::builder()
                .status(StatusCode::OK)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .header(CONTENT_LENGTH, manifest.size)
                .body(Body::empty())?
        };

        Ok(res)
    }

    #[instrument(skip(self, request))]
    async fn handle_get_manifest<T>(
        &self,
        request: Request<T>,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::get_manifest(&parameters.name, &parameters.reference),
            &identity,
        )?;

        let manifest = self
            .get_manifest(
                repository,
                &request.accepted_content_types(),
                &parameters.name,
                parameters.reference,
            )
            .await?;

        let res = if let Some(content_type) = manifest.media_type {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, content_type)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .body(Body::fixed(manifest.content))?
        } else {
            Response::builder()
                .status(StatusCode::OK)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .body(Body::fixed(manifest.content))?
        };

        Ok(res)
    }

    #[instrument(skip(self, request))]
    async fn handle_put_manifest<T>(
        &self,
        request: Request<T>,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>
    where
        T: body::Body,
    {
        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::put_manifest(&parameters.name, &parameters.reference),
            &identity,
        )?;

        let content_type = request
            .get_header(CONTENT_TYPE)
            .ok_or(Error::ManifestInvalid(
                "No Content-Type header provided".to_string(),
            ))?;

        let request_body = request.into_body().collect().await.map_err(|_| {
            Error::ManifestInvalid("Unable to retrieve manifest from client query".to_string())
        })?;
        let body = request_body.to_bytes();

        let location = format!("/v2/{}/manifests/{}", parameters.name, parameters.reference);

        let manifest = self
            .put_manifest(
                &parameters.name,
                parameters.reference,
                Some(&content_type),
                &body,
            )
            .await?;

        let res = match manifest.subject {
            Some(subject) => Response::builder()
                .status(StatusCode::CREATED)
                .header(LOCATION, location)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .header(OCI_SUBJECT, subject.to_string())
                .body(Body::empty())?,
            None => Response::builder()
                .status(StatusCode::CREATED)
                .header(LOCATION, location)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .body(Body::empty())?,
        };

        Ok(res)
    }

    #[instrument(skip(self))]
    async fn handle_delete_manifest(
        &self,
        parameters: QueryManifestParameters,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        let repository = self.validate_namespace(&parameters.name)?;
        Self::validate_request(
            Some(repository),
            &ClientRequest::delete_manifest(&parameters.name, &parameters.reference),
            &identity,
        )?;

        self.delete_manifest(&parameters.name, parameters.reference)
            .await?;

        let res = Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(Body::empty())?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::api::hyper::response_ext::IntoAsyncRead;
    use crate::registry::api::hyper::response_ext::ResponseExt;
    use crate::registry::oci_types::Reference;
    use crate::registry::test_utils::{
        create_test_fs_backend, create_test_manifest, create_test_s3_backend,
    };
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::Method;
    use hyper::Uri;
    use tokio::io::AsyncReadExt;

    async fn test_handle_head_manifest_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let put_response = registry
            .put_manifest(
                namespace,
                Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        let uri = Uri::builder()
            .path_and_query(format!("/v2/{namespace}/manifests/{tag}"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::HEAD)
            .uri(uri)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let parameters = QueryManifestParameters {
            name: namespace.to_string(),
            reference: Reference::Tag(tag.to_string()),
        };

        let response = registry
            .handle_head_manifest(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.get_header(DOCKER_CONTENT_DIGEST),
            Some(put_response.digest.to_string())
        );
        assert_eq!(
            response.get_header(CONTENT_LENGTH),
            Some(content.len().to_string())
        );
        assert_eq!(response.get_header(CONTENT_TYPE), Some(media_type));
    }

    #[tokio::test]
    async fn test_handle_head_manifest_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_head_manifest_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_head_manifest_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_head_manifest_impl(&registry).await;
    }

    async fn test_handle_get_manifest_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let put_response = registry
            .put_manifest(
                namespace,
                Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        let uri = Uri::builder()
            .path_and_query(format!("/v2/{namespace}/manifests/{tag}"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let parameters = QueryManifestParameters {
            name: namespace.to_string(),
            reference: Reference::Tag(tag.to_string()),
        };

        let response = registry
            .handle_get_manifest(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.get_header(DOCKER_CONTENT_DIGEST),
            Some(put_response.digest.to_string())
        );
        assert_eq!(response.get_header(CONTENT_TYPE), Some(media_type));

        // Read response body
        let mut reader = response.into_async_read();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, content);
    }

    #[tokio::test]
    async fn test_handle_get_manifest_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_get_manifest_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_get_manifest_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_get_manifest_impl(&registry).await;
    }

    async fn test_handle_put_manifest_impl<D: BlobStore + 'static>(
        registry: &Registry<D>,
    ) -> Result<(), Error> {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        let uri = Uri::builder()
            .path_and_query(format!("/v2/{namespace}/manifests/{tag}"))
            .build()
            .unwrap();

        let request = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header(CONTENT_TYPE, &media_type)
            .body(Body::fixed(content.clone()))?;

        let parameters = QueryManifestParameters {
            name: namespace.to_string(),
            reference: Reference::Tag(tag.to_string()),
        };

        let response = registry
            .handle_put_manifest(request, parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let digest = response.get_header(DOCKER_CONTENT_DIGEST).unwrap();
        assert_eq!(
            response.get_header(LOCATION),
            Some(format!("/v2/{namespace}/manifests/{tag}"))
        );

        // Verify manifest was stored
        let stored_manifest = registry
            .get_manifest(
                registry.validate_namespace(namespace).unwrap(),
                &[media_type.clone()],
                namespace,
                Reference::Tag(tag.to_string()),
            )
            .await
            .unwrap();

        assert_eq!(stored_manifest.content, content);
        assert_eq!(stored_manifest.media_type.unwrap(), media_type);
        assert_eq!(stored_manifest.digest.to_string(), digest);

        Ok(())
    }

    #[tokio::test]
    async fn test_handle_put_manifest_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_put_manifest_impl(&registry).await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_put_manifest_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_put_manifest_impl(&registry).await.unwrap();
    }

    async fn test_handle_delete_manifest_impl<D: BlobStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let _put_response = registry
            .put_manifest(
                namespace,
                Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        let parameters = QueryManifestParameters {
            name: namespace.to_string(),
            reference: Reference::Tag(tag.to_string()),
        };

        let response = registry
            .handle_delete_manifest(parameters, ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        // Verify manifest is deleted
        assert!(registry
            .get_manifest(
                registry.validate_namespace(namespace).unwrap(),
                &[media_type.clone()],
                namespace,
                Reference::Tag(tag.to_string()),
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_handle_delete_manifest_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_delete_manifest_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_delete_manifest_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_delete_manifest_impl(&registry).await;
    }
}
