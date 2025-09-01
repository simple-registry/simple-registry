use crate::registry::api::body::Body;
use crate::registry::api::hyper::{DOCKER_DISTRIBUTION_API_VERSION, X_POWERED_BY};
use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry};
use hyper::{Response, StatusCode};
use tracing::instrument;

pub trait RegistryAPIVersionHandlerExt {
    async fn handle_get_api_version(
        &self,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error>;
}

impl<B: BlobStore, M: MetadataStore> RegistryAPIVersionHandlerExt for Registry<B, M> {
    #[instrument(skip(self))]
    async fn handle_get_api_version(
        &self,
        identity: ClientIdentity,
    ) -> Result<Response<Body>, Error> {
        Self::validate_request(None, &ClientRequest::get_api_version(), &identity)?;

        let res = Response::builder()
            .status(StatusCode::OK)
            .header(DOCKER_DISTRIBUTION_API_VERSION, "registry/2.0")
            .header(X_POWERED_BY, "Simple-Registry")
            .body(Body::empty())?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::api::hyper::response_ext::ResponseExt;
    use crate::registry::blob_store::BlobStore;
    use crate::registry::metadata_store::MetadataStore;
    use crate::registry::test_utils::{create_test_fs_backend, create_test_s3_backend};
    use crate::registry::Registry;

    async fn test_handle_get_api_version_impl<
        B: BlobStore + 'static,
        M: MetadataStore + 'static,
    >(
        registry: &Registry<B, M>,
    ) {
        let response = registry
            .handle_get_api_version(ClientIdentity::default())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.get_header(DOCKER_DISTRIBUTION_API_VERSION),
            Some("registry/2.0".to_string())
        );
        assert_eq!(
            response.get_header(X_POWERED_BY),
            Some("Simple-Registry".to_string())
        );
    }

    #[tokio::test]
    async fn test_handle_get_api_version_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_handle_get_api_version_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_handle_get_api_version_s3() {
        let registry = create_test_s3_backend().await;
        test_handle_get_api_version_impl(&registry).await;
    }
}
