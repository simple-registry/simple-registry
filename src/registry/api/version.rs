use crate::registry::api::body::Body;
use crate::registry::api::hyper::{DOCKER_DISTRIBUTION_API_VERSION, X_POWERED_BY};
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

impl RegistryAPIVersionHandlerExt for Registry {
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
    use crate::registry::tests::{FSRegistryTestCase, S3RegistryTestCase};
    use crate::registry::Registry;

    async fn test_handle_get_api_version_impl(registry: &Registry) {
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
        let t = FSRegistryTestCase::new();
        test_handle_get_api_version_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_get_api_version_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_get_api_version_impl(t.registry()).await;
    }
}
