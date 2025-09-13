use crate::registry::server::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry, ResponseBody};
use hyper::{Response, StatusCode};
use tracing::instrument;

pub const DOCKER_DISTRIBUTION_API_VERSION: &str = "Docker-Distribution-API-Version";
pub const X_POWERED_BY: &str = "X-Powered-By";

impl Registry {
    // API Handlers
    #[instrument(skip(self, identity))]
    pub async fn handle_get_api_version(
        &self,
        identity: &ClientIdentity,
    ) -> Result<Response<ResponseBody>, Error> {
        self.validate_request(None, &ClientRequest::get_api_version(), identity)?;

        let res = Response::builder()
            .status(StatusCode::OK)
            .header(DOCKER_DISTRIBUTION_API_VERSION, "registry/2.0")
            .header(X_POWERED_BY, "Simple-Registry")
            .body(ResponseBody::empty())?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::server::response_ext::ResponseExt;
    use crate::registry::tests::{FSRegistryTestCase, S3RegistryTestCase};
    use crate::registry::Registry;

    async fn test_handle_get_api_version_impl(registry: &Registry) {
        let identity = ClientIdentity::default();
        let response = registry.handle_get_api_version(&identity).await.unwrap();

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
