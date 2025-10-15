use crate::command::server::response_body::ResponseBody;
use crate::registry::{Error, Registry};
use hyper::{Response, StatusCode};
use tracing::instrument;

pub const DOCKER_DISTRIBUTION_API_VERSION: &str = "Docker-Distribution-API-Version";
pub const X_POWERED_BY: &str = "X-Powered-By";

impl Registry {
    #[instrument(skip(self))]
    pub async fn handle_get_api_version(&self) -> Result<Response<ResponseBody>, Error> {
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
    use crate::registry::tests::backends;

    #[tokio::test]
    async fn test_handle_get_api_version() {
        for test_case in backends() {
            let response = test_case.registry().handle_get_api_version().await.unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get(DOCKER_DISTRIBUTION_API_VERSION)
                    .and_then(|h| h.to_str().ok())
                    .map(std::string::ToString::to_string),
                Some("registry/2.0".to_string())
            );
            assert_eq!(
                response
                    .headers()
                    .get(X_POWERED_BY)
                    .and_then(|h| h.to_str().ok())
                    .map(std::string::ToString::to_string),
                Some("Simple-Registry".to_string())
            );
        }
    }
}
