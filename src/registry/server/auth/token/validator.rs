use crate::registry::server::auth::token::TokenSigner;
use crate::registry::server::auth::{AuthMiddleware, AuthResult};
use crate::registry::server::request_ext::HeaderExt;
use crate::registry::server::ClientIdentity;
use crate::registry::Error;
use async_trait::async_trait;
use hyper::http::request::Parts;
use std::sync::Arc;
use tracing::debug;

pub struct TokenAuthMiddleware {
    token_signer: Arc<TokenSigner>,
}

impl TokenAuthMiddleware {
    pub fn new(token_signer: Arc<TokenSigner>) -> Self {
        Self { token_signer }
    }
}

#[async_trait]
impl AuthMiddleware for TokenAuthMiddleware {
    async fn authenticate(
        &self,
        parts: &Parts,
        identity: &mut ClientIdentity,
    ) -> Result<AuthResult, Error> {
        let Some(token) = parts.bearer_token() else {
            return Ok(AuthResult::NoCredentials);
        };

        debug!("Attempting to validate registry token");

        match self.token_signer.validate_token(&token) {
            Ok(claims) => {
                debug!(
                    "Successfully validated registry token for subject '{}' with {} access entries",
                    claims.sub,
                    claims.access.len()
                );

                identity.id = Some(claims.sub.clone());
                identity.username = Some(claims.sub);
                identity.token_scopes.clone_from(&claims.access);

                Ok(AuthResult::Authenticated)
            }
            Err(e) => {
                debug!("Registry token validation failed: {}", e);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::server::auth::token::{jwt::TokenSigner, AccessEntry};
    use crate::registry::ResponseBody;
    use chrono::Duration;
    use hyper::header::{HeaderValue, AUTHORIZATION};
    use hyper::Request;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};

    fn create_test_signer() -> TokenSigner {
        TokenSigner::new(
            EncodingKey::from_secret(b"test-secret"),
            DecodingKey::from_secret(b"test-secret"),
            Algorithm::HS256,
            "test-issuer".to_string(),
            Duration::hours(1),
            Duration::hours(24),
        )
    }

    #[tokio::test]
    async fn test_authenticate_with_valid_token() {
        let signer = Arc::new(create_test_signer());
        let middleware = TokenAuthMiddleware::new(signer.clone());

        let access = vec![AccessEntry {
            resource_type: "repository".to_string(),
            name: "myorg/myapp".to_string(),
            actions: vec!["pull".to_string()],
        }];

        let (token, _) = signer.generate_token("test-user", access, None).unwrap();

        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            )
            .body(ResponseBody::empty())
            .unwrap();

        let (parts, _) = request.into_parts();
        let mut identity = ClientIdentity::default();

        let result = middleware.authenticate(&parts, &mut identity).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), AuthResult::Authenticated));
        assert_eq!(identity.username, Some("test-user".to_string()));
        assert_eq!(identity.id, Some("test-user".to_string()));
    }

    #[tokio::test]
    async fn test_authenticate_with_invalid_token() {
        let signer = Arc::new(create_test_signer());
        let middleware = TokenAuthMiddleware::new(signer);

        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Bearer invalid.token.here"),
            )
            .body(ResponseBody::empty())
            .unwrap();

        let (parts, _) = request.into_parts();
        let mut identity = ClientIdentity::default();

        let result = middleware.authenticate(&parts, &mut identity).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_no_bearer_token() {
        let signer = Arc::new(create_test_signer());
        let middleware = TokenAuthMiddleware::new(signer);

        let request = Request::builder().body(ResponseBody::empty()).unwrap();

        let (parts, _) = request.into_parts();
        let mut identity = ClientIdentity::default();

        let result = middleware.authenticate(&parts, &mut identity).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), AuthResult::NoCredentials));
    }

    #[tokio::test]
    async fn test_authenticate_with_expired_token() {
        let signer = Arc::new(TokenSigner::new(
            EncodingKey::from_secret(b"test-secret"),
            DecodingKey::from_secret(b"test-secret"),
            Algorithm::HS256,
            "test-issuer".to_string(),
            Duration::seconds(1),
            Duration::seconds(1),
        ));

        let middleware = TokenAuthMiddleware::new(signer.clone());

        let access = vec![AccessEntry {
            resource_type: "repository".to_string(),
            name: "test/repo".to_string(),
            actions: vec!["pull".to_string()],
        }];

        let (token, _) = signer
            .generate_token("user", access, Some(Duration::seconds(1)))
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            )
            .body(ResponseBody::empty())
            .unwrap();

        let (parts, _) = request.into_parts();
        let mut identity = ClientIdentity::default();

        let result = middleware.authenticate(&parts, &mut identity).await;
        assert!(result.is_err());
    }
}
