use crate::registry::server::auth::token::{parse_scopes, validate_repository_access};
use crate::registry::server::ServerContext;
use crate::registry::{Error, ResponseBody};
use chrono::Duration;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::http::request::Parts;
use hyper::{Response, StatusCode};
use serde_json::json;
use tracing::{debug, instrument, warn};

impl ServerContext {
    #[instrument(skip(self, parts))]
    pub async fn handle_token(
        &self,
        parts: &Parts,
        scopes: Vec<String>,
        expires_in: Option<u64>,
    ) -> Result<Response<ResponseBody>, Error> {
        let token_signer = self
            .token_signer
            .as_ref()
            .ok_or_else(|| Error::Internal("Token authentication is not enabled".to_string()))?;

        let identity = self.authenticate_request(parts, None).await?;

        debug!(
            "Token request from identity: {:?}, scopes: {:?}",
            identity, scopes
        );

        let access_entries = if scopes.is_empty() {
            debug!("No scopes requested, issuing token with empty access");
            Vec::new()
        } else {
            let entries = parse_scopes(&scopes)?;

            for entry in &entries {
                if entry.resource_type != "repository" {
                    return Err(Error::Unauthorized(format!(
                        "Unsupported resource type: {}",
                        entry.resource_type
                    )));
                }

                let validation_routes = validate_repository_access(&entry.name, &entry.actions)?;

                for route in validation_routes {
                    debug!(
                        "Validating repository '{}' actions {:?} for identity {:?}",
                        entry.name, entry.actions, identity
                    );

                    self.registry
                        .validate_request(&route, &identity, parts)
                        .await?;
                }
            }

            entries
        };

        let requested_ttl = expires_in.map(|secs| {
            let i_secs = i64::try_from(secs).unwrap_or(3600);
            Duration::seconds(i_secs)
        });

        let subject = identity
            .id
            .as_ref()
            .or(identity.username.as_ref())
            .map_or("anonymous", String::as_str);

        let (token, exp) = token_signer.generate_token(subject, access_entries, requested_ttl)?;

        let now = chrono::Utc::now();
        let actual_ttl = exp.signed_duration_since(now);
        let expires_in_secs = u64::try_from(actual_ttl.num_seconds()).unwrap_or(0);

        if let Some(requested) = expires_in {
            if requested > expires_in_secs {
                warn!(
                    "Requested TTL {}s exceeds maximum, using {}s",
                    requested, expires_in_secs
                );
            }
        }

        let body = json!({
            "token": token,
            "access_token": token,
            "expires_in": expires_in_secs,
            "issued_at": now.to_rfc3339(),
        });

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(ResponseBody::Fixed(Full::new(Bytes::from(
                body.to_string(),
            ))))?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{IdentityConfig, TokenConfig};
    use crate::registry::server::auth::oidc::OidcValidator;
    use crate::registry::tests::FSRegistryTestCase;
    use crate::registry::ResponseBody;
    use base64::Engine;
    use hyper::header::{HeaderValue, AUTHORIZATION};
    use hyper::Request;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn create_test_context(test_case: FSRegistryTestCase) -> ServerContext {
        let mut identities = HashMap::new();
        identities.insert(
            "testuser".to_string(),
            IdentityConfig {
                username: "testuser".to_string(),
                password: "$argon2id$v=19$m=19456,t=2,p=1$test$test".to_string(),
            },
        );

        let token_config = TokenConfig {
            algorithm: "HS256".to_string(),
            secret: Some("test-secret-key-for-testing-only".to_string()),
            private_key_path: None,
            public_key_path: None,
            default_ttl: "1h".to_string(),
            max_ttl: "24h".to_string(),
            issuer: "test-issuer".to_string(),
        };

        ServerContext::new(
            &identities,
            test_case.into_registry(),
            Arc::new(Vec::<OidcValidator>::new()),
            Some(token_config),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_handle_token_no_scopes() {
        let test_case = FSRegistryTestCase::new();
        let context = create_test_context(test_case);

        let request = Request::builder()
            .uri("https://registry.example.com/v2/token?service=registry.example.com")
            .body(ResponseBody::empty())
            .unwrap();

        let (parts, _) = request.into_parts();

        let response = context.handle_token(&parts, vec![], None).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn test_handle_token_with_basic_auth() {
        let test_case = FSRegistryTestCase::new();
        let context = create_test_context(test_case);

        let auth_value = base64::prelude::BASE64_STANDARD.encode("testuser:testpass");
        let request = Request::builder()
            .uri("https://registry.example.com/v2/token?service=registry.example.com&scope=repository:myapp:pull")
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {auth_value}")).unwrap(),
            )
            .body(ResponseBody::empty())
            .unwrap();

        let (parts, _) = request.into_parts();

        let _result = context
            .handle_token(&parts, vec!["repository:myapp:pull".to_string()], None)
            .await;
    }
}
