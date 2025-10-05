pub mod jwk;
pub mod provider;

use crate::configuration::OidcProviderConfig;
use crate::registry::cache::Cache;
use crate::registry::server::auth::basic_auth::extract_basic_auth;
use crate::registry::server::auth::oidc::provider::{generic, github};
use crate::registry::server::auth::{AuthMiddleware, AuthResult};
use crate::registry::server::request_ext::HeaderExt;
use crate::registry::server::{ClientIdentity, OidcClaims};
use crate::registry::Error;
use async_trait::async_trait;
use hyper::http::request::Parts;
pub use jwk::Jwk;
pub use provider::OidcProvider;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

pub struct OidcValidator {
    provider_name: String,
    provider: Box<dyn OidcProvider>,
    http_client: Arc<Client>,
    cache: Arc<dyn Cache>,
}

impl OidcValidator {
    pub fn new(
        provider_name: String,
        provider_config: &OidcProviderConfig,
        cache: Arc<dyn Cache>,
    ) -> Result<Self, Error> {
        let http_client = Arc::new(
            Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| Error::Internal(format!("Failed to build HTTP client: {e}")))?,
        );

        let provider: Box<dyn OidcProvider> = match provider_config {
            OidcProviderConfig::Generic(cfg) => Box::new(generic::Provider::new(cfg.clone())),
            OidcProviderConfig::GitHub(cfg) => Box::new(github::Provider::new(cfg.clone())),
        };

        Ok(Self {
            provider_name,
            provider,
            http_client,
            cache,
        })
    }

    pub async fn validate_token(&self, token: &str) -> Result<OidcClaims, Error> {
        generic::validate_oidc_token(
            &self.provider_name,
            &*self.provider,
            token,
            &self.http_client,
            &*self.cache,
        )
        .await
    }
}

#[async_trait]
impl AuthMiddleware for OidcValidator {
    async fn authenticate(
        &self,
        parts: &Parts,
        identity: &mut ClientIdentity,
    ) -> Result<AuthResult, Error> {
        let token = if let Some(bearer_token) = parts.bearer_token() {
            debug!(
                "Found Bearer token for OIDC provider '{}'",
                self.provider_name
            );
            bearer_token
        } else if let Some((username, password)) = extract_basic_auth(parts) {
            debug!("Found Basic auth credentials with username '{}'", username);
            if username != self.provider_name {
                debug!(
                    "Basic auth username '{}' doesn't match OIDC provider name '{}', skipping",
                    username, self.provider_name
                );
                return Ok(AuthResult::NoCredentials);
            }
            password
        } else {
            return Ok(AuthResult::NoCredentials);
        };

        match self.validate_token(&token).await {
            Ok(claims) => {
                debug!(
                    "Successfully validated OIDC token for provider '{}' with claims: {:?}",
                    self.provider_name, claims
                );
                identity.oidc = Some(claims);
                Ok(AuthResult::Authenticated)
            }
            Err(e) => {
                debug!(
                    "OIDC token validation failed for provider '{}': {}",
                    self.provider_name, e
                );
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ResponseBody;
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;
    use hyper::header::{HeaderValue, AUTHORIZATION};
    use hyper::Request;

    #[test]
    fn test_oidc_bearer_token() {
        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            )
            .body(ResponseBody::empty())
            .unwrap();

        let (parts, _) = request.into_parts();

        assert_eq!(
            parts.bearer_token(),
            Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9".to_string())
        );
    }

    #[test]
    fn test_oidc_basic_auth() {
        let credentials = BASE64_STANDARD.encode("github:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {credentials}")).unwrap(),
            )
            .body(ResponseBody::empty())
            .unwrap();

        let (parts, _) = request.into_parts();

        let (username, password) = extract_basic_auth(&parts).unwrap();
        assert_eq!(username, "github");
        assert_eq!(password, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
    }
}
