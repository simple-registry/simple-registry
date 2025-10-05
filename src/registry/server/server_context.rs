use crate::configuration::{IdentityConfig, OidcProviderConfig};
use crate::registry::cache;
use crate::registry::server::auth::oidc::OidcValidator;
use crate::registry::server::auth::{
    AuthMiddleware, AuthResult, BasicAuthValidator, MtlsValidator,
};
use crate::registry::server::ClientIdentity;
use crate::registry::{Error, Registry};
use hyper::http::request::Parts;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::instrument;

pub struct ServerContext {
    mtls_middleware: Arc<MtlsValidator>,
    basic_auth_middleware: Arc<BasicAuthValidator>,
    oidc_middlewares: Arc<Vec<OidcValidator>>,
    pub registry: Registry,
}

impl ServerContext {
    pub fn build_oidc_validators(
        oidc_config: &HashMap<String, OidcProviderConfig>,
        auth_token_cache: &cache::CacheStoreConfig,
    ) -> Result<Arc<Vec<OidcValidator>>, crate::configuration::Error> {
        let mut validators = Vec::new();
        for (name, provider_config) in oidc_config {
            let cache = auth_token_cache.to_backend()?;

            let validator =
                OidcValidator::new(name.clone(), provider_config, cache).map_err(|e| {
                    crate::configuration::Error::Http(format!(
                        "Failed to create OIDC validator '{name}': {e}"
                    ))
                })?;

            validators.push(validator);
        }
        Ok(Arc::new(validators))
    }

    pub fn new(
        identities: &HashMap<String, IdentityConfig>,
        registry: Registry,
        oidc_middlewares: Arc<Vec<OidcValidator>>,
    ) -> Self {
        let mtls_middleware = Arc::new(MtlsValidator::new());
        let basic_auth_middleware = Arc::new(BasicAuthValidator::new(identities));

        Self {
            mtls_middleware,
            basic_auth_middleware,
            oidc_middlewares,
            registry,
        }
    }

    #[instrument(skip(self, parts))]
    pub async fn authenticate_request(
        &self,
        parts: &Parts,
        remote_address: Option<std::net::SocketAddr>,
    ) -> Result<ClientIdentity, Error> {
        let mut identity = ClientIdentity::default();

        if let Some(forwarded_for) = parts.headers.get("X-Forwarded-For") {
            if let Ok(forwarded_str) = forwarded_for.to_str() {
                if let Some(first_ip) = forwarded_str.split(',').next() {
                    identity.client_ip = Some(first_ip.trim().to_string());
                }
            }
        } else if let Some(real_ip) = parts.headers.get("X-Real-IP") {
            if let Ok(ip_str) = real_ip.to_str() {
                identity.client_ip = Some(ip_str.to_string());
            }
        } else if let Some(addr) = remote_address {
            identity.client_ip = Some(addr.ip().to_string());
        }

        self.mtls_middleware
            .authenticate(parts, &mut identity)
            .await?;

        // Check OIDC validators first (stop on first match)
        // OIDC is checked first because JWT validation is fast and stateless, and may find
        // tokens in the Authorization header that are Basic Auth tokens.
        for validator in self.oidc_middlewares.iter() {
            match validator.authenticate(parts, &mut identity).await {
                Ok(AuthResult::Authenticated) => return Ok(identity),
                Ok(AuthResult::NoCredentials) => {}
                Err(e) => return Err(e),
            }
        }

        match self
            .basic_auth_middleware
            .authenticate(parts, &mut identity)
            .await
        {
            Ok(AuthResult::Authenticated) => return Ok(identity),
            Ok(AuthResult::NoCredentials) => {}
            Err(e) => return Err(e),
        }

        Ok(identity)
    }
}
