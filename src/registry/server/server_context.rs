use crate::configuration::{CacheStoreConfig, IdentityConfig, OidcProviderConfig};
use crate::registry::cache::{self, Cache};
use crate::registry::server::auth::oidc::OidcValidator;
use crate::registry::server::auth::{
    AuthMiddleware, AuthResult, BasicAuthValidator, MtlsValidator,
};
use crate::registry::server::ClientIdentity;
use crate::registry::{Error, Registry};
use hyper::body::Incoming;
use hyper::Request;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

pub struct ServerContext {
    mtls_middleware: Arc<MtlsValidator>,
    basic_auth_middleware: Arc<BasicAuthValidator>,
    oidc_middlewares: Arc<Vec<OidcValidator>>,
    pub timeouts: Vec<Duration>,
    pub registry: Registry,
    pub credentials: HashMap<String, (String, String)>, // Keep for backwards compatibility
}

impl ServerContext {
    pub fn build_oidc_validators(
        oidc_config: &HashMap<String, OidcProviderConfig>,
        auth_token_cache: &CacheStoreConfig,
    ) -> Result<Arc<Vec<OidcValidator>>, crate::configuration::Error> {
        let mut validators = Vec::new();
        for (name, provider_config) in oidc_config {
            let cache: Box<dyn Cache> = match auth_token_cache {
                CacheStoreConfig::Redis(redis_config) => {
                    Box::new(cache::redis::Backend::new(redis_config.clone())?)
                }
                CacheStoreConfig::Memory => Box::new(cache::memory::Backend::new()),
            };

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
        timeouts: Vec<Duration>,
        registry: Registry,
        oidc_middlewares: Arc<Vec<OidcValidator>>,
    ) -> Self {
        let mtls_middleware = Arc::new(MtlsValidator::new());
        let basic_auth_middleware = Arc::new(BasicAuthValidator::new(identities));

        let credentials = identities
            .iter()
            .map(|(id, config)| {
                (
                    config.username.clone(),
                    (id.clone(), config.password.clone()),
                )
            })
            .collect();

        Self {
            mtls_middleware,
            basic_auth_middleware,
            oidc_middlewares,
            timeouts,
            registry,
            credentials,
        }
    }

    #[instrument(skip(self, request))]
    pub async fn authenticate_request(
        &self,
        request: &Request<Incoming>,
    ) -> Result<ClientIdentity, Error> {
        let mut identity = ClientIdentity::default();

        self.mtls_middleware
            .authenticate(request, &mut identity)
            .await?;

        // Check basic auth
        match self
            .basic_auth_middleware
            .authenticate(request, &mut identity)
            .await
        {
            Ok(AuthResult::Authenticated) => return Ok(identity),
            Ok(AuthResult::NoCredentials) => {}
            Err(e) => return Err(e),
        }

        // Check OIDC validators (stop on first match)
        for validator in self.oidc_middlewares.iter() {
            match validator.authenticate(request, &mut identity).await {
                Ok(AuthResult::Authenticated) => return Ok(identity),
                Ok(AuthResult::NoCredentials) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(identity)
    }
}
