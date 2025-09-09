pub mod jwk;
pub mod provider;

use crate::configuration::OidcProviderConfig;
use crate::registry::cache::Cache;
use crate::registry::http_client::{HttpClient, HttpClientBuilder};
use crate::registry::repository::access_policy::OidcClaims;
use crate::registry::Error;

use crate::registry::auth::oidc::provider::{generic, github};
pub use jwk::Jwk;
pub use provider::OidcProvider;

pub struct OidcValidator {
    provider: Box<dyn OidcProvider>,
    http_client: Box<dyn HttpClient>,
    cache: Box<dyn Cache>,
}

impl OidcValidator {
    pub fn new(
        _provider_name: String,
        provider_config: &OidcProviderConfig,
        cache: Box<dyn Cache>,
    ) -> Result<Self, Error> {
        let http_client = HttpClientBuilder::new().build()?;

        let provider: Box<dyn OidcProvider> = match provider_config {
            OidcProviderConfig::Generic(cfg) => Box::new(generic::Provider::new(cfg.clone())),
            OidcProviderConfig::GitHub(cfg) => Box::new(github::Provider::new(cfg.clone())),
        };

        Ok(Self {
            provider,
            http_client,
            cache,
        })
    }

    pub async fn validate_token(&self, token: &str) -> Result<OidcClaims, Error> {
        provider::generic::validate_oidc_token(
            self.provider.as_ref(),
            token,
            self.http_client.as_ref(),
            self.cache.as_ref(),
        )
        .await
    }
}
