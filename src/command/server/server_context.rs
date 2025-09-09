use crate::configuration::IdentityConfig;
use crate::registry::auth::{BasicAuthValidator, OidcValidator};
use crate::registry::repository::access_policy::OidcClaims;
use crate::registry::{Error, Registry};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

pub struct ServerContext {
    pub basic_auth_validator: BasicAuthValidator,
    pub timeouts: Vec<Duration>,
    pub registry: Registry,
    pub oidc_validators: HashMap<String, Arc<OidcValidator>>,
    pub credentials: HashMap<String, (String, String)>, // Keep for backwards compatibility
}

impl ServerContext {
    pub fn new(
        identities: &HashMap<String, IdentityConfig>,
        timeouts: Vec<Duration>,
        registry: Registry,
    ) -> Self {
        let basic_auth_validator = BasicAuthValidator::new(identities);
        let oidc_validators = registry.oidc_validators().clone();

        // Keep credentials for backwards compatibility
        let mut credentials = HashMap::new();
        for (identity_id, identity_config) in identities {
            credentials.insert(
                identity_config.username.clone(),
                (identity_id.clone(), identity_config.password.clone()),
            );
        }

        Self {
            basic_auth_validator,
            timeouts,
            registry,
            oidc_validators,
            credentials,
        }
    }

    #[instrument(skip(self, password))]
    pub fn validate_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<String>, Error> {
        self.basic_auth_validator
            .validate_credentials(username, password)
    }

    #[instrument(skip(self, token))]
    pub async fn validate_oidc_token(&self, token: &str) -> Result<OidcClaims, Error> {
        for validator in self.oidc_validators.values() {
            if let Ok(claims) = validator.validate_token(token).await {
                return Ok(claims);
            }
        }

        Err(Error::Unauthorized(
            "No OIDC providers configured".to_string(),
        ))
    }
}
