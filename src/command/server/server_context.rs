use crate::configuration::IdentityConfig;
use crate::registry::auth::oidc::OidcValidator;
use crate::registry::repository::access_policy::OidcClaims;
use crate::registry::{Error, Registry};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, instrument, warn};

pub struct ServerContext {
    pub credentials: HashMap<String, (String, String)>,
    pub timeouts: Vec<Duration>,
    pub registry: Registry,
    pub oidc_validators: HashMap<String, Arc<OidcValidator>>,
}

impl ServerContext {
    pub fn new(
        identities: &HashMap<String, IdentityConfig>,
        timeouts: Vec<Duration>,
        registry: Registry,
    ) -> Self {
        let mut credentials = HashMap::new();
        for (identity_id, identity_config) in identities {
            credentials.insert(
                identity_config.username.clone(),
                (identity_id.clone(), identity_config.password.clone()),
            );
        }

        let oidc_validators = registry.oidc_validators().clone();

        Self {
            credentials,
            timeouts,
            registry,
            oidc_validators,
        }
    }

    fn deny() -> Error {
        Error::Unauthorized("Access denied".to_string())
    }

    #[instrument(skip(self, password))]
    pub fn validate_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<String>, Error> {
        let (identity_id, identity_password) =
            self.credentials.get(username).ok_or_else(Self::deny)?;

        let identity_password = PasswordHash::new(identity_password).map_err(|error| {
            error!("Unable to hash password: {error}");
            Self::deny()
        })?;

        Argon2::default()
            .verify_password(password.as_bytes(), &identity_password)
            .map_err(|error| {
                error!("Unable to verify password: {error}");
                Self::deny()
            })?;

        Ok(Some(identity_id.clone()))
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
