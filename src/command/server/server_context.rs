use crate::configuration::IdentityConfig;
use crate::registry::auth::{AuthMiddleware, AuthResult, BasicAuthValidator, OidcValidator};
use crate::registry::repository::access_policy::ClientIdentity;
use crate::registry::{Error, Registry};
use hyper::body::Incoming;
use hyper::Request;
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

    /// Process authentication middlewares in order
    #[instrument(skip(self, request))]
    pub async fn authenticate_request(
        &self,
        request: &Request<Incoming>,
        identity: &mut ClientIdentity,
    ) -> Result<(), Error> {
        // Try basic auth first
        match self.basic_auth_validator.authenticate(request, identity).await {
            Ok(AuthResult::Authenticated) => return Ok(()),
            Ok(AuthResult::NoCredentials) => {},  // Continue to next auth method
            Err(e) => return Err(e),  // Invalid credentials, fail immediately
        }
        
        // Try OIDC validators
        for validator in self.oidc_validators.values() {
            match validator.authenticate(request, identity).await {
                Ok(AuthResult::Authenticated) => return Ok(()),
                Ok(AuthResult::NoCredentials) => continue,  // Try next validator
                Err(e) => return Err(e),  // Invalid token, fail immediately
            }
        }
        
        // No authentication performed, request continues as anonymous
        Ok(())
    }

}
