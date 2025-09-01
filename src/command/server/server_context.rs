use crate::configuration::IdentityConfig;
use crate::registry::{Error, Registry};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{error, instrument};

pub struct ServerContext<B, M> {
    pub credentials: HashMap<String, (String, String)>,
    pub timeouts: Vec<Duration>,
    pub registry: Registry<B, M>,
}

impl<B, M> ServerContext<B, M> {
    pub fn new(
        identities: &HashMap<String, IdentityConfig>,
        timeouts: Vec<Duration>,
        registry: Registry<B, M>,
    ) -> Self {
        let mut credentials = HashMap::new();
        for (identity_id, identity_config) in identities {
            credentials.insert(
                identity_config.username.clone(),
                (identity_id.clone(), identity_config.password.clone()),
            );
        }

        Self {
            credentials,
            timeouts,
            registry,
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
}
