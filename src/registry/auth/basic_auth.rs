use super::{AuthMiddleware, AuthResult};
use crate::configuration::IdentityConfig;
use crate::registry::repository::access_policy::ClientIdentity;
use crate::registry::utils::request_ext::RequestExt;
use crate::registry::Error;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use hyper::body::Incoming;
use hyper::Request;
use std::collections::HashMap;
use tracing::{error, instrument};

pub struct BasicAuthValidator {
    credentials: HashMap<String, (String, String)>, // username -> (identity_id, password_hash)
}

impl BasicAuthValidator {
    pub fn new(identities: &HashMap<String, IdentityConfig>) -> Self {
        let mut credentials = HashMap::new();
        for (identity_id, identity_config) in identities {
            credentials.insert(
                identity_config.username.clone(),
                (identity_id.clone(), identity_config.password.clone()),
            );
        }

        Self { credentials }
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

#[async_trait]
impl AuthMiddleware for BasicAuthValidator {
    async fn authenticate(&self, request: &Request<Incoming>, identity: &mut ClientIdentity) -> Result<AuthResult, Error> {
        if let Some((username, password)) = request.basic_auth() {
            // Credentials were provided, validate them
            let identity_id = self.validate_credentials(&username, &password)?;
            identity.id = identity_id;
            identity.username = Some(username);
            Ok(AuthResult::Authenticated)
        } else {
            // No basic auth credentials in request
            Ok(AuthResult::NoCredentials)
        }
    }
}
