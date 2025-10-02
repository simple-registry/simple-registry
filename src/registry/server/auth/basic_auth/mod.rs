#[cfg(test)]
mod tests;

use crate::configuration::IdentityConfig;
use crate::registry::server::auth::{AuthMiddleware, AuthResult};
use crate::registry::server::request_ext::HeaderExt;
use crate::registry::server::ClientIdentity;
use crate::registry::Error;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use hyper::header::AUTHORIZATION;
use hyper::http::request::Parts;
use std::collections::HashMap;
use tracing::{debug, error, instrument};

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

    #[instrument(skip(self, password))]
    pub fn validate_credentials(&self, username: &str, password: &str) -> Option<String> {
        let Some((identity_id, identity_password)) = self.credentials.get(username) else {
            debug!("Username not found in credentials");
            return None;
        };

        let Ok(identity_password) = PasswordHash::new(identity_password) else {
            error!("Unable to parse password hash");
            return None;
        };

        match Argon2::default().verify_password(password.as_bytes(), &identity_password) {
            Ok(()) => Some(identity_id.clone()),
            Err(error) => {
                debug!("Password verification failed: {error}");
                None
            }
        }
    }
}

#[async_trait]
impl AuthMiddleware for BasicAuthValidator {
    async fn authenticate(
        &self,
        parts: &Parts,
        identity: &mut ClientIdentity,
    ) -> Result<AuthResult, Error> {
        let Some((username, password)) = extract_basic_auth(parts) else {
            return Ok(AuthResult::NoCredentials);
        };

        match self.validate_credentials(&username, &password) {
            Some(identity_id) => {
                identity.id = Some(identity_id);
                identity.username = Some(username);
                Ok(AuthResult::Authenticated)
            }
            None => Ok(AuthResult::NoCredentials),
        }
    }
}

/// Extracts Basic authentication credentials from the Authorization header.
pub fn extract_basic_auth(parts: &Parts) -> Option<(String, String)> {
    let Some(authorization) = parts.get_header(AUTHORIZATION) else {
        debug!("No authorization header found");
        return None;
    };

    let value = authorization.strip_prefix("Basic ")?;
    let value = BASE64_STANDARD.decode(value).ok()?;
    let value = String::from_utf8(value).ok()?;

    let (username, password) = value.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}
