use crate::configuration::IdentityConfig;
use crate::registry::server::auth::{AuthMiddleware, AuthResult};
use crate::registry::server::request_ext::RequestExt;
use crate::registry::server::ClientIdentity;
use crate::registry::Error;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use hyper::body::Incoming;
use hyper::header::AUTHORIZATION;
use hyper::Request;
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
    async fn authenticate(
        &self,
        request: &Request<Incoming>,
        identity: &mut ClientIdentity,
    ) -> Result<AuthResult, Error> {
        let Some((username, password)) = extract_basic_auth(request) else {
            return Ok(AuthResult::NoCredentials);
        };

        let identity_id = self.validate_credentials(&username, &password)?;
        identity.id = identity_id;
        identity.username = Some(username);
        Ok(AuthResult::Authenticated)
    }
}

/// Extracts Basic authentication credentials from the Authorization header.
pub fn extract_basic_auth<T>(request: &Request<T>) -> Option<(String, String)> {
    let Some(authorization) = request.get_header(AUTHORIZATION) else {
        debug!("No authorization header found");
        return None;
    };

    let value = authorization.strip_prefix("Basic ")?;
    let value = BASE64_STANDARD.decode(value).ok()?;
    let value = String::from_utf8(value).ok()?;

    let (username, password) = value.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ResponseBody;
    use hyper::header::HeaderValue;

    #[test]
    fn test_extract_basic_auth() {
        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Basic dXNlcjpwYXNzd29yZA=="),
            )
            .body(ResponseBody::empty())
            .unwrap();
        assert_eq!(
            extract_basic_auth(&request),
            Some(("user".to_string(), "password".to_string()))
        );

        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Bearer dXNlcjpwYXNzd29yZA=="),
            )
            .body(ResponseBody::empty())
            .unwrap();
        assert_eq!(extract_basic_auth(&request), None);

        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Basic dXNlcjpw YXNzd29yZA="),
            )
            .body(ResponseBody::empty())
            .unwrap();
        assert_eq!(extract_basic_auth(&request), None);

        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Basic dXNlcjpwY%%%%XNzd29yZA"),
            )
            .body(ResponseBody::empty())
            .unwrap();
        assert_eq!(extract_basic_auth(&request), None);

        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Basic dXNlcjpwYXNzd29yZA==="),
            )
            .body(ResponseBody::empty())
            .unwrap();
        assert_eq!(extract_basic_auth(&request), None);

        let request = Request::builder()
            .body(ResponseBody::empty())
            .unwrap();
        assert_eq!(extract_basic_auth(&request), None);
    }
}
