use super::oidc::OidcValidator;
use super::{AuthMiddleware, AuthResult, BasicAuthValidator, MtlsValidator};
use crate::configuration::{AuthConfig, Configuration};
use crate::metrics_provider::AUTH_ATTEMPTS;
use crate::registry::cache::CacheStoreConfig;
use crate::registry::server::ClientIdentity;
use crate::registry::Error;
use hyper::http::request::Parts;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, instrument, warn};

type OidcValidators = Vec<(String, Arc<dyn AuthMiddleware>)>;

/// Coordinates all authentication methods and handles the authentication chain
pub struct Authenticator {
    mtls_validator: MtlsValidator,
    oidc_validators: OidcValidators,
    basic_auth_validator: Option<BasicAuthValidator>,
    auth_required: bool,
}

impl Authenticator {
    pub fn new(config: &Configuration) -> Result<Self, Error> {
        let auth_config = &config.auth;

        let mtls_validator = MtlsValidator::new();
        let oidc_validators = Self::build_oidc_validators(auth_config, &config.cache)?;
        let basic_auth_validator = (!auth_config.identity.is_empty())
            .then(|| BasicAuthValidator::new(&auth_config.identity));

        let auth_required = !auth_config.identity.is_empty()
            || !oidc_validators.is_empty()
            || !config.global.access_policy.rules.is_empty()
            || config
                .repository
                .values()
                .any(|r| !r.access_policy.rules.is_empty());

        Ok(Self {
            mtls_validator,
            oidc_validators,
            basic_auth_validator,
            auth_required,
        })
    }

    fn build_oidc_validators(
        auth_config: &AuthConfig,
        cache_config: &CacheStoreConfig,
    ) -> Result<OidcValidators, Error> {
        let mut validators = Vec::new();

        for (name, oidc_config) in &auth_config.oidc {
            let cache = cache_config
                .to_backend()
                .map_err(|e| Error::Internal(format!("Failed to create cache for OIDC: {e}")))?;

            let validator = OidcValidator::new(name.clone(), oidc_config, cache)?;
            validators.push((name.clone(), Arc::new(validator) as Arc<dyn AuthMiddleware>));
        }

        Ok(validators)
    }

    /// Authentication order: mTLS → OIDC → Basic Auth
    #[instrument(skip(self, parts), fields(auth_method = tracing::field::Empty))]
    pub async fn authenticate_request(
        &self,
        parts: &Parts,
        remote_address: Option<SocketAddr>,
    ) -> Result<ClientIdentity, Error> {
        let mut identity = ClientIdentity::new(remote_address);
        let mut authenticated_method = None;

        match self.mtls_validator.authenticate(parts, &mut identity).await {
            Ok(AuthResult::Authenticated) => {
                debug!("mTLS authentication extracted certificate info");
                if authenticated_method.is_none()
                    && (!identity.certificate.common_names.is_empty()
                        || !identity.certificate.organizations.is_empty())
                {
                    AUTH_ATTEMPTS.with_label_values(&["mtls", "success"]).inc();
                    authenticated_method = Some("mtls");
                }
            }
            Ok(AuthResult::NoCredentials) => {}
            Err(e) => {
                warn!("mTLS validation error: {}", e);
                AUTH_ATTEMPTS.with_label_values(&["mtls", "failed"]).inc();
            }
        }

        let mut oidc_authenticated = false;
        for (provider_name, validator) in &self.oidc_validators {
            match validator.authenticate(parts, &mut identity).await {
                Ok(AuthResult::Authenticated) => {
                    debug!(
                        "OIDC authentication succeeded with provider: {}",
                        provider_name
                    );
                    AUTH_ATTEMPTS.with_label_values(&["oidc", "success"]).inc();
                    authenticated_method = Some("oidc");
                    oidc_authenticated = true;
                    break;
                }
                Ok(AuthResult::NoCredentials) => {}
                Err(e) => {
                    warn!(
                        "OIDC validation failed for provider {}: {}",
                        provider_name, e
                    );
                    AUTH_ATTEMPTS.with_label_values(&["oidc", "failed"]).inc();
                    return Err(e);
                }
            }
        }

        if !oidc_authenticated {
            if let Some(ref basic_auth) = self.basic_auth_validator {
                match basic_auth.authenticate(parts, &mut identity).await {
                    Ok(AuthResult::Authenticated) => {
                        debug!("Basic authentication succeeded");
                        AUTH_ATTEMPTS.with_label_values(&["basic", "success"]).inc();
                        authenticated_method = Some("basic");
                    }
                    Ok(AuthResult::NoCredentials) => {}
                    Err(e) => {
                        warn!("Basic auth validation failed: {}", e);
                        AUTH_ATTEMPTS.with_label_values(&["basic", "failed"]).inc();
                        return Err(e);
                    }
                }
            }
        }

        if self.auth_required && !identity.is_authenticated() {
            AUTH_ATTEMPTS.with_label_values(&["none", "failed"]).inc();
            return Err(Error::Unauthorized(
                "Authentication required but no valid credentials provided".to_string(),
            ));
        }

        if let Some(method) = authenticated_method {
            tracing::Span::current().record("auth_method", method);
        } else {
            tracing::Span::current().record("auth_method", "anonymous");
        }

        Ok(identity)
    }

    #[cfg(test)]
    pub fn is_auth_required(&self) -> bool {
        self.auth_required
    }

    #[cfg(test)]
    pub fn oidc_provider_count(&self) -> usize {
        self.oidc_validators.len()
    }

    #[cfg(test)]
    pub fn has_basic_auth(&self) -> bool {
        self.basic_auth_validator.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::IdentityConfig;
    use std::collections::HashMap;

    #[test]
    fn test_authenticator_properties() {
        let authenticator = Authenticator {
            mtls_validator: MtlsValidator::new(),
            oidc_validators: vec![],
            basic_auth_validator: None,
            auth_required: false,
        };

        assert!(!authenticator.is_auth_required());
        assert_eq!(authenticator.oidc_provider_count(), 0);
        assert!(!authenticator.has_basic_auth());
    }

    #[test]
    fn test_authenticator_with_basic_auth() {
        let mut identities = HashMap::new();
        identities.insert(
            "test".to_string(),
            IdentityConfig {
                username: "test".to_string(),
                password: "hash".to_string(),
            },
        );

        let authenticator = Authenticator {
            mtls_validator: MtlsValidator::new(),
            oidc_validators: vec![],
            basic_auth_validator: Some(BasicAuthValidator::new(&identities)),
            auth_required: true,
        };

        assert!(authenticator.is_auth_required());
        assert_eq!(authenticator.oidc_provider_count(), 0);
        assert!(authenticator.has_basic_auth());
    }
}
