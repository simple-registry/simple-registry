use crate::configuration::IdentityConfig;
use crate::policy::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use cel_interpreter::{Context, Program, Value};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, info, instrument};

pub struct ServerContext {
    pub credentials: HashMap<String, (String, String)>,
    pub timeouts: Vec<Duration>,
    pub registry: Registry,
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

        Self {
            credentials,
            timeouts,
            registry,
        }
    }

    fn deny() -> Error {
        Error::Unauthorized(Some("Access denied".to_string()))
    }

    #[instrument(skip(self, request))]
    pub fn validate_request(
        &self,
        request: ClientRequest,
        identity: ClientIdentity,
    ) -> Result<(), Error> {
        let Some(namespace) = request.namespace.as_ref() else {
            return Ok(());
        };

        let (repository_name, found_repository) = self
            .registry
            .repositories
            .iter()
            .find(|(repository, _)| namespace.starts_with(*repository))
            .ok_or_else(Self::deny)?;

        debug!(
            "Default allow: {:?} for namespace: {:?} ({:?})",
            found_repository.access_default_allow, namespace, repository_name
        );

        if found_repository.access_default_allow {
            self.check_deny_policies(&request, &identity, &found_repository.access_rules)
        } else {
            self.check_allow_policies(&request, &identity, &found_repository.access_rules)
        }
    }

    #[instrument(skip(self, policies))]
    fn check_deny_policies(
        &self,
        request: &ClientRequest,
        identity: &ClientIdentity,
        policies: &[Program],
    ) -> Result<(), Error> {
        let context = self.build_policy_context(identity, request)?;

        for policy in policies {
            let evaluation_result = policy.execute(&context).map_err(|e| {
                error!("Policy execution failed: {}", e);
                Self::deny()
            })?;

            debug!(
                "CEL program '{:?}' evaluates to {:?}",
                policy, evaluation_result
            );
            match evaluation_result {
                Value::Bool(false) => {
                    info!("Policy matched, denying access");
                    return Err(Self::deny());
                }
                Value::Bool(_) => {} // Not validated, continue checking
                _ => {
                    info!("Policy returned invalid value, denying access");
                    return Err(Self::deny());
                }
            }
        }

        debug!("No policy matched, applying default policy");
        Ok(())
    }

    #[instrument(skip(self, policies))]
    fn check_allow_policies(
        &self,
        request: &ClientRequest,
        identity: &ClientIdentity,
        policies: &[Program],
    ) -> Result<(), Error> {
        let context = self.build_policy_context(identity, request)?;

        for policy in policies {
            let evaluation_result = policy.execute(&context).map_err(|e| {
                error!("Policy execution failed: {}", e);
                Self::deny()
            })?;

            debug!(
                "CEL program '{:?}' evaluates to {:?}",
                policy, evaluation_result
            );
            match evaluation_result {
                Value::Bool(true) => {
                    debug!("Policy matched, allowing access");
                    return Ok(());
                }
                Value::Bool(_) => {} // Not validated, continue checking
                _ => {
                    info!("Policy returned invalid value, denying access");
                    return Err(Self::deny());
                }
            }
        }

        debug!(
            "Default policy denied access: {:?} for {:?}",
            request, identity.id
        );
        Err(Self::deny())
    }

    #[instrument(skip(self))]
    fn build_policy_context(
        &self,
        identity: &ClientIdentity,
        request: &ClientRequest,
    ) -> Result<Context, Error> {
        let mut context = Context::default();

        debug!("Policy context (request) : {:?}", request);
        context.add_variable("request", request).map_err(|e| {
            error!("Failed to add request to policy context: {}", e);
            Self::deny()
        })?;

        debug!("Policy context (identity) : {:?}", identity);
        context.add_variable("identity", identity).map_err(|e| {
            error!("Failed to add identity to policy context: {}", e);
            Self::deny()
        })?;

        Ok(context)
    }

    #[instrument(skip(self, password))]
    pub fn validate_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<String>, Error> {
        let (identity_id, identity_password) =
            self.credentials.get(username).ok_or_else(Self::deny)?;

        let identity_password = PasswordHash::new(identity_password).map_err(|e| {
            error!("Unable to hash password: {}", e);
            Self::deny()
        })?;

        Argon2::default()
            .verify_password(password.as_bytes(), &identity_password)
            .map_err(|e| {
                error!("Unable to verify password: {}", e);
                Self::deny()
            })?;

        Ok(Some(identity_id.clone()))
    }
}
