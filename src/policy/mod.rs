use cel::{CELIdentity, CELIdentityCertificate, CELRequest};
use cel_interpreter::{Context, Program, Value};
use log::{debug, error};
use x509_parser::prelude::X509Certificate;

mod cel;
mod client_action;

use crate::error::RegistryError;
use crate::registry::Registry;
use crate::storage::StorageEngine;
pub use client_action::ClientAction;

#[derive(Clone, Debug, Default)]
pub struct ClientIdentity {
    pub cert_organizations: Vec<String>,
    pub cert_common_name: Vec<String>,
    pub credentials: Option<(String, String)>,
}

impl ClientIdentity {
    pub fn new() -> Self {
        ClientIdentity::default()
    }

    pub fn from_cert(cert: &X509Certificate) -> Result<ClientIdentity, RegistryError> {
        let subject = cert.subject();
        let cert_organizations = subject
            .iter_organization()
            .map(|o| o.as_str().map(String::from))
            .collect::<Result<Vec<String>, _>>()
            .map_err(|_| {
                RegistryError::Unauthorized("Unable to parse provided certificate".to_string())
            })?;
        let cert_common_name = subject
            .iter_common_name()
            .map(|o| o.as_str().map(String::from))
            .collect::<Result<Vec<String>, _>>()
            .map_err(|_| {
                RegistryError::Unauthorized("Unable to parse provided certificate".to_string())
            })?;

        Ok(ClientIdentity {
            cert_organizations,
            cert_common_name,
            credentials: None,
        })
    }

    pub fn set_credentials(&mut self, username: String, password: String) {
        self.credentials = Some((username, password));
    }

    pub fn can_do<T: StorageEngine>(
        &self,
        registry: &Registry<T>,
        action: ClientAction,
    ) -> Result<(), RegistryError> {
        // TODO: check repository exists!

        let identity_id = registry.validate_credentials(&self.credentials)?;

        let Some(namespace) = action.get_namespace() else {
            return Ok(());
        };

        let default_allow = registry.is_namespace_policy_default_allow(&namespace);
        let policies = registry.get_namespace_policies(&namespace);

        if let Some(policies) = policies {
            let request = CELRequest::from(action.clone());
            debug!("Policy context (request) : {:?}", request);

            let username = self
                .credentials
                .as_ref()
                .map(|(username, _)| username.clone());
            let certificate = CELIdentityCertificate::new(
                self.cert_organizations.clone(),
                self.cert_common_name.clone(),
            );
            let identity = CELIdentity::new(identity_id, username, certificate);
            debug!("Policy context (identity) : {:?}", identity);

            let mut context = Context::default();
            context.add_variable("request", &request).unwrap();
            context.add_variable("identity", &identity).unwrap();
            return self.check_policies(context, policies, default_allow);
        }

        self.apply_default_policy(default_allow)
    }

    fn apply_default_policy(&self, default_allow: bool) -> Result<(), RegistryError> {
        if default_allow {
            Ok(())
        } else {
            Err(RegistryError::Unauthorized(
                "Access denied (by policy)".to_string(),
            ))
        }
    }

    fn check_policies(
        &self,
        context: Context,
        policies: &[Program],
        default_allow: bool,
    ) -> Result<(), RegistryError> {
        for policy in policies {
            let evaluation_result = policy.execute(&context).map_err(|e| {
                error!("Policy execution failed: {}", e);
                RegistryError::Unauthorized("Policy execution failed".to_string())
            })?;
            debug!("CEL program evaluates to {:?}", evaluation_result);

            match evaluation_result {
                Value::Bool(true) if !default_allow => {
                    debug!("Policy matched, allowing access");
                    return Ok(());
                }
                Value::Bool(false) if default_allow => {
                    debug!("Policy matched, denying access");
                    return Err(RegistryError::Unauthorized(
                        "Access denied (by policy)".to_string(),
                    ));
                }
                Value::Bool(_) => {} // Not validated, continue checking
                _ => {
                    error!("Policy returned invalid value, denying access");
                    return Err(RegistryError::Unauthorized(
                        "Access denied (by policy)".to_string(),
                    ));
                }
            }
        }

        debug!("No policy matched, applying default policy");
        self.apply_default_policy(default_allow)
    }
}
