//! Access control policy evaluation for registry operations.
//!
//! This module provides CEL-based access control for registry operations.
//! Policies are pre-compiled at configuration load time for performance.
//!
//! # Policy Evaluation
//!
//! Access policies support two modes:
//! - **Default Allow**: Access is granted unless explicitly denied by a rule
//! - **Default Deny**: Access is denied unless explicitly granted by a rule
//!
//! # Available Variables
//!
//! CEL expressions have access to:
//! - `identity`: Client identity information (id, username, certificate details)
//! - `request`: Request details (action, namespace, digest, reference)

use crate::configuration::Error as ConfigError;
pub use crate::registry::server::{ClientIdentity, ClientRequest};
use crate::registry::Error;
use cel_interpreter::{Context, Program, Value};
use serde::Deserialize;
use tracing::{debug, info};

/// Configuration for access control policies.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RepositoryAccessPolicyConfig {
    #[serde(default)]
    pub default_allow: bool,
    #[serde(default)]
    pub rules: Vec<String>,
}

/// Access control policy engine.
///
/// Evaluates CEL expressions to determine if a request should be allowed.
/// Rules are pre-compiled at configuration time for better performance.
pub struct AccessPolicy {
    default_allow: bool,
    rules: Vec<Program>,
}

impl AccessPolicy {
    /// Creates a new access policy from configuration.
    ///
    /// Compiles CEL expressions from the configuration into programs.
    pub fn new(config: &RepositoryAccessPolicyConfig) -> Result<Self, ConfigError> {
        let mut compiled_rules = Vec::new();

        for (index, rule) in config.rules.iter().enumerate() {
            match Program::compile(rule) {
                Ok(program) => compiled_rules.push(program),
                Err(e) => {
                    return Err(ConfigError::PolicyCompilation(format!(
                        "Failed to compile access policy rule #{} '{}': {}",
                        index + 1,
                        rule,
                        e
                    )));
                }
            }
        }

        Ok(Self {
            default_allow: config.default_allow,
            rules: compiled_rules,
        })
    }

    /// Evaluates the access policy for a given request and identity.
    ///
    /// # Arguments
    /// * `request` - The client request containing action and resource information
    /// * `identity` - The client identity containing authentication information
    ///
    /// # Returns
    /// * `Ok(true)` if access should be granted
    /// * `Ok(false)` if access should be denied
    /// * `Err` if policy evaluation fails
    pub fn evaluate(
        &self,
        request: &ClientRequest,
        identity: &ClientIdentity,
    ) -> Result<bool, Error> {
        if self.rules.is_empty() {
            return Ok(self.default_allow);
        }

        let context = Self::build_context(request, identity)?;

        if self.default_allow {
            for rule in &self.rules {
                match rule.execute(&context)? {
                    Value::Bool(true) => {
                        info!("Deny rule matched");
                        return Ok(false);
                    }
                    Value::Bool(false) => {}
                    _ => return Ok(false),
                }
            }
            Ok(true)
        } else {
            for rule in &self.rules {
                match rule.execute(&context)? {
                    Value::Bool(true) => {
                        debug!("Allow rule matched");
                        return Ok(true);
                    }
                    Value::Bool(false) => {}
                    _ => return Ok(false),
                }
            }
            Ok(false)
        }
    }

    fn build_context<'a>(
        request: &'a ClientRequest,
        identity: &'a ClientIdentity,
    ) -> Result<Context<'a>, Error> {
        let mut context = Context::default();
        context.add_variable("request", request)?;
        context.add_variable("identity", identity)?;
        Ok(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::oci::{Digest, Reference};

    #[test]
    fn test_access_policy_default_allow_no_rules() {
        let config = RepositoryAccessPolicyConfig {
            default_allow: true,
            rules: vec![],
        };
        let policy = AccessPolicy::new(&config).unwrap();
        let request = ClientRequest::get_api_version();
        let identity = ClientIdentity::default();

        let result = policy.evaluate(&request, &identity);
        assert!(result.unwrap());
    }

    #[test]
    fn test_access_policy_default_deny_no_rules() {
        let config = RepositoryAccessPolicyConfig {
            default_allow: false,
            rules: vec![],
        };
        let policy = AccessPolicy::new(&config).unwrap();
        let request = ClientRequest::get_api_version();
        let identity = ClientIdentity::default();

        let result = policy.evaluate(&request, &identity);
        assert!(!result.unwrap());
    }

    #[test]
    fn test_access_policy_default_allow_with_deny_rule() {
        let config = RepositoryAccessPolicyConfig {
            default_allow: true,
            rules: vec!["identity.username == 'forbidden'".to_string()],
        };
        let policy = AccessPolicy::new(&config).unwrap();

        let request = ClientRequest::get_api_version();
        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };

        let result = policy.evaluate(&request, &identity);
        assert!(!result.unwrap());

        let identity = ClientIdentity {
            username: Some("allowed".to_string()),
            ..ClientIdentity::default()
        };

        let result = policy.evaluate(&request, &identity);
        assert!(result.unwrap());
    }

    #[test]
    fn test_access_policy_default_deny_with_allow_rule() {
        let config = RepositoryAccessPolicyConfig {
            default_allow: false,
            rules: vec!["identity.username == 'admin'".to_string()],
        };
        let policy = AccessPolicy::new(&config).unwrap();

        let request = ClientRequest::get_api_version();
        let identity = ClientIdentity {
            username: Some("admin".to_string()),
            ..ClientIdentity::default()
        };

        let result = policy.evaluate(&request, &identity);
        assert!(result.unwrap());

        let identity = ClientIdentity {
            username: Some("user".to_string()),
            ..ClientIdentity::default()
        };

        let result = policy.evaluate(&request, &identity);
        assert!(!result.unwrap());
    }

    #[test]
    fn test_get_api_version() {
        let request = ClientRequest::get_api_version();
        assert_eq!(request.action, "get-api-version");
        assert!(request.namespace.is_none());
        assert!(request.digest.is_none());
        assert!(request.reference.is_none());
    }

    #[test]
    fn test_get_manifest() {
        use crate::registry::oci::Reference;
        let namespace = "test-namespace";
        let reference = Reference::Tag("tag".to_string());
        let request = ClientRequest::get_manifest(namespace, &reference);

        assert_eq!(request.action, "get-manifest");
        assert_eq!(request.namespace, Some(namespace.to_string()));
        assert_eq!(request.reference, Some(reference.to_string()));
        assert!(request.digest.is_none());
    }

    #[test]
    fn test_get_blob() {
        use crate::registry::oci::Digest;
        let namespace = "test-namespace";
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        let request = ClientRequest::get_blob(namespace, &digest);

        assert_eq!(request.action, "get-blob");
        assert_eq!(request.namespace, Some(namespace.to_string()));
        assert_eq!(request.digest, Some(digest.to_string()));
        assert!(request.reference.is_none());
    }

    #[test]
    fn test_upload_operations() {
        let name = "test-upload";

        let start_request = ClientRequest::start_upload(name);
        assert_eq!(start_request.action, "start-upload");
        assert_eq!(start_request.namespace, Some(name.to_string()));

        let update_request = ClientRequest::update_upload(name);
        assert_eq!(update_request.action, "update-upload");
        assert_eq!(update_request.namespace, Some(name.to_string()));

        let complete_request = ClientRequest::complete_upload(name);
        assert_eq!(complete_request.action, "complete-upload");
        assert_eq!(complete_request.namespace, Some(name.to_string()));

        let cancel_request = ClientRequest::cancel_upload(name);
        assert_eq!(cancel_request.action, "cancel-upload");
        assert_eq!(cancel_request.namespace, Some(name.to_string()));

        let get_request = ClientRequest::get_upload(name);
        assert_eq!(get_request.action, "get-upload");
        assert_eq!(get_request.namespace, Some(name.to_string()));
    }

    #[test]
    fn test_delete_operations() {
        use crate::registry::oci::{Digest, Reference};
        let name = "test-namespace";
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        let reference = Reference::Tag("tag".to_string());

        let delete_blob_request = ClientRequest::delete_blob(name, &digest);
        assert_eq!(delete_blob_request.action, "delete-blob");
        assert_eq!(delete_blob_request.namespace, Some(name.to_string()));
        assert_eq!(delete_blob_request.digest, Some(digest.to_string()));

        let delete_manifest_request = ClientRequest::delete_manifest(name, &reference);
        assert_eq!(delete_manifest_request.action, "delete-manifest");
        assert_eq!(delete_manifest_request.namespace, Some(name.to_string()));
        assert_eq!(
            delete_manifest_request.reference,
            Some(reference.to_string())
        );
    }

    #[test]
    fn test_get_referrers() {
        use crate::registry::oci::Digest;
        let name = "test-namespace";
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        let request = ClientRequest::get_referrers(name, &digest);

        assert_eq!(request.action, "get-referrers");
        assert_eq!(request.namespace, Some(name.to_string()));
        assert_eq!(request.digest, Some(digest.to_string()));
        assert!(request.reference.is_none());
    }

    #[test]
    fn test_list_operations() {
        let list_catalog_request = ClientRequest::list_catalog();
        assert_eq!(list_catalog_request.action, "list-catalog");
        assert!(list_catalog_request.namespace.is_none());
        assert!(list_catalog_request.digest.is_none());
        assert!(list_catalog_request.reference.is_none());

        let name = "test-namespace";
        let list_tags_request = ClientRequest::list_tags(name);
        assert_eq!(list_tags_request.action, "list-tags");
        assert_eq!(list_tags_request.namespace, Some(name.to_string()));
        assert!(list_tags_request.digest.is_none());
        assert!(list_tags_request.reference.is_none());
    }

    #[test]
    fn test_is_write() {
        let write_actions = [
            ClientRequest::start_upload("test"),
            ClientRequest::update_upload("test"),
            ClientRequest::complete_upload("test"),
            ClientRequest::cancel_upload("test"),
            ClientRequest::put_manifest("test", &Reference::Tag("tag".to_string())),
            ClientRequest::delete_manifest("test", &Reference::Tag("tag".to_string())),
            ClientRequest::delete_blob("test", &Digest::Sha256("1234567890abcdef".to_string())),
        ];

        let read_actions = [
            ClientRequest::get_api_version(),
            ClientRequest::get_manifest("test", &Reference::Tag("tag".to_string())),
            ClientRequest::get_blob("test", &Digest::Sha256("1234567890abcdef".to_string())),
            ClientRequest::get_upload("test"),
            ClientRequest::get_referrers("test", &Digest::Sha256("1234567890abcdef".to_string())),
            ClientRequest::list_catalog(),
            ClientRequest::list_tags("test"),
        ];

        for request in write_actions {
            assert!(
                request.is_write(),
                "{} should be a write operation",
                request.action
            );
        }

        for request in read_actions {
            assert!(
                !request.is_write(),
                "{} should not be a write operation",
                request.action
            );
        }
    }
}
