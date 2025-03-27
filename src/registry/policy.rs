use crate::registry::data_store::DataStore;
use crate::registry::policy_types::{ClientIdentity, ClientRequest};
use crate::registry::{Error, Registry, Repository};
use cel_interpreter::{Context, Program, Value};
use tracing::{debug, error, info, instrument};

impl<D: DataStore> Registry<D> {
    fn deny() -> Error {
        Error::Unauthorized("Access denied".to_string())
    }

    #[instrument(skip(self, repository, request))]
    pub fn validate_request(
        &self,
        repository: Option<&Repository>,
        request: ClientRequest,
        identity: ClientIdentity,
    ) -> Result<(), Error> {
        let Some(namespace) = request.namespace.as_ref() else {
            return Ok(());
        };

        let Some(repository) = repository else {
            return Ok(());
        };

        debug!(
            "Default allow: {} for namespace: {namespace} ({})",
            repository.access_default_allow, repository.name
        );

        if repository.access_default_allow {
            self.check_deny_policies(&request, &identity, &repository.access_rules)?;
        } else {
            self.check_allow_policies(&request, &identity, &repository.access_rules)?;
        }

        if repository.is_pull_through() && request.is_write() {
            Err(Error::Unauthorized(
                "Write operations is not supported on pull-through cache repositories".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    #[instrument(skip(self, policies))]
    fn check_deny_policies(
        &self,
        request: &ClientRequest,
        identity: &ClientIdentity,
        policies: &[Program],
    ) -> Result<(), Error> {
        if policies.is_empty() {
            debug!("No deny policies defined, allowing access");
            return Ok(());
        }

        let context = self.build_policy_context(identity, request)?;

        for policy in policies {
            let evaluation_result = policy.execute(&context).map_err(|error| {
                error!("Policy execution failed: {error}");
                Self::deny()
            })?;

            debug!("CEL program '{policy:?}' evaluates to {evaluation_result:?}");
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
        if policies.is_empty() {
            debug!("No allow policies defined, allowing access");
            return Err(Self::deny());
        }

        let context = self.build_policy_context(identity, request)?;

        for policy in policies {
            let evaluation_result = policy.execute(&context).map_err(|error| {
                error!("Policy execution failed: {error}");
                Self::deny()
            })?;

            debug!("CEL program '{policy:?}' evaluates to {evaluation_result:?}");
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
            "Default policy denied access: {request:?} for {:?}",
            identity.id
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

        debug!("Policy context (request) : {request:?}");
        context.add_variable("request", request).map_err(|error| {
            error!("Failed to add request to policy context: {error}");
            Self::deny()
        })?;

        debug!("Policy context (identity) : {identity:?}");
        context.add_variable("identity", identity).map_err(|e| {
            error!("Failed to add identity to policy context: {e}");
            Self::deny()
        })?;

        Ok(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{
        CacheStoreConfig, RepositoryAccessPolicyConfig, RepositoryConfig,
        RepositoryRetentionPolicyConfig,
    };
    use crate::registry::cache_store::CacheStore;
    use crate::registry::oci_types::Reference;
    use crate::registry::test_utils::create_test_fs_backend;
    use std::sync::Arc;

    fn create_default_deny_repo(rules: Vec<String>) -> Repository {
        let config = RepositoryConfig {
            retention_policy: RepositoryRetentionPolicyConfig::default(),
            access_policy: RepositoryAccessPolicyConfig {
                default_allow: false,
                rules,
            },
            ..RepositoryConfig::default()
        };

        let token_cache = Arc::new(CacheStore::new(CacheStoreConfig::default()).unwrap());
        Repository::new(config, "policy-deny-repo".to_string(), &token_cache).unwrap()
    }

    fn create_default_allow_repo(rules: Vec<String>) -> Repository {
        let config = RepositoryConfig {
            access_policy: RepositoryAccessPolicyConfig {
                default_allow: true,
                rules,
            },
            retention_policy: RepositoryRetentionPolicyConfig::default(),
            ..RepositoryConfig::default()
        };

        let token_cache = Arc::new(CacheStore::new(CacheStoreConfig::default()).unwrap());
        Repository::new(config, "policy-allow-repo".to_string(), &token_cache).unwrap()
    }

    #[tokio::test]
    async fn test_validate_request_no_namespace() {
        let (registry, _) = create_test_fs_backend().await;
        let request = ClientRequest::list_catalog();
        let identity = ClientIdentity::default();

        assert!(registry.validate_request(None, request, identity).is_ok());

        // TODO: implement global rules for non-namespaced queries.
    }

    #[tokio::test]
    async fn test_validate_request_no_repository() {
        let (registry, _) = create_test_fs_backend().await;
        let reference = Reference::Tag("latest".to_string());

        let request = ClientRequest::get_manifest("policy-deny-repo", &reference);
        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };

        assert!(registry.validate_request(None, request, identity).is_ok());

        let request = ClientRequest::get_manifest("policy-deny-repo", &reference);
        let identity = ClientIdentity {
            username: Some("admin".to_string()),
            ..ClientIdentity::default()
        };

        assert!(registry.validate_request(None, request, identity).is_ok());
    }

    #[tokio::test]
    async fn test_validate_request_default_allow_no_rules() {
        let (mut registry, _) = create_test_fs_backend().await;
        let reference = Reference::Tag("latest".to_string());

        registry.repositories.insert(
            "policy-allow-repo".to_string(),
            create_default_allow_repo(Vec::new()),
        );

        let request = ClientRequest::get_manifest("policy-allow-repo", &reference);
        let identity = ClientIdentity {
            username: Some("whatever-identity".to_string()),
            ..ClientIdentity::default()
        };
        let repository = registry.validate_namespace("test-repo").unwrap();

        assert!(registry
            .validate_request(Some(repository), request, identity)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_request_default_deny_no_rules() {
        let (mut registry, _) = create_test_fs_backend().await;
        let reference = Reference::Tag("latest".to_string());

        registry.repositories.insert(
            "policy-deny-repo".to_string(),
            create_default_deny_repo(Vec::new()),
        );

        let request = ClientRequest::get_manifest("policy-deny-repo", &reference);
        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };
        let repository = registry.validate_namespace("policy-deny-repo").unwrap();

        assert!(registry
            .validate_request(Some(repository), request, identity)
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_request_default_allow() {
        let (mut registry, _) = create_test_fs_backend().await;
        let reference = Reference::Tag("latest".to_string());

        let rules = vec!["identity.username == 'forbidden'".to_string()];
        registry.repositories.insert(
            "policy-allow-repo".to_string(),
            create_default_allow_repo(rules),
        );

        let request = ClientRequest::get_manifest("policy-allow-repo", &reference);
        let identity = ClientIdentity {
            username: Some("whatever-identity".to_string()),
            ..ClientIdentity::default()
        };
        let repository = registry.validate_namespace("policy-allow-repo").unwrap();

        assert!(registry
            .validate_request(Some(repository), request, identity)
            .is_ok());

        let request = ClientRequest::get_manifest("policy-allow-repo", &reference);
        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };
        let repository = registry.validate_namespace("policy-allow-repo").unwrap();

        assert!(registry
            .validate_request(Some(repository), request, identity)
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_request_default_deny() {
        let (mut registry, _) = create_test_fs_backend().await;
        let reference = Reference::Tag("latest".to_string());

        let rules = vec!["identity.username == 'admin'".to_string()];
        registry.repositories.insert(
            "policy-deny-repo".to_string(),
            create_default_deny_repo(rules),
        );

        let request = ClientRequest::get_manifest("policy-deny-repo", &reference);
        let identity = ClientIdentity {
            username: Some("admin".to_string()),
            ..ClientIdentity::default()
        };
        let repository = registry.validate_namespace("policy-deny-repo").unwrap();

        assert!(registry
            .validate_request(Some(repository), request, identity)
            .is_ok());

        let request = ClientRequest::get_manifest("policy-deny-repo", &reference);
        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };
        let repository = registry.validate_namespace("policy-deny-repo").unwrap();

        assert!(registry
            .validate_request(Some(repository), request, identity)
            .is_err());
    }
}
