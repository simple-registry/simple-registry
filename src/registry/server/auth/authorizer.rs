use crate::configuration::Configuration;
use crate::registry::repository::AccessPolicy;
use crate::registry::server::auth::webhook::WebhookAuthorizer;
use crate::registry::server::route::Route;
use crate::registry::server::ClientIdentity;
use crate::registry::{Error, Registry};
use hyper::http::request::Parts;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, instrument};

/// Centralized authorization component that handles all access control decisions
pub struct Authorizer {
    global_access_policy: Option<AccessPolicy>,
    global_authorization_webhook: Option<String>,
    global_immutable_tags: bool,
    global_immutable_tags_exclusions: Vec<Regex>,
    webhooks: HashMap<String, Arc<WebhookAuthorizer>>,
    repositories: HashMap<String, AuthorizerRepository>,
}

/// Repository-specific authorization configuration
struct AuthorizerRepository {
    access_policy: AccessPolicy,
    authorization_webhook: Option<String>,
    immutable_tags: bool,
    immutable_tags_exclusions: Vec<Regex>,
}

impl Authorizer {
    pub fn new(config: &Configuration, registry: &Registry) -> Result<Self, Error> {
        let global_config = &config.global;

        let global_access_policy = if global_config.access_policy.rules.is_empty() {
            None
        } else {
            Some(
                AccessPolicy::new(&global_config.access_policy).map_err(|e| {
                    Error::Internal(format!("Failed to create global access policy: {e}"))
                })?,
            )
        };

        let mut webhooks = HashMap::new();
        for (name, webhook_config) in &config.auth.webhook {
            let cache = config.cache.to_backend().map_err(|e| {
                Error::Internal(format!("Failed to create cache for webhook '{name}': {e}"))
            })?;

            let authorizer = Arc::new(
                WebhookAuthorizer::new(name.clone(), webhook_config.clone(), cache).map_err(
                    |e| Error::Internal(format!("Failed to create webhook '{name}': {e}")),
                )?,
            );
            webhooks.insert(name.clone(), authorizer);
        }

        let mut repositories = HashMap::new();
        for (name, repo_config) in &config.repository {
            let _ = registry.get_repository(name)?;

            let access_policy = AccessPolicy::new(&repo_config.access_policy).map_err(|e| {
                Error::Internal(format!(
                    "Failed to create access policy for repository '{name}': {e}"
                ))
            })?;

            let immutable_tags_exclusions = repo_config
                .immutable_tags_exclusions
                .iter()
                .filter_map(|p| match Regex::new(p) {
                    Ok(regex) => Some(regex),
                    Err(e) => {
                        error!(
                            "Invalid regex pattern '{}' in repository '{}': {}",
                            p, name, e
                        );
                        None
                    }
                })
                .collect();

            let auth_repo = AuthorizerRepository {
                access_policy,
                authorization_webhook: repo_config.authorization_webhook.clone(),
                immutable_tags: repo_config.immutable_tags,
                immutable_tags_exclusions,
            };
            repositories.insert(name.clone(), auth_repo);
        }

        let global_immutable_tags_exclusions = global_config
            .immutable_tags_exclusions
            .iter()
            .filter_map(|p| match Regex::new(p) {
                Ok(regex) => Some(regex),
                Err(e) => {
                    error!("Invalid global regex pattern '{}': {}", p, e);
                    None
                }
            })
            .collect();

        Ok(Self {
            global_access_policy,
            global_authorization_webhook: global_config.authorization_webhook.clone(),
            global_immutable_tags: global_config.immutable_tags,
            global_immutable_tags_exclusions,
            webhooks,
            repositories,
        })
    }

    #[instrument(skip(self, request, registry))]
    pub async fn authorize_request(
        &self,
        route: &Route<'_>,
        identity: &ClientIdentity,
        request: &Parts,
        registry: &Registry,
    ) -> Result<(), Error> {
        if let Some(global_policy) = &self.global_access_policy {
            debug!("Evaluating global access policy");
            let allowed = global_policy.evaluate(route, identity)?;
            if !allowed {
                log_denial("global policy", identity);
                return Err(Error::Unauthorized(
                    "Access denied by global policy".to_string(),
                ));
            }
        }

        if let Some(namespace) = route.get_namespace() {
            if let Ok(repository) = registry.get_repository_for_namespace(namespace) {
                debug!(
                    "Evaluating repository access policy for namespace: {namespace} ({})",
                    repository.name
                );

                let auth_repo = self.repositories.get(&repository.name).ok_or_else(|| {
                    Error::Internal(format!(
                        "Repository '{}' not found in authorizer",
                        repository.name
                    ))
                })?;

                let allowed = auth_repo.access_policy.evaluate(route, identity)?;
                if !allowed {
                    log_denial(
                        &format!("repository '{}' policy", repository.name),
                        identity,
                    );
                    return Err(Error::Unauthorized("Access denied".to_string()));
                }

                if let Route::PutManifest {
                    reference: crate::registry::oci::Reference::Tag(tag),
                    ..
                } = route
                {
                    if !self.is_tag_mutable(auth_repo, tag) {
                        return Err(Error::TagImmutable(format!(
                            "Tag '{tag}' is immutable and cannot be overwritten"
                        )));
                    }
                }

                let webhook_name = auth_repo
                    .authorization_webhook
                    .as_ref()
                    .filter(|name| !name.is_empty())
                    .or(self.global_authorization_webhook.as_ref());

                if let Some(webhook_name) = webhook_name {
                    debug!("Evaluating webhook authorization: {}", webhook_name);

                    let webhook = self.webhooks.get(webhook_name).ok_or_else(|| {
                        Error::Internal(format!("Webhook '{webhook_name}' not found"))
                    })?;

                    let allowed = webhook.authorize(route, identity, request).await?;
                    if !allowed {
                        log_denial(&format!("webhook '{webhook_name}'"), identity);
                        return Err(Error::Unauthorized("Access denied by webhook".to_string()));
                    }
                }

                if repository.is_pull_through() && route.is_write() {
                    return Err(Error::Unauthorized(
                        "Write operations are not supported on pull-through cache repositories"
                            .to_string(),
                    ));
                }
            } else if self.global_access_policy.is_none() {
                return Err(Error::NotFound);
            }
        } else {
            if let Some(webhook_name) = &self.global_authorization_webhook {
                debug!("Evaluating global webhook authorization: {}", webhook_name);

                let webhook = self.webhooks.get(webhook_name).ok_or_else(|| {
                    Error::Internal(format!("Webhook '{webhook_name}' not found"))
                })?;

                let allowed = webhook.authorize(route, identity, request).await?;
                if !allowed {
                    log_denial(&format!("global webhook '{webhook_name}'"), identity);
                    return Err(Error::Unauthorized("Access denied by webhook".to_string()));
                }
            }
        }

        Ok(())
    }

    fn is_tag_mutable(&self, auth_repo: &AuthorizerRepository, tag: &str) -> bool {
        let immutable = auth_repo.immutable_tags || self.global_immutable_tags;

        if !immutable {
            return true;
        }

        let exclusions = if auth_repo.immutable_tags_exclusions.is_empty() {
            &self.global_immutable_tags_exclusions
        } else {
            &auth_repo.immutable_tags_exclusions
        };

        exclusions.iter().any(|pattern| pattern.is_match(tag))
    }

    pub fn is_tag_immutable(&self, namespace: &str, tag: &str) -> bool {
        if let Some(auth_repo) = self.repositories.get(namespace) {
            !self.is_tag_mutable(auth_repo, tag)
        } else {
            self.global_immutable_tags
                && !self
                    .global_immutable_tags_exclusions
                    .iter()
                    .any(|pattern| pattern.is_match(tag))
        }
    }
}

fn log_denial(reason: &str, identity: &ClientIdentity) {
    info!("Access denied: {reason} | Identity: {identity:?}");
}
