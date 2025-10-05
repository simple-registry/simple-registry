use crate::configuration::Configuration;
use crate::registry::server::auth::{Authenticator, Authorizer};
use crate::registry::server::route::Route;
use crate::registry::server::ClientIdentity;
use crate::registry::{Error, Registry};
use hyper::http::request::Parts;
use std::sync::Arc;
use tracing::instrument;

pub struct ServerContext {
    authenticator: Arc<Authenticator>,
    authorizer: Arc<Authorizer>,
    pub registry: Registry,
}

impl ServerContext {
    pub fn new(config: &Configuration, registry: Registry) -> Result<Self, Error> {
        let authenticator = Arc::new(Authenticator::new(config)?);
        let authorizer = Arc::new(Authorizer::new(config, &registry)?);

        Ok(Self {
            authenticator,
            authorizer,
            registry,
        })
    }

    #[instrument(skip(self, parts))]
    pub async fn authenticate_request(
        &self,
        parts: &Parts,
        remote_address: Option<std::net::SocketAddr>,
    ) -> Result<ClientIdentity, Error> {
        let mut identity = self
            .authenticator
            .authenticate_request(parts, remote_address)
            .await?;
        if let Some(forwarded_for) = parts.headers.get("X-Forwarded-For") {
            if let Ok(forwarded_str) = forwarded_for.to_str() {
                if let Some(first_ip) = forwarded_str.split(',').next() {
                    identity.client_ip = Some(first_ip.trim().to_string());
                }
            }
        } else if let Some(real_ip) = parts.headers.get("X-Real-IP") {
            if let Ok(ip_str) = real_ip.to_str() {
                identity.client_ip = Some(ip_str.to_string());
            }
        }

        Ok(identity)
    }

    #[instrument(skip(self, request))]
    pub async fn authorize_request(
        &self,
        route: &Route<'_>,
        identity: &ClientIdentity,
        request: &Parts,
    ) -> Result<(), Error> {
        self.authorizer
            .authorize_request(route, identity, request, &self.registry)
            .await
    }

    pub fn is_tag_immutable(&self, namespace: &str, tag: &str) -> bool {
        self.authorizer.is_tag_immutable(namespace, tag)
    }
}
