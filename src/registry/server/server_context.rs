use crate::configuration::Configuration;
use crate::registry::server::auth::Authenticator;
use crate::registry::server::ClientIdentity;
use crate::registry::{Error, Registry};
use hyper::http::request::Parts;
use std::sync::Arc;
use tracing::instrument;

pub struct ServerContext {
    authenticator: Arc<Authenticator>,
    pub registry: Registry,
}

impl ServerContext {
    pub fn new(config: &Configuration, registry: Registry) -> Result<Self, Error> {
        let authenticator = Arc::new(Authenticator::new(config)?);

        Ok(Self {
            authenticator,
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
}
