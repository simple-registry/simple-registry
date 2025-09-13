use crate::configuration::{IdentityConfig, ServerConfig};
use crate::registry::server::auth::oidc::OidcValidator;
use crate::registry::server::listeners::insecure::InsecureListener;
use crate::registry::server::listeners::tls::TlsListener;
use crate::registry::server::ServerContext;
use crate::registry::Registry;
use crate::{command, configuration};
use argh::FromArgs;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub enum ServiceListener {
    Insecure(InsecureListener),
    Secure(TlsListener),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(
    subcommand,
    name = "server",
    description = "Run the registry listeners"
)]
pub struct Options {}

pub struct Command {
    listener: ServiceListener,
}

impl Command {
    pub fn new(
        server_config: &ServerConfig,
        identities: &HashMap<String, IdentityConfig>,
        registry: Registry,
        oidc_validators: Arc<Vec<OidcValidator>>,
    ) -> Result<Command, configuration::Error> {
        let timeouts = vec![
            Duration::from_secs(server_config.query_timeout),
            Duration::from_secs(server_config.query_timeout_grace_period),
        ];
        let context = ServerContext::new(identities, timeouts, registry, oidc_validators);

        let listener = if server_config.tls.is_some() {
            ServiceListener::Secure(TlsListener::new(server_config, context)?)
        } else {
            ServiceListener::Insecure(InsecureListener::new(server_config, context))
        };

        Ok(Command { listener })
    }

    pub fn notify_config_change(
        &self,
        server_config: ServerConfig,
        identities: &HashMap<String, IdentityConfig>,
        registry: Registry,
        oidc_validators: Arc<Vec<OidcValidator>>,
    ) -> Result<(), configuration::Error> {
        let timeouts = vec![
            Duration::from_secs(server_config.query_timeout),
            Duration::from_secs(server_config.query_timeout_grace_period),
        ];
        let context = ServerContext::new(identities, timeouts, registry, oidc_validators);

        match &self.listener {
            ServiceListener::Insecure(listener) => listener.notify_config_change(context),
            ServiceListener::Secure(listener) => {
                listener.notify_config_change(server_config, context)?;
            }
        }

        Ok(())
    }

    pub async fn run(&self) -> Result<(), command::Error> {
        match &self.listener {
            ServiceListener::Insecure(listener) => listener.serve().await?,
            ServiceListener::Secure(listener) => listener.serve().await?,
        }

        Ok(())
    }
}
