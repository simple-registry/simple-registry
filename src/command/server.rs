use crate::configuration::{IdentityConfig, ServerConfig};
use crate::registry::server::auth::oidc::OidcValidator;
use crate::registry::server::listeners::insecure::InsecureListener;
use crate::registry::server::listeners::tls::{ServerTlsConfig, TlsListener};
use crate::registry::server::ServerContext;
use crate::registry::Registry;
use crate::{command, configuration};
use argh::FromArgs;
use std::collections::HashMap;
use std::sync::Arc;

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
        let context = ServerContext::new(identities, registry, oidc_validators);

        let listener = match server_config {
            ServerConfig::Insecure(config) => {
                ServiceListener::Insecure(InsecureListener::new(config, context))
            }
            ServerConfig::Tls(config) => {
                ServiceListener::Secure(TlsListener::new(config, context)?)
            }
        };

        Ok(Command { listener })
    }

    pub fn notify_config_change(
        &self,
        server_config: &ServerConfig,
        identities: &HashMap<String, IdentityConfig>,
        registry: Registry,
        oidc_validators: Arc<Vec<OidcValidator>>,
    ) -> Result<(), configuration::Error> {
        let context = ServerContext::new(identities, registry, oidc_validators);

        match (&self.listener, server_config) {
            (ServiceListener::Insecure(listener), _) => listener.notify_config_change(context),
            (ServiceListener::Secure(listener), ServerConfig::Tls(config)) => {
                listener.notify_config_change(config, context)?;
            }
            _ => {}
        }

        Ok(())
    }

    pub fn notify_tls_config_change(
        &self,
        server_config: &ServerTlsConfig,
    ) -> Result<(), configuration::Error> {
        if let ServiceListener::Secure(listener) = &self.listener {
            listener.notify_tls_config_change(server_config)?;
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
