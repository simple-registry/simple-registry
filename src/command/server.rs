use crate::configuration::{Configuration, ServerConfig};
use crate::registry::server::listeners::insecure::InsecureListener;
use crate::registry::server::listeners::tls::{ServerTlsConfig, TlsListener};
use crate::registry::server::ServerContext;
use crate::registry::Registry;
use crate::{command, configuration};
use argh::FromArgs;

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
        config: &Configuration,
        registry: Registry,
    ) -> Result<Command, configuration::Error> {
        let context = ServerContext::new(config, registry).map_err(|e| {
            configuration::Error::Http(format!("Failed to create server context: {e}"))
        })?;

        let listener = match &config.server {
            ServerConfig::Insecure(server_config) => {
                ServiceListener::Insecure(InsecureListener::new(server_config, context))
            }
            ServerConfig::Tls(server_config) => {
                ServiceListener::Secure(TlsListener::new(server_config, context)?)
            }
        };

        Ok(Command { listener })
    }

    pub fn notify_config_change(
        &self,
        config: &Configuration,
        registry: Registry,
    ) -> Result<(), configuration::Error> {
        let context = ServerContext::new(config, registry).map_err(|e| {
            configuration::Error::Http(format!("Failed to create server context: {e}"))
        })?;

        match (&self.listener, &config.server) {
            (ServiceListener::Insecure(listener), _) => listener.notify_config_change(context),
            (ServiceListener::Secure(listener), ServerConfig::Tls(server_config)) => {
                listener.notify_config_change(server_config, context)?;
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
