use crate::cmd::server::serve_request;
use crate::cmd::CommandError;
use crate::configuration::Configuration;
use crate::policy::ClientIdentity;
use crate::registry::Registry;
use arc_swap::ArcSwap;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{debug, info};

pub struct InsecureListener {
    binding_address: SocketAddr,
    timeouts: ArcSwap<Vec<Duration>>,
    registry: ArcSwap<Registry>,
}

impl InsecureListener {
    pub fn try_from_config(config: &Configuration) -> Result<Self, CommandError> {
        let binding_address = SocketAddr::new(config.server.bind_address, config.server.port);
        let timeouts = ArcSwap::new(Arc::new(vec![
            Duration::from_secs(config.server.query_timeout),
            Duration::from_secs(config.server.query_timeout_grace_period),
        ]));
        let registry = ArcSwap::new(Arc::new(Registry::try_from_config(config)?));

        Ok(Self {
            binding_address,
            timeouts,
            registry,
        })
    }

    pub fn notify_config_change(&self, config: &Configuration) -> Result<(), CommandError> {
        let timeouts = Arc::new(vec![
            Duration::from_secs(config.server.query_timeout),
            Duration::from_secs(config.server.query_timeout_grace_period),
        ]);
        let registry = Arc::new(Registry::try_from_config(config)?);

        self.timeouts.store(timeouts);
        self.registry.store(registry);

        Ok(())
    }

    pub async fn serve(&self) -> Result<(), CommandError> {
        info!("Listening on {} (non-TLS)", self.binding_address);
        let listener = TcpListener::bind(self.binding_address).await?;

        loop {
            debug!("Waiting for incoming connection");
            let (tcp, remote_address) = listener.accept().await?;

            debug!("Accepted connection from {:?}", remote_address);
            let stream = TokioIo::new(tcp);
            let timeouts = self.timeouts.load();
            let registry = self.registry.load();
            serve_request(
                stream,
                timeouts.clone(),
                registry.clone(),
                ClientIdentity::new(),
            )
            .await;
        }
    }
}
