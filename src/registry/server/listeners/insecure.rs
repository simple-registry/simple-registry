use crate::registry::server::serve_request;
use crate::registry::server::ServerContext;
use crate::registry::Error;
use arc_swap::ArcSwap;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{debug, info};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub bind_address: IpAddr,
    #[serde(default = "Config::default_port")]
    pub port: u16,
    #[serde(default = "Config::default_query_timeout")]
    pub query_timeout: u64,
    #[serde(default = "Config::default_query_timeout_grace_period")]
    pub query_timeout_grace_period: u64,
}

impl Config {
    fn default_port() -> u16 {
        8000
    }

    fn default_query_timeout() -> u64 {
        3600
    }

    fn default_query_timeout_grace_period() -> u64 {
        60
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_address: IpAddr::from(Ipv4Addr::from([0; 4])),
            port: Self::default_port(),
            query_timeout: Self::default_query_timeout(),
            query_timeout_grace_period: Self::default_query_timeout_grace_period(),
        }
    }
}

pub struct InsecureListener {
    binding_address: SocketAddr,
    context: ArcSwap<ServerContext>,
    timeouts: ArcSwap<[Duration; 2]>,
}

impl InsecureListener {
    pub fn new(server_config: &Config, context: ServerContext) -> Self {
        let binding_address = SocketAddr::new(server_config.bind_address, server_config.port);

        let timeouts = [
            Duration::from_secs(server_config.query_timeout),
            Duration::from_secs(server_config.query_timeout_grace_period),
        ];

        Self {
            binding_address,
            context: ArcSwap::from_pointee(context),
            timeouts: ArcSwap::from_pointee(timeouts),
        }
    }

    pub fn notify_config_change(&self, context: ServerContext) {
        self.context.store(Arc::new(context));
    }

    pub async fn serve(&self) -> Result<(), Error> {
        info!("Listening on {} (non-TLS)", self.binding_address);
        let listener = TcpListener::bind(self.binding_address).await?;

        loop {
            debug!("Waiting for incoming connection");
            let (tcp, remote_address) = listener.accept().await?;

            debug!("Accepted connection from {remote_address}");
            let stream = TokioIo::new(tcp);
            let context = Arc::clone(&self.context.load());
            let timeouts = Arc::clone(&self.timeouts.load());

            tokio::spawn(Box::pin(serve_request(
                stream,
                context,
                None,
                timeouts,
                remote_address,
            )));
        }
    }
}
