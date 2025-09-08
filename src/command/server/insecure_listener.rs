use crate::command;
use crate::command::server::{serve_request, ServerContext};
use crate::configuration::ServerConfig;
use crate::registry::repository::access_policy::ClientIdentity;
use arc_swap::ArcSwap;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, info};

pub struct InsecureListener {
    binding_address: SocketAddr,
    context: ArcSwap<ServerContext>,
}

impl InsecureListener {
    pub fn new(server_config: &ServerConfig, context: ServerContext) -> Self {
        let binding_address = SocketAddr::new(server_config.bind_address, server_config.port);

        Self {
            binding_address,
            context: ArcSwap::new(Arc::new(context)),
        }
    }

    pub fn notify_config_change(&self, context: ServerContext) {
        self.context.store(Arc::new(context));
    }

    pub async fn serve(&self) -> Result<(), command::Error> {
        info!("Listening on {} (non-TLS)", self.binding_address);
        let listener = TcpListener::bind(self.binding_address).await?;

        loop {
            debug!("Waiting for incoming connection");
            let (tcp, remote_address) = listener.accept().await?;

            debug!("Accepted connection from {remote_address}");
            let stream = TokioIo::new(tcp);
            let context = self.context.load();

            tokio::spawn(Box::pin(serve_request(
                stream,
                context.clone(),
                ClientIdentity::default(),
            )));
        }
    }
}
