use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use argh::FromArgs;
use tokio::time::timeout;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::warn;

use crate::{
    command::{
        bootstrap,
        server::{
            ServerContext,
            error::Error,
            listeners::{insecure::InsecureListener, tls::TlsListener},
        },
    },
    configuration::{Configuration, ServerConfig, listeners::ServerTlsConfig},
    jobs::Queue,
    jobs::store::{QueueDepthRefresh, queue_depth_refresh_loop},
};

mod notifier;
pub mod setup;

pub enum ServiceListener {
    Insecure(InsecureListener),
    Secure(TlsListener),
}

impl ServiceListener {
    async fn serve(&self) -> Result<(), Error> {
        match self {
            Self::Insecure(listener) => listener.serve().await,
            Self::Secure(listener) => listener.serve().await,
        }
    }

    async fn shutdown(&self) {
        match self {
            Self::Insecure(listener) => listener.shutdown().await,
            Self::Secure(listener) => listener.shutdown().await,
        }
    }
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(
    subcommand,
    name = "server",
    description = "Run the registry listeners"
)]
pub struct Options {}

/// Background tickers, one per queue, publishing the job-queue depth gauges on
/// `/metrics`. They read `refresh` on every tick, so a reload swaps the store
/// and cadence under them rather than leaving them on the boot-time ones.
struct PendingRefreshTask {
    refresh: Arc<ArcSwap<QueueDepthRefresh>>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
}

pub struct Command {
    listener: ServiceListener,
    /// `None` when `[global.job_queue]` is not configured.
    pending_refresh: Option<PendingRefreshTask>,
}

impl Command {
    pub async fn new(config: &Configuration) -> Result<Command, Error> {
        let auth_cache = bootstrap::auth_cache(&config.cache)?;
        let (registry, pending) = setup::build_registry(config, &auth_cache).await?;
        let context = ServerContext::new(config, &auth_cache, registry)?;

        let listener = match &config.server {
            ServerConfig::Insecure(server_config) => {
                ServiceListener::Insecure(InsecureListener::new(server_config, context))
            }
            ServerConfig::Tls(server_config) => {
                ServiceListener::Secure(TlsListener::new(server_config, context)?)
            }
        };

        let pending_refresh = pending.map(|refresh| {
            let refresh = Arc::new(ArcSwap::from_pointee(refresh));
            let shutdown = CancellationToken::new();
            let tracker = TaskTracker::new();
            // Queue depth is read off the shared store, so the replication
            // gauges are published here even though `angos worker` drains it.
            for queue in [Queue::Cache, Queue::Replication] {
                tracker.spawn(queue_depth_refresh_loop(
                    Arc::clone(&refresh),
                    queue,
                    shutdown.clone(),
                ));
            }
            PendingRefreshTask {
                refresh,
                shutdown,
                tracker,
            }
        });

        Ok(Command {
            listener,
            pending_refresh,
        })
    }

    pub async fn notify_config_change(&self, config: &Configuration) -> Result<(), Error> {
        let auth_cache = bootstrap::auth_cache(&config.cache)?;
        let (registry, pending) = setup::build_registry(config, &auth_cache).await?;

        match (&self.pending_refresh, pending) {
            // The tickers read this on their next tick, so the gauges describe
            // the store the reloaded registry enqueues into.
            (Some(task), Some(refresh)) => task.refresh.store(Arc::new(refresh)),
            (Some(_), None) | (None, Some(_)) => warn!(
                "Enabling or disabling [global.job_queue] at runtime is not supported; \
                 restart angos for the new configuration to take effect."
            ),
            (None, None) => {}
        }

        let context = ServerContext::new(config, &auth_cache, registry)?;

        match (&self.listener, &config.server) {
            (ServiceListener::Insecure(listener), ServerConfig::Insecure(server_config)) => {
                listener.notify_config_change(server_config, context);
            }
            (ServiceListener::Insecure(listener), ServerConfig::Tls(_)) => {
                warn!(
                    "Listener type transition from insecure to TLS is not supported at runtime; \
                     restart the server to apply the new listener configuration. \
                     Non-listener changes will still be applied."
                );
                listener.store_context(context);
            }
            (ServiceListener::Secure(listener), ServerConfig::Tls(server_config)) => {
                listener.notify_config_change(server_config, context)?;
            }
            (ServiceListener::Secure(_), ServerConfig::Insecure(_)) => {
                warn!(
                    "Listener type transition from TLS to insecure is not supported at runtime; \
                     restart the server to apply the new listener configuration."
                );
            }
        }

        Ok(())
    }

    pub fn notify_tls_config_change(&self, server_config: &ServerTlsConfig) -> Result<(), Error> {
        if let ServiceListener::Secure(listener) = &self.listener {
            listener.notify_tls_config_change(server_config)?;
        }

        Ok(())
    }

    #[cfg(test)]
    pub fn as_insecure(&self) -> Option<&InsecureListener> {
        match &self.listener {
            ServiceListener::Insecure(listener) => Some(listener),
            ServiceListener::Secure(_) => None,
        }
    }

    pub async fn shutdown_with_timeout(&self, grace: Duration) {
        self.listener.shutdown().await;

        if let Some(refresh) = &self.pending_refresh {
            refresh.shutdown.cancel();
            refresh.tracker.close();
            if timeout(grace, refresh.tracker.wait()).await.is_err() {
                warn!("Pending-gauge ticker did not stop within shutdown grace period");
            }
        }
    }

    pub async fn run(&self) -> Result<(), Error> {
        self.listener.serve().await
    }
}

#[cfg(test)]
mod tests;
