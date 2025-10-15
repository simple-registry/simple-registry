use crate::command::server::error::Error;
use crate::command::server::listeners::{accept, build_listener};
use crate::command::server::serve_request;
use crate::command::server::ServerContext;
use arc_swap::ArcSwap;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
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
        let listener = build_listener(self.binding_address).await?;

        loop {
            debug!("Waiting for incoming connection");
            let (tcp, remote_address) = accept(&listener).await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::server::server_context::tests::create_test_server_context;
    use std::net::Ipv6Addr;

    #[test]
    fn test_config_default_values() {
        let config = Config::default();

        assert_eq!(config.port, 8000);
        assert_eq!(config.query_timeout, 3600);
        assert_eq!(config.query_timeout_grace_period, 60);
        assert_eq!(config.bind_address, IpAddr::from(Ipv4Addr::from([0; 4])));
    }

    #[test]
    fn test_config_custom_values() {
        let toml = r#"
            bind_address = "192.168.1.100"
            port = 9000
            query_timeout = 7200
            query_timeout_grace_period = 120
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.port, 9000);
        assert_eq!(config.query_timeout, 7200);
        assert_eq!(config.query_timeout_grace_period, 120);
        assert_eq!(
            config.bind_address,
            "192.168.1.100".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_config_partial_defaults() {
        let toml = r#"
            bind_address = "10.0.0.1"
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.port, 8000);
        assert_eq!(config.query_timeout, 3600);
        assert_eq!(config.query_timeout_grace_period, 60);
    }

    #[test]
    fn test_config_ipv6_address() {
        let toml = r#"
            bind_address = "::1"
            port = 8443
        "#;

        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.bind_address, IpAddr::from(Ipv6Addr::LOCALHOST));
        assert_eq!(config.port, 8443);
    }

    #[test]
    fn test_insecure_listener_new() {
        let config = Config {
            bind_address: "127.0.0.1".parse().unwrap(),
            port: 8080,
            query_timeout: 1800,
            query_timeout_grace_period: 30,
        };

        let context = create_test_server_context();
        let listener = InsecureListener::new(&config, context);

        assert_eq!(
            listener.binding_address,
            SocketAddr::from(([127, 0, 0, 1], 8080))
        );
    }

    #[test]
    fn test_insecure_listener_new_with_ipv6() {
        let config = Config {
            bind_address: "::1".parse().unwrap(),
            port: 9000,
            query_timeout: 3600,
            query_timeout_grace_period: 60,
        };

        let context = create_test_server_context();
        let listener = InsecureListener::new(&config, context);

        assert_eq!(
            listener.binding_address.ip(),
            "::1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(listener.binding_address.port(), 9000);
    }

    #[test]
    fn test_insecure_listener_notify_config_change() {
        let config = Config::default();
        let context1 = create_test_server_context();
        let listener = InsecureListener::new(&config, context1);

        let context2 = create_test_server_context();
        listener.notify_config_change(context2);
    }

    #[test]
    fn test_insecure_listener_timeouts_initialization() {
        let config = Config {
            bind_address: "127.0.0.1".parse().unwrap(),
            port: 8080,
            query_timeout: 5000,
            query_timeout_grace_period: 100,
        };

        let context = create_test_server_context();
        let listener = InsecureListener::new(&config, context);

        let timeouts = listener.timeouts.load();
        assert_eq!(timeouts[0], Duration::from_secs(5000));
        assert_eq!(timeouts[1], Duration::from_secs(100));
    }

    #[test]
    fn test_insecure_listener_with_zero_port() {
        let config = Config {
            bind_address: "127.0.0.1".parse().unwrap(),
            port: 0,
            query_timeout: 3600,
            query_timeout_grace_period: 60,
        };

        let context = create_test_server_context();
        let listener = InsecureListener::new(&config, context);

        assert_eq!(listener.binding_address.port(), 0);
    }

    #[test]
    fn test_insecure_listener_multiple_config_changes() {
        let config = Config::default();
        let context1 = create_test_server_context();
        let listener = InsecureListener::new(&config, context1);

        for _ in 0..5 {
            let context = create_test_server_context();
            listener.notify_config_change(context);
        }
    }
}
