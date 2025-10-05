use crate::command::server::serve_request;
use crate::command::server::ServerContext;
use crate::configuration::Error;
use crate::registry;
use arc_swap::ArcSwap;
use hyper_util::rt::TokioIo;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
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
    pub tls: ServerTlsConfig,
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

#[derive(Clone, Debug, Deserialize)]
pub struct ServerTlsConfig {
    pub server_certificate_bundle: String,
    pub server_private_key: String,
    pub client_ca_bundle: Option<String>,
}

pub struct TlsListener {
    binding_address: SocketAddr,
    tls_acceptor: ArcSwap<TlsAcceptor>,
    context: ArcSwap<ServerContext>,
    timeouts: ArcSwap<[Duration; 2]>,
}

impl TlsListener {
    pub fn new(config: &Config, context: ServerContext) -> Result<Self, Error> {
        let binding_address = SocketAddr::new(config.bind_address, config.port);
        let tls_acceptor = ArcSwap::from_pointee(Self::build_tls_acceptor(&config.tls)?);
        let timeouts = [
            Duration::from_secs(config.query_timeout),
            Duration::from_secs(config.query_timeout_grace_period),
        ];

        Ok(Self {
            binding_address,
            tls_acceptor,
            context: ArcSwap::from_pointee(context),
            timeouts: ArcSwap::from_pointee(timeouts),
        })
    }

    pub fn notify_config_change(
        &self,
        config: &Config,
        context: ServerContext,
    ) -> Result<(), Error> {
        let acceptor = Arc::new(Self::build_tls_acceptor(&config.tls)?);
        self.tls_acceptor.store(acceptor);

        let timeouts = [
            Duration::from_secs(config.query_timeout),
            Duration::from_secs(config.query_timeout_grace_period),
        ];

        self.timeouts.store(Arc::new(timeouts));
        self.context.store(Arc::new(context));

        Ok(())
    }

    pub fn notify_tls_config_change(&self, config: &ServerTlsConfig) -> Result<(), Error> {
        let acceptor = Arc::new(Self::build_tls_acceptor(config)?);
        self.tls_acceptor.store(acceptor);

        Ok(())
    }

    fn build_tls_acceptor(tls_config: &ServerTlsConfig) -> Result<TlsAcceptor, Error> {
        debug!("Detected TLS configuration");
        let server_certs = CertificateDer::pem_file_iter(&tls_config.server_certificate_bundle)?
            .collect::<Result<_, _>>()?;
        let server_key = PrivateKeyDer::from_pem_file(&tls_config.server_private_key)?;

        let server_config = if let Some(client_ca_bundle) = tls_config.client_ca_bundle.as_ref() {
            debug!("Client CA bundle detected (will serve with TLS client authentication)");
            let client_certs: Vec<CertificateDer> =
                CertificateDer::pem_file_iter(client_ca_bundle)?.collect::<Result<_, _>>()?;

            let mut client_cert_store = RootCertStore::empty();
            for client_cert in client_certs {
                client_cert_store.add(client_cert)?;
            }

            let client_cert_verifier = WebPkiClientVerifier::builder(Arc::new(client_cert_store))
                .allow_unauthenticated()
                .build()?;

            rustls::ServerConfig::builder()
                .with_client_cert_verifier(client_cert_verifier)
                .with_single_cert(server_certs, server_key)?
        } else {
            debug!("No client CA bundle detected (will serve without TLS client authentication)");

            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(server_certs, server_key)?
        };

        let server_config = Arc::new(server_config);
        let tls_acceptor = TlsAcceptor::from(server_config);
        Ok(tls_acceptor)
    }

    pub async fn serve(&self) -> Result<(), registry::Error> {
        info!("Listening on {} (mTLS)", self.binding_address);
        let listener = TcpListener::bind(self.binding_address).await?;

        loop {
            let (tcp, remote_address) = listener.accept().await?;

            let tls_acceptor = self.tls_acceptor.load();
            let tls_stream = tls_acceptor.accept(tcp).await;
            drop(tls_acceptor);

            let Ok(tls) = tls_stream else {
                continue;
            };

            let (_, session) = tls.get_ref();
            let peer_certificate = session
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|cert| cert.to_vec());

            debug!("Accepted connection from {remote_address}");
            let stream = TokioIo::new(tls);
            let context = Arc::clone(&self.context.load());
            let timeouts = Arc::clone(&self.timeouts.load());

            tokio::spawn(Box::pin(serve_request(
                stream,
                context,
                peer_certificate,
                timeouts,
                remote_address,
            )));
        }
    }
}
