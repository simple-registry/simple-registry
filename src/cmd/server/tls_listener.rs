use crate::cmd::server::serve_request;
use crate::cmd::CommandError;
use crate::configuration::{Configuration, ServerTlsConfig};
use crate::policy::ClientIdentity;
use crate::registry::Registry;
use arc_swap::ArcSwap;
use hyper_util::rt::TokioIo;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fmt::Display;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

pub struct TlsListener {
    binding_address: SocketAddr,
    timeouts: ArcSwap<Vec<Duration>>,
    tls_acceptor: ArcSwap<TlsAcceptor>,
    registry: ArcSwap<Registry>,
}

impl TlsListener {
    pub fn try_from_config(config: &Configuration) -> Result<Self, CommandError> {
        let tls_config = config.server.tls.as_ref().ok_or_else(|| {
            CommandError::ConfigurationError("TLS configuration is missing".to_string())
        })?;

        let binding_address = SocketAddr::new(config.server.bind_address, config.server.port);
        let timeouts = ArcSwap::new(Arc::new(vec![
            Duration::from_secs(config.server.query_timeout),
            Duration::from_secs(config.server.query_timeout_grace_period),
        ]));
        let tls_acceptor = ArcSwap::new(Arc::new(Self::build_tls_acceptor(tls_config)?));
        let registry = ArcSwap::new(Arc::new(Registry::try_from_config(config)?));

        Ok(Self {
            binding_address,
            timeouts,
            tls_acceptor,
            registry,
        })
    }

    pub fn notify_config_change(&self, config: &Configuration) -> Result<(), CommandError> {
        let tls_config = config.server.tls.as_ref().ok_or_else(|| {
            CommandError::ConfigurationError("TLS configuration is missing".to_string())
        })?;

        let timeouts = Arc::new(vec![
            Duration::from_secs(config.server.query_timeout),
            Duration::from_secs(config.server.query_timeout_grace_period),
        ]);
        let tls_acceptor = Arc::new(Self::build_tls_acceptor(tls_config)?);
        let registry = Arc::new(Registry::try_from_config(config)?);

        self.timeouts.store(timeouts);
        self.tls_acceptor.store(tls_acceptor);
        self.registry.store(registry);

        Ok(())
    }

    fn build_tls_acceptor(tls_config: &ServerTlsConfig) -> Result<TlsAcceptor, CommandError> {
        debug!("Detected TLS configuration");
        let server_certs =
            Self::load_certificate_bundle(tls_config.server_certificate_bundle.as_str())?;
        let server_key = Self::load_private_key(tls_config.server_private_key.as_str())?;

        let server_config = match tls_config.client_ca_bundle.as_ref() {
            Some(client_ca_bundle) => {
                debug!("Client CA bundle detected (will serve with TLS client authentication)");
                let client_cert = Self::load_certificate_bundle(client_ca_bundle)?;
                let client_cert_store = Self::build_root_store(client_cert)?;

                let client_cert_verifier =
                    WebPkiClientVerifier::builder(Arc::new(client_cert_store))
                        .allow_unauthenticated()
                        .build()?;

                rustls::ServerConfig::builder()
                    .with_client_cert_verifier(client_cert_verifier)
                    .with_single_cert(server_certs, server_key)?
            }
            None => {
                debug!(
                    "No client CA bundle detected (will serve without TLS client authentication)"
                );

                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(server_certs, server_key)?
            }
        };

        let server_config = Arc::new(server_config);
        let tls_acceptor = TlsAcceptor::from(server_config);
        Ok(tls_acceptor)
    }

    fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, CommandError> {
        info!("Loading private key from {}", path);
        let key = PrivateKeyDer::from_pem_file(path)?;

        Ok(key)
    }

    fn load_certificate_bundle<T: AsRef<Path> + Display>(
        path: T,
    ) -> Result<Vec<CertificateDer<'static>>, CommandError> {
        info!("Loading certificate bundle from {}", path);
        let certs = CertificateDer::pem_file_iter(path)?.collect::<Result<Vec<_>, _>>()?;

        Ok(certs)
    }

    fn build_root_store(certs: Vec<CertificateDer>) -> Result<RootCertStore, CommandError> {
        let mut root_store = RootCertStore::empty();
        for cert in certs {
            root_store.add(cert)?;
        }
        Ok(root_store)
    }

    pub async fn serve(&self) -> Result<(), CommandError> {
        info!("Listening on {} (mTLS)", self.binding_address);
        let listener = TcpListener::bind(self.binding_address).await?;

        loop {
            let (tcp, remote_address) = listener.accept().await?;

            let tls_acceptor = self.tls_acceptor.load();
            let tls_stream = tls_acceptor.accept(tcp).await;
            drop(tls_acceptor);

            if let Ok(tls) = tls_stream {
                let (_, session) = tls.get_ref();

                let identity = session
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .and_then(|cert| match X509Certificate::from_der(cert).ok() {
                        Some((_, cert)) => ClientIdentity::from_cert(&cert).ok(),
                        None => None,
                    });

                debug!("Accepted connection from {:?}", remote_address);
                let stream = TokioIo::new(tls);
                let timeouts = self.timeouts.load();
                let registry = self.registry.load();
                serve_request(
                    stream,
                    timeouts.clone(),
                    registry.clone(),
                    identity.unwrap_or_default(),
                )
                .await;
            }
        }
    }
}
