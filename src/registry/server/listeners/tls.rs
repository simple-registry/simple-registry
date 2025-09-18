use crate::configuration::{Error, ServerConfig, ServerTlsConfig};
use crate::registry;
use crate::registry::server::serve_request;
use crate::registry::server::ServerContext;
use arc_swap::ArcSwap;
use hyper_util::rt::TokioIo;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

pub struct TlsListener {
    binding_address: SocketAddr,
    tls_acceptor: ArcSwap<TlsAcceptor>,
    context: ArcSwap<ServerContext>,
}

impl TlsListener {
    pub fn new(server_config: &ServerConfig, context: ServerContext) -> Result<Self, Error> {
        let tls_config = server_config.tls.as_ref().ok_or_else(|| {
            Error::MissingExpectedTLSSection("TLS configuration is missing".to_string())
        })?;

        let binding_address = SocketAddr::new(server_config.bind_address, server_config.port);
        let tls_acceptor = ArcSwap::new(Arc::new(Self::build_tls_acceptor(tls_config)?));

        Ok(Self {
            binding_address,
            tls_acceptor,
            context: ArcSwap::new(Arc::new(context)),
        })
    }

    pub fn notify_config_change(
        &self,
        server_config: ServerConfig,
        context: ServerContext,
    ) -> Result<(), Error> {
        let tls_config = server_config.tls.ok_or_else(|| {
            Error::MissingExpectedTLSSection("TLS configuration is missing".to_string())
        })?;

        let tls_acceptor = Arc::new(Self::build_tls_acceptor(&tls_config)?);
        self.tls_acceptor.store(tls_acceptor);

        self.context.store(Arc::new(context));
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
            let context = self.context.load();
            tokio::spawn(Box::pin(serve_request(
                stream,
                context.clone(),
                peer_certificate,
            )));
        }
    }
}
