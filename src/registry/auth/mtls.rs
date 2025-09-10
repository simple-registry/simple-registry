use super::{AuthMiddleware, AuthResult};
use crate::registry::server::{ClientCertificate, ClientIdentity};
use crate::registry::Error;
use async_trait::async_trait;
use hyper::body::Incoming;
use hyper::Request;
use std::sync::Arc;
use tracing::{debug, instrument};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// Extension type for passing peer certificate data from TLS layer
#[derive(Clone)]
pub struct PeerCertificate(pub Arc<Vec<u8>>);

/// mTLS certificate-based authentication validator
///
/// Note: Certificate validation (expiry, CA trust chain, etc.) is performed by the TLS layer
/// during the handshake. This middleware only extracts identity from already-validated certificates.
/// Invalid certificates are rejected at the TLS layer before reaching this middleware.
pub struct MtlsValidator;

impl MtlsValidator {
    pub fn new() -> Self {
        Self
    }

    /// Extract certificate identity information from X509 certificate
    #[instrument(skip(cert))]
    fn extract_certificate_identity(cert: &X509Certificate) -> Result<ClientCertificate, Error> {
        let subject = cert.subject();

        let organizations = subject
            .iter_organization()
            .map(|o| o.as_str().map(String::from))
            .collect::<Result<Vec<String>, _>>()
            .map_err(|_| {
                Error::Unauthorized("Unable to parse certificate organizations".to_string())
            })?;

        let common_names = subject
            .iter_common_name()
            .map(|o| o.as_str().map(String::from))
            .collect::<Result<Vec<String>, _>>()
            .map_err(|_| {
                Error::Unauthorized("Unable to parse certificate common names".to_string())
            })?;

        Ok(ClientCertificate {
            organizations,
            common_names,
        })
    }
}

impl Default for MtlsValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthMiddleware for MtlsValidator {
    #[instrument(skip(self, request, identity))]
    async fn authenticate(
        &self,
        request: &Request<Incoming>,
        identity: &mut ClientIdentity,
    ) -> Result<AuthResult, Error> {
        let Some(peer_cert) = request.extensions().get::<PeerCertificate>() else {
            return Ok(AuthResult::NoCredentials);
        };

        let (_, cert) = X509Certificate::from_der(&peer_cert.0).map_err(|e| {
            debug!("Failed to parse client certificate: {:?}", e);
            Error::Unauthorized(format!("Malformed client certificate: {e:?}"))
        })?;

        debug!("Extracting identity from client certificate");
        let cert_info = Self::extract_certificate_identity(&cert)
            .inspect_err(|e| debug!("Failed to extract identity from certificate: {e}"))?;

        identity.certificate = cert_info;
        Ok(AuthResult::Authenticated)
    }
}
