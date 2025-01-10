use crate::registry::Error;
use serde::Serialize;
use tracing::instrument;
use x509_parser::certificate::X509Certificate;

#[derive(Clone, Debug, Default, Serialize)]
pub struct ClientIdentity {
    pub id: Option<String>,
    pub username: Option<String>,
    pub certificate: CELIdentityCertificate,
}

impl ClientIdentity {
    #[instrument(skip(cert))]
    pub fn from_cert(cert: &X509Certificate) -> Result<Self, Error> {
        let subject = cert.subject();
        let organizations = subject
            .iter_organization()
            .map(|o| o.as_str().map(String::from))
            .collect::<Result<Vec<String>, _>>()
            .map_err(|_| {
                Error::Unauthorized(Some("Unable to parse provided certificate".to_string()))
            })?;
        let common_names = subject
            .iter_common_name()
            .map(|o| o.as_str().map(String::from))
            .collect::<Result<Vec<String>, _>>()
            .map_err(|_| {
                Error::Unauthorized(Some("Unable to parse provided certificate".to_string()))
            })?;

        let certificate = CELIdentityCertificate {
            organizations,
            common_names,
        };

        Ok(Self {
            id: None,
            username: None,
            certificate,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CELIdentityCertificate {
    pub organizations: Vec<String>,
    pub common_names: Vec<String>,
}
