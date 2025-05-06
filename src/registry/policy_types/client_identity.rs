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
            .map_err(|_| Error::Unauthorized("Unable to parse provided certificate".to_string()))?;
        let common_names = subject
            .iter_common_name()
            .map(|o| o.as_str().map(String::from))
            .collect::<Result<Vec<String>, _>>()
            .map_err(|_| Error::Unauthorized("Unable to parse provided certificate".to_string()))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::pem::Pem;
    use x509_parser::prelude::FromDer;

    #[test]
    fn test_client_identity_from_cert() {
        let cert_pem = r"-----BEGIN CERTIFICATE-----
MIIDfjCCAmagAwIBAgIUaW13SK9b9NpqZDdhlUOm1PbFPfwwDQYJKoZIhvcNAQEL
BQAwXDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRcwFQYDVQQHDA5TYW4gRnJh
bmNpc2NvczETMBEGA1UECgwKTXkgQ29tcGFueTESMBAGA1UEAwwJQ2xpZW50IENB
MB4XDTI1MDEwNjEwMjAwNVoXDTI2MDEwNjEwMjAwNVowUjELMAkGA1UEBhMCTFUx
CzAJBgNVBAgMAkxVMRIwEAYDVQQHDAlIb2xsZXJpY2gxDzANBgNVBAoMBmFkbWlu
czERMA8GA1UEAwwIcGhpbGlwcGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCmpai47IEvSEqZiQSFJwNKoW4Qc9brH8OPLRpZVT515P4deWpGZHVHB59w
q1OHdyO2I7UBZEEjYqQh5TPopMqudJIP341GfEXbGNpBx5I2fGpXYnMgmgRdoyKb
s5CM6or5V8iDqTR95Zk+1FyyDWpUPt/JJ3JemJngE4IpPLf+TY1lbinKevFxecRV
rT3H/Dg4SrCq+hurmnFwQNKYOxFYHb5m/NJUtITDsS+jDsWGWIqQPPqgjnDMlmth
ClpSfZQRLLf610UAREcePPGcD73XZDQ3KxJQn3ZBu5u3tze1svt6VBXZvYiMXgAm
4SKmvavCvaeZBjeMkb5FrZpSrziNAgMBAAGjQjBAMB0GA1UdDgQWBBROjANAJ9EZ
ZVSNIneM6YWameUinDAfBgNVHSMEGDAWgBTmWLkSfI/ltvmnt73hWPZ2jJIQKjAN
BgkqhkiG9w0BAQsFAAOCAQEAJPacFTGSzjCkT6dTQGpJbVoCiuPiQyma1B7/gQ+Y
oyO9nonH4HsfjetN+34bvCE9nYT8DV8dk02oVPxoTLU33WygzTopvUi+4Qz5bjiZ
TpN8PBMfl7Mhd0YhPjsebVuG+yLXO5wFi1K81En8FOCRL/CjHB1ZzufLdTrmnl+2
LIoJPrvP5ZvHr/s1ygf2MapkbvEGUp8r52oY6lQ9wElD5d4JuIrDj3cofd+iVaMj
rpdFlMhx4o4OfMqZ/iyi+tDJmBY750FtJRjY4uUKgEW0vdTExlJL9PqmedGtRegO
BgnxbMXuvf2GlDDhbWOs3/ColqqwqUrkQXH1XxX47a0GCQ==
-----END CERTIFICATE-----";

        let pem = Pem::iter_from_buffer(cert_pem.as_bytes())
            .next()
            .expect("Failed to read PEM certificate")
            .unwrap();

        let (_, cert) = X509Certificate::from_der(&pem.contents).unwrap();
        let identity = ClientIdentity::from_cert(&cert).unwrap();

        assert_eq!(identity.certificate.organizations.len(), 1);
        assert_eq!(identity.certificate.organizations[0], "admins");
        assert_eq!(identity.certificate.common_names.len(), 1);
        assert_eq!(identity.certificate.common_names[0], "philippe");
    }
}
