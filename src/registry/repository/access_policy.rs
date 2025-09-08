//! Access control policy evaluation for registry operations.
//!
//! This module provides CEL-based access control for registry operations.
//! Policies are pre-compiled at configuration load time for performance.
//!
//! # Policy Evaluation
//!
//! Access policies support two modes:
//! - **Default Allow**: Access is granted unless explicitly denied by a rule
//! - **Default Deny**: Access is denied unless explicitly granted by a rule
//!
//! # Available Variables
//!
//! CEL expressions have access to:
//! - `identity`: Client identity information (id, username, certificate details)
//! - `request`: Request details (action, namespace, digest, reference)

use crate::registry::oci::{Digest, Reference};
use crate::registry::Error;
use cel_interpreter::{Context, Program, Value};
use serde::Serialize;
use tracing::{debug, info, instrument};
use x509_parser::certificate::X509Certificate;

/// Access control policy engine.
///
/// Evaluates CEL expressions to determine if a request should be allowed.
/// Rules are pre-compiled at configuration time for better performance.
pub struct AccessPolicy {
    default_allow: bool,
    rules: Vec<Program>,
}

impl AccessPolicy {
    pub fn new(default_allow: bool, rules: Vec<Program>) -> Self {
        Self {
            default_allow,
            rules,
        }
    }

    /// Evaluates the access policy for a given request and identity.
    ///
    /// # Arguments
    /// * `request` - The client request containing action and resource information
    /// * `identity` - The client identity containing authentication information
    ///
    /// # Returns
    /// * `Ok(true)` if access should be granted
    /// * `Ok(false)` if access should be denied
    /// * `Err` if policy evaluation fails
    pub fn evaluate(
        &self,
        request: &ClientRequest,
        identity: &ClientIdentity,
    ) -> Result<bool, Error> {
        if self.rules.is_empty() {
            return Ok(self.default_allow);
        }

        let context = Self::build_context(request, identity)?;

        if self.default_allow {
            for rule in &self.rules {
                match rule.execute(&context)? {
                    Value::Bool(true) => {
                        info!("Deny rule matched");
                        return Ok(false);
                    }
                    Value::Bool(false) => {}
                    _ => return Ok(false),
                }
            }
            Ok(true)
        } else {
            for rule in &self.rules {
                match rule.execute(&context)? {
                    Value::Bool(true) => {
                        debug!("Allow rule matched");
                        return Ok(true);
                    }
                    Value::Bool(false) => {}
                    _ => return Ok(false),
                }
            }
            Ok(false)
        }
    }

    fn build_context<'a>(
        request: &'a ClientRequest,
        identity: &'a ClientIdentity,
    ) -> Result<Context<'a>, Error> {
        let mut context = Context::default();
        context.add_variable("request", request)?;
        context.add_variable("identity", identity)?;
        Ok(context)
    }
}

/// Client identity information used in access control decisions.
///
/// Contains authentication details extracted from basic auth or mTLS certificates.
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

/// Certificate information extracted from client mTLS certificates.
#[derive(Clone, Debug, Default, Serialize)]
pub struct CELIdentityCertificate {
    pub organizations: Vec<String>,
    pub common_names: Vec<String>,
}

const GET_API_VERSION: &str = "get-api-version";
const GET_MANIFEST: &str = "get-manifest";
const GET_BLOB: &str = "get-blob";
const START_UPLOAD: &str = "start-upload";
const UPDATE_UPLOAD: &str = "update-upload";
const COMPLETE_UPLOAD: &str = "complete-upload";
const CANCEL_UPLOAD: &str = "cancel-upload";
const GET_UPLOAD: &str = "get-upload";
const DELETE_BLOB: &str = "delete-blob";
const PUT_MANIFEST: &str = "put-manifest";
const DELETE_MANIFEST: &str = "delete-manifest";
const GET_REFERRERS: &str = "get-referrers";
const LIST_CATALOG: &str = "list-catalog";
const LIST_TAGS: &str = "list-tags";

/// Registry operation request details used in access control decisions.
///
/// Contains information about the requested action and target resources.
/// The action field uses static string constants for efficiency.
#[derive(Debug, Default, Serialize)]
pub struct ClientRequest {
    pub action: &'static str,
    pub namespace: Option<String>,
    pub digest: Option<String>,
    pub reference: Option<String>,
}

impl ClientRequest {
    pub fn get_api_version() -> Self {
        Self {
            action: GET_API_VERSION,
            ..Self::default()
        }
    }

    pub fn get_manifest(namespace: &str, reference: &Reference) -> Self {
        Self {
            action: GET_MANIFEST,
            namespace: Some(namespace.to_string()),
            reference: Some(reference.to_string()),
            ..Self::default()
        }
    }

    pub fn get_blob(namespace: &str, digest: &Digest) -> Self {
        Self {
            action: GET_BLOB,
            namespace: Some(namespace.to_string()),
            digest: Some(digest.to_string()),
            ..Self::default()
        }
    }

    pub fn start_upload(name: &str) -> Self {
        Self {
            action: START_UPLOAD,
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn update_upload(name: &str) -> Self {
        Self {
            action: UPDATE_UPLOAD,
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn complete_upload(name: &str) -> Self {
        Self {
            action: COMPLETE_UPLOAD,
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn cancel_upload(name: &str) -> Self {
        Self {
            action: CANCEL_UPLOAD,
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn get_upload(name: &str) -> Self {
        Self {
            action: GET_UPLOAD,
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn delete_blob(name: &str, digest: &Digest) -> Self {
        Self {
            action: DELETE_BLOB,
            namespace: Some(name.to_string()),
            digest: Some(digest.to_string()),
            ..Self::default()
        }
    }

    pub fn put_manifest(name: &str, reference: &Reference) -> Self {
        Self {
            action: PUT_MANIFEST,
            namespace: Some(name.to_string()),
            reference: Some(reference.to_string()),
            ..Self::default()
        }
    }

    pub fn delete_manifest(name: &str, reference: &Reference) -> Self {
        Self {
            action: DELETE_MANIFEST,
            namespace: Some(name.to_string()),
            reference: Some(reference.to_string()),
            ..Self::default()
        }
    }

    pub fn get_referrers(name: &str, digest: &Digest) -> Self {
        Self {
            action: GET_REFERRERS,
            namespace: Some(name.to_string()),
            digest: Some(digest.to_string()),
            ..Self::default()
        }
    }

    pub fn list_catalog() -> Self {
        Self {
            action: LIST_CATALOG,
            ..Self::default()
        }
    }

    pub fn list_tags(name: &str) -> Self {
        Self {
            action: LIST_TAGS,
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn is_write(&self) -> bool {
        matches!(
            self.action,
            START_UPLOAD
                | UPDATE_UPLOAD
                | COMPLETE_UPLOAD
                | CANCEL_UPLOAD
                | PUT_MANIFEST
                | DELETE_MANIFEST
                | DELETE_BLOB
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::pem::Pem;
    use x509_parser::prelude::FromDer;

    #[test]
    fn test_access_policy_default_allow_no_rules() {
        let policy = AccessPolicy::new(true, vec![]);
        let request = ClientRequest::get_api_version();
        let identity = ClientIdentity::default();

        let result = policy.evaluate(&request, &identity);
        assert!(result.unwrap());
    }

    #[test]
    fn test_access_policy_default_deny_no_rules() {
        let policy = AccessPolicy::new(false, vec![]);
        let request = ClientRequest::get_api_version();
        let identity = ClientIdentity::default();

        let result = policy.evaluate(&request, &identity);
        assert!(!result.unwrap());
    }

    #[test]
    fn test_access_policy_default_allow_with_deny_rule() {
        use cel_interpreter::Program;
        let program = Program::compile("identity.username == 'forbidden'").unwrap();
        let policy = AccessPolicy::new(true, vec![program]);

        let request = ClientRequest::get_api_version();
        let identity = ClientIdentity {
            username: Some("forbidden".to_string()),
            ..ClientIdentity::default()
        };

        let result = policy.evaluate(&request, &identity);
        assert!(!result.unwrap());

        let identity = ClientIdentity {
            username: Some("allowed".to_string()),
            ..ClientIdentity::default()
        };

        let result = policy.evaluate(&request, &identity);
        assert!(result.unwrap());
    }

    #[test]
    fn test_access_policy_default_deny_with_allow_rule() {
        use cel_interpreter::Program;
        let program = Program::compile("identity.username == 'admin'").unwrap();
        let policy = AccessPolicy::new(false, vec![program]);

        let request = ClientRequest::get_api_version();
        let identity = ClientIdentity {
            username: Some("admin".to_string()),
            ..ClientIdentity::default()
        };

        let result = policy.evaluate(&request, &identity);
        assert!(result.unwrap());

        let identity = ClientIdentity {
            username: Some("user".to_string()),
            ..ClientIdentity::default()
        };

        let result = policy.evaluate(&request, &identity);
        assert!(!result.unwrap());
    }

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

    #[test]
    fn test_get_api_version() {
        let request = ClientRequest::get_api_version();
        assert_eq!(request.action, GET_API_VERSION);
        assert!(request.namespace.is_none());
        assert!(request.digest.is_none());
        assert!(request.reference.is_none());
    }

    #[test]
    fn test_get_manifest() {
        use crate::registry::oci::Reference;
        let namespace = "test-namespace";
        let reference = Reference::Tag("tag".to_string());
        let request = ClientRequest::get_manifest(namespace, &reference);

        assert_eq!(request.action, GET_MANIFEST);
        assert_eq!(request.namespace, Some(namespace.to_string()));
        assert_eq!(request.reference, Some(reference.to_string()));
        assert!(request.digest.is_none());
    }

    #[test]
    fn test_get_blob() {
        use crate::registry::oci::Digest;
        let namespace = "test-namespace";
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        let request = ClientRequest::get_blob(namespace, &digest);

        assert_eq!(request.action, GET_BLOB);
        assert_eq!(request.namespace, Some(namespace.to_string()));
        assert_eq!(request.digest, Some(digest.to_string()));
        assert!(request.reference.is_none());
    }

    #[test]
    fn test_upload_operations() {
        let name = "test-upload";

        let start_request = ClientRequest::start_upload(name);
        assert_eq!(start_request.action, START_UPLOAD);
        assert_eq!(start_request.namespace, Some(name.to_string()));

        let update_request = ClientRequest::update_upload(name);
        assert_eq!(update_request.action, UPDATE_UPLOAD);
        assert_eq!(update_request.namespace, Some(name.to_string()));

        let complete_request = ClientRequest::complete_upload(name);
        assert_eq!(complete_request.action, COMPLETE_UPLOAD);
        assert_eq!(complete_request.namespace, Some(name.to_string()));

        let cancel_request = ClientRequest::cancel_upload(name);
        assert_eq!(cancel_request.action, CANCEL_UPLOAD);
        assert_eq!(cancel_request.namespace, Some(name.to_string()));

        let get_request = ClientRequest::get_upload(name);
        assert_eq!(get_request.action, GET_UPLOAD);
        assert_eq!(get_request.namespace, Some(name.to_string()));
    }

    #[test]
    fn test_delete_operations() {
        use crate::registry::oci::{Digest, Reference};
        let name = "test-namespace";
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        let reference = Reference::Tag("tag".to_string());

        let delete_blob_request = ClientRequest::delete_blob(name, &digest);
        assert_eq!(delete_blob_request.action, DELETE_BLOB);
        assert_eq!(delete_blob_request.namespace, Some(name.to_string()));
        assert_eq!(delete_blob_request.digest, Some(digest.to_string()));

        let delete_manifest_request = ClientRequest::delete_manifest(name, &reference);
        assert_eq!(delete_manifest_request.action, DELETE_MANIFEST);
        assert_eq!(delete_manifest_request.namespace, Some(name.to_string()));
        assert_eq!(
            delete_manifest_request.reference,
            Some(reference.to_string())
        );
    }

    #[test]
    fn test_get_referrers() {
        use crate::registry::oci::Digest;
        let name = "test-namespace";
        let digest = Digest::Sha256("1234567890abcdef".to_string());
        let request = ClientRequest::get_referrers(name, &digest);

        assert_eq!(request.action, GET_REFERRERS);
        assert_eq!(request.namespace, Some(name.to_string()));
        assert_eq!(request.digest, Some(digest.to_string()));
        assert!(request.reference.is_none());
    }

    #[test]
    fn test_list_operations() {
        let list_catalog_request = ClientRequest::list_catalog();
        assert_eq!(list_catalog_request.action, LIST_CATALOG);
        assert!(list_catalog_request.namespace.is_none());
        assert!(list_catalog_request.digest.is_none());
        assert!(list_catalog_request.reference.is_none());

        let name = "test-namespace";
        let list_tags_request = ClientRequest::list_tags(name);
        assert_eq!(list_tags_request.action, LIST_TAGS);
        assert_eq!(list_tags_request.namespace, Some(name.to_string()));
        assert!(list_tags_request.digest.is_none());
        assert!(list_tags_request.reference.is_none());
    }

    #[test]
    fn test_is_write() {
        use crate::registry::oci::{Digest, Reference};
        let write_actions = [
            ClientRequest::start_upload("test"),
            ClientRequest::update_upload("test"),
            ClientRequest::complete_upload("test"),
            ClientRequest::cancel_upload("test"),
            ClientRequest::put_manifest("test", &Reference::Tag("tag".to_string())),
            ClientRequest::delete_manifest("test", &Reference::Tag("tag".to_string())),
            ClientRequest::delete_blob("test", &Digest::Sha256("1234567890abcdef".to_string())),
        ];

        let read_actions = [
            ClientRequest::get_api_version(),
            ClientRequest::get_manifest("test", &Reference::Tag("tag".to_string())),
            ClientRequest::get_blob("test", &Digest::Sha256("1234567890abcdef".to_string())),
            ClientRequest::get_upload("test"),
            ClientRequest::get_referrers("test", &Digest::Sha256("1234567890abcdef".to_string())),
            ClientRequest::list_catalog(),
            ClientRequest::list_tags("test"),
        ];

        for request in write_actions {
            assert!(
                request.is_write(),
                "{} should be a write operation",
                request.action
            );
        }

        for request in read_actions {
            assert!(
                !request.is_write(),
                "{} should not be a write operation",
                request.action
            );
        }
    }
}
