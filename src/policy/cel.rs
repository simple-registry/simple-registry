use crate::policy::client_action::ClientAction;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CELRequest {
    pub action: String,
    pub namespace: Option<String>,
    pub digest: Option<String>,
    pub reference: Option<String>,
}

impl CELRequest {
    pub fn new(
        action: String,
        namespace: Option<String>,
        digest: Option<String>,
        reference: Option<String>,
    ) -> Self {
        CELRequest {
            action,
            namespace,
            digest,
            reference,
        }
    }
}

impl From<ClientAction> for CELRequest {
    fn from(action: ClientAction) -> Self {
        let action_name = action.get_action_name();
        let namespace = action.get_namespace();
        let digest = action.get_digest().map(|d| d.to_string());
        let reference = action.get_reference().map(|r| r.to_string());

        CELRequest::new(action_name, namespace, digest, reference)
    }
}

#[derive(Debug, Serialize)]
pub struct CELIdentity {
    pub id: Option<String>,
    pub username: Option<String>,
    pub certificate: CELIdentityCertificate,
}

impl CELIdentity {
    pub fn new(
        id: Option<String>,
        username: Option<String>,
        certificate: CELIdentityCertificate,
    ) -> Self {
        CELIdentity {
            id,
            username,
            certificate,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CELIdentityCertificate {
    pub organizations: Vec<String>,
    pub common_names: Vec<String>,
}

impl CELIdentityCertificate {
    pub fn new(organizations: Vec<String>, common_names: Vec<String>) -> Self {
        CELIdentityCertificate {
            organizations,
            common_names,
        }
    }
}
