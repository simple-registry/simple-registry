use serde::Serialize;
use serde_json;
use std::collections::HashMap;

/// Client identity information used in access control decisions.
///
/// Contains authentication details extracted from basic auth, mTLS certificates, or OIDC tokens.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ClientIdentity {
    pub id: Option<String>,
    pub username: Option<String>,
    pub certificate: ClientCertificate,
    pub oidc: Option<OidcClaims>,
    pub client_ip: Option<String>,
}

/// Certificate information extracted from client mTLS certificates.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ClientCertificate {
    pub organizations: Vec<String>,
    pub common_names: Vec<String>,
}

/// OIDC claims extracted from JWT tokens.
///
/// All claims from the token are exposed as-is to allow maximum flexibility
/// in policy expressions. Standard claims like sub, iss, aud are available
/// along with any custom claims from the OIDC provider.
#[derive(Clone, Debug, Default, Serialize)]
pub struct OidcClaims {
    pub provider_name: String,
    pub provider_type: String,
    pub claims: HashMap<String, serde_json::Value>,
}
