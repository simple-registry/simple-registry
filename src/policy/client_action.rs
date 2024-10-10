use crate::oci::{Digest, Reference};
use crate::registry::extract_namespace;

#[derive(Clone, Debug)]
pub enum ClientAction {
    GetApiVersion,
    PutBlob(String),
    GetBlob(String, Digest),
    DeleteBlob(String, Digest),
    PutManifest(String, Reference),
    GetManifest(String, Reference),
    DeleteManifest(String, Reference),
    GetReferrers(String, Digest),
    ListCatalog,
    ListTags(String),
}

impl ClientAction {
    pub fn get_action_name(&self) -> String {
        match self {
            ClientAction::GetApiVersion => "get-api-version".to_string(),
            ClientAction::PutBlob(_) => "put-blob".to_string(),
            ClientAction::GetBlob(_, _) => "get-blob".to_string(),
            ClientAction::DeleteBlob(_, _) => "delete-blob".to_string(),
            ClientAction::PutManifest(_, _) => "put-manifest".to_string(),
            ClientAction::GetManifest(_, _) => "get-manifest".to_string(),
            ClientAction::DeleteManifest(_, _) => "delete-manifest".to_string(),
            ClientAction::GetReferrers(_, _) => "get-referrers".to_string(),
            ClientAction::ListCatalog => "list-catalog".to_string(),
            ClientAction::ListTags(_) => "list-tags".to_string(),
        }
    }

    pub fn get_namespace(&self) -> Option<String> {
        match self {
            ClientAction::PutBlob(name)
            | ClientAction::GetBlob(name, _)
            | ClientAction::DeleteBlob(name, _)
            | ClientAction::PutManifest(name, _)
            | ClientAction::GetManifest(name, _)
            | ClientAction::DeleteManifest(name, _)
            | ClientAction::GetReferrers(name, _)
            | ClientAction::ListTags(name) => Some(extract_namespace(name.to_string())),
            _ => None,
        }
    }

    pub fn get_digest(&self) -> Option<Digest> {
        match self {
            ClientAction::GetBlob(_, digest)
            | ClientAction::DeleteBlob(_, digest)
            | ClientAction::GetReferrers(_, digest) => Some(digest.clone()),
            _ => None,
        }
    }

    pub fn get_reference(&self) -> Option<Reference> {
        match self {
            ClientAction::PutManifest(_, reference)
            | ClientAction::GetManifest(_, reference)
            | ClientAction::DeleteManifest(_, reference) => Some(reference.clone()),
            _ => None,
        }
    }
}
