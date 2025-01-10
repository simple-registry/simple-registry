use crate::oci::{Digest, Reference};
use serde::Serialize;

// NOTE: Here we define a struct instead of an enum to simplify integration with
// the policy evaluation logic.
#[derive(Debug, Default, Serialize)]
pub struct ClientRequest {
    pub action: String,
    pub namespace: Option<String>,
    pub digest: Option<String>,
    pub reference: Option<String>,
}

impl ClientRequest {
    pub fn get_api_version() -> Self {
        Self {
            action: "get-api-version".to_string(),
            ..Self::default()
        }
    }

    pub fn get_manifest(namespace: &str, reference: &Reference) -> Self {
        Self {
            action: "get-manifest".to_string(),
            namespace: Some(namespace.to_string()),
            reference: Some(reference.to_string()),
            ..Self::default()
        }
    }

    pub fn get_blob(namespace: &str, digest: &Digest) -> Self {
        Self {
            action: "get-blob".to_string(),
            namespace: Some(namespace.to_string()),
            digest: Some(digest.to_string()),
            ..Self::default()
        }
    }

    pub fn start_upload(name: &str) -> Self {
        Self {
            action: "start-upload".to_string(),
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn update_upload(name: &str) -> Self {
        Self {
            action: "update-upload".to_string(),
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn complete_upload(name: &str) -> Self {
        Self {
            action: "complete-upload".to_string(),
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn cancel_upload(name: &str) -> Self {
        Self {
            action: "cancel-upload".to_string(),
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn get_upload(name: &str) -> Self {
        Self {
            action: "get-upload".to_string(),
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn delete_blob(name: &str, digest: &Digest) -> Self {
        Self {
            action: "delete-blob".to_string(),
            namespace: Some(name.to_string()),
            digest: Some(digest.to_string()),
            ..Self::default()
        }
    }

    pub fn put_manifest(name: &str, reference: &Reference) -> Self {
        Self {
            action: "put-manifest".to_string(),
            namespace: Some(name.to_string()),
            reference: Some(reference.to_string()),
            ..Self::default()
        }
    }

    pub fn delete_manifest(name: &str, reference: &Reference) -> Self {
        Self {
            action: "delete-manifest".to_string(),
            namespace: Some(name.to_string()),
            reference: Some(reference.to_string()),
            ..Self::default()
        }
    }

    pub fn get_referrers(name: &str, digest: &Digest) -> Self {
        Self {
            action: "get-referrers".to_string(),
            namespace: Some(name.to_string()),
            digest: Some(digest.to_string()),
            ..Self::default()
        }
    }

    pub fn list_catalog() -> Self {
        Self {
            action: "list-catalog".to_string(),
            ..Self::default()
        }
    }

    pub fn list_tags(name: &str) -> Self {
        Self {
            action: "list-tags".to_string(),
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }
}
