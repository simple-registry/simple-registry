use crate::oci::{Digest, Reference};
use serde::Serialize;

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
            action: GET_API_VERSION.to_string(),
            ..Self::default()
        }
    }

    pub fn get_manifest(namespace: &str, reference: &Reference) -> Self {
        Self {
            action: GET_MANIFEST.to_string(),
            namespace: Some(namespace.to_string()),
            reference: Some(reference.to_string()),
            ..Self::default()
        }
    }

    pub fn get_blob(namespace: &str, digest: &Digest) -> Self {
        Self {
            action: GET_BLOB.to_string(),
            namespace: Some(namespace.to_string()),
            digest: Some(digest.to_string()),
            ..Self::default()
        }
    }

    pub fn start_upload(name: &str) -> Self {
        Self {
            action: START_UPLOAD.to_string(),
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn update_upload(name: &str) -> Self {
        Self {
            action: UPDATE_UPLOAD.to_string(),
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn complete_upload(name: &str) -> Self {
        Self {
            action: COMPLETE_UPLOAD.to_string(),
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn cancel_upload(name: &str) -> Self {
        Self {
            action: CANCEL_UPLOAD.to_string(),
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn get_upload(name: &str) -> Self {
        Self {
            action: GET_UPLOAD.to_string(),
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn delete_blob(name: &str, digest: &Digest) -> Self {
        Self {
            action: DELETE_BLOB.to_string(),
            namespace: Some(name.to_string()),
            digest: Some(digest.to_string()),
            ..Self::default()
        }
    }

    pub fn put_manifest(name: &str, reference: &Reference) -> Self {
        Self {
            action: PUT_MANIFEST.to_string(),
            namespace: Some(name.to_string()),
            reference: Some(reference.to_string()),
            ..Self::default()
        }
    }

    pub fn delete_manifest(name: &str, reference: &Reference) -> Self {
        Self {
            action: DELETE_MANIFEST.to_string(),
            namespace: Some(name.to_string()),
            reference: Some(reference.to_string()),
            ..Self::default()
        }
    }

    pub fn get_referrers(name: &str, digest: &Digest) -> Self {
        Self {
            action: GET_REFERRERS.to_string(),
            namespace: Some(name.to_string()),
            digest: Some(digest.to_string()),
            ..Self::default()
        }
    }

    pub fn list_catalog() -> Self {
        Self {
            action: LIST_CATALOG.to_string(),
            ..Self::default()
        }
    }

    pub fn list_tags(name: &str) -> Self {
        Self {
            action: LIST_TAGS.to_string(),
            namespace: Some(name.to_string()),
            ..Self::default()
        }
    }

    pub fn is_write(&self) -> bool {
        matches!(
            self.action.as_str(),
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
