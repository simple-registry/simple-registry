use crate::registry::oci_types::{Digest, Reference};
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
