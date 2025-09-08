use crate::registry::oci::{Digest, Reference};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::oci::{Digest, Reference};

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
