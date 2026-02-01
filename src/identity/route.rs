use serde::Serialize;
use uuid::Uuid;

use crate::oci::{Digest, Reference};

/// Route represents the parsed request path and action.
/// Serializes to a flat structure compatible with CEL policy expressions.
///
/// Available fields in CEL policies:
/// - `action`: The action being performed (always present)
/// - `namespace`: The repository namespace (when applicable)
/// - `digest`: The blob/manifest digest (when applicable)
/// - `reference`: The manifest tag or digest reference (when applicable)
/// - `uuid`: The upload session UUID (for upload operations)
/// - `n`: Maximum number of results for pagination
/// - `last`: Last result marker for pagination
/// - `artifact_type`: Filter for referrer queries
#[derive(Debug, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Route<'a> {
    #[serde(rename = "ui-asset")]
    UiAsset {
        #[serde(skip)]
        path: &'a str,
    },
    #[serde(rename = "ui-config")]
    UiConfig,
    Healthz,
    Metrics,
    #[serde(rename = "get-api-version")]
    ApiVersion,
    #[serde(rename = "list-catalog")]
    ListCatalog {
        #[serde(skip_serializing_if = "Option::is_none")]
        n: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        last: Option<String>,
    },
    #[serde(rename = "list-tags")]
    ListTags {
        namespace: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        n: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        last: Option<String>,
    },
    #[serde(rename = "start-upload")]
    StartUpload {
        namespace: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        digest: Option<Digest>,
    },
    #[serde(rename = "get-upload")]
    GetUpload {
        namespace: &'a str,
        uuid: Uuid,
    },
    #[serde(rename = "update-upload")]
    PatchUpload {
        namespace: &'a str,
        uuid: Uuid,
    },
    #[serde(rename = "complete-upload")]
    PutUpload {
        namespace: &'a str,
        digest: Digest,
        uuid: Uuid,
    },
    #[serde(rename = "cancel-upload")]
    DeleteUpload {
        namespace: &'a str,
        uuid: Uuid,
    },
    #[serde(rename = "get-blob")]
    GetBlob {
        namespace: &'a str,
        digest: Digest,
    },
    #[serde(rename = "get-blob")]
    HeadBlob {
        namespace: &'a str,
        digest: Digest,
    },
    #[serde(rename = "delete-blob")]
    DeleteBlob {
        namespace: &'a str,
        digest: Digest,
    },
    #[serde(rename = "get-manifest")]
    GetManifest {
        namespace: &'a str,
        reference: Reference,
    },
    #[serde(rename = "get-manifest")]
    HeadManifest {
        namespace: &'a str,
        reference: Reference,
    },
    #[serde(rename = "put-manifest")]
    PutManifest {
        namespace: &'a str,
        reference: Reference,
    },
    #[serde(rename = "delete-manifest")]
    DeleteManifest {
        namespace: &'a str,
        reference: Reference,
    },
    #[serde(rename = "get-referrers")]
    GetReferrer {
        namespace: &'a str,
        digest: Digest,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifact_type: Option<String>,
    },
    #[serde(rename = "list-revisions")]
    ListRevisions {
        namespace: &'a str,
    },
    #[serde(rename = "list-uploads")]
    ListUploads {
        namespace: &'a str,
    },
    #[serde(rename = "list-repositories")]
    ListRepositories,
    #[serde(rename = "list-namespaces")]
    ListNamespaces {
        repository: &'a str,
    },
    #[serde(rename = "unknown")]
    Unknown,
}

impl<'a> Route<'a> {
    pub fn get_namespace(&self) -> Option<&'a str> {
        match self {
            Route::ListTags { namespace, .. }
            | Route::StartUpload { namespace, .. }
            | Route::GetUpload { namespace, .. }
            | Route::PatchUpload { namespace, .. }
            | Route::PutUpload { namespace, .. }
            | Route::DeleteUpload { namespace, .. }
            | Route::GetBlob { namespace, .. }
            | Route::HeadBlob { namespace, .. }
            | Route::DeleteBlob { namespace, .. }
            | Route::GetManifest { namespace, .. }
            | Route::HeadManifest { namespace, .. }
            | Route::PutManifest { namespace, .. }
            | Route::DeleteManifest { namespace, .. }
            | Route::GetReferrer { namespace, .. }
            | Route::ListRevisions { namespace, .. }
            | Route::ListUploads { namespace, .. } => Some(namespace),
            _ => None,
        }
    }

    pub fn get_digest(&self) -> Option<&Digest> {
        match self {
            Route::GetBlob { digest, .. }
            | Route::HeadBlob { digest, .. }
            | Route::DeleteBlob { digest, .. }
            | Route::GetReferrer { digest, .. }
            | Route::PutUpload { digest, .. } => Some(digest),
            Route::StartUpload { digest, .. } => digest.as_ref(),
            _ => None,
        }
    }

    pub fn get_reference(&self) -> Option<&Reference> {
        match self {
            Route::GetManifest { reference, .. }
            | Route::HeadManifest { reference, .. }
            | Route::PutManifest { reference, .. }
            | Route::DeleteManifest { reference, .. } => Some(reference),
            _ => None,
        }
    }

    pub fn action_name(&self) -> &'static str {
        match self {
            Route::UiAsset { .. } => "ui-asset",
            Route::UiConfig => "ui-config",
            Route::ApiVersion => "get-api-version",
            Route::Healthz => "healthz",
            Route::Metrics => "metrics",
            Route::ListCatalog { .. } => "list-catalog",
            Route::ListTags { .. } => "list-tags",
            Route::StartUpload { .. } => "start-upload",
            Route::GetUpload { .. } => "get-upload",
            Route::PatchUpload { .. } => "update-upload",
            Route::PutUpload { .. } => "complete-upload",
            Route::DeleteUpload { .. } => "cancel-upload",
            Route::GetBlob { .. } | Route::HeadBlob { .. } => "get-blob",
            Route::DeleteBlob { .. } => "delete-blob",
            Route::GetManifest { .. } | Route::HeadManifest { .. } => "get-manifest",
            Route::PutManifest { .. } => "put-manifest",
            Route::DeleteManifest { .. } => "delete-manifest",
            Route::GetReferrer { .. } => "get-referrers",
            Route::ListRevisions { .. } => "list-revisions",
            Route::ListUploads { .. } => "list-uploads",
            Route::ListRepositories => "list-repositories",
            Route::ListNamespaces { .. } => "list-namespaces",
            Route::Unknown => "unknown",
        }
    }

    pub fn is_write(&self) -> bool {
        matches!(
            self,
            Route::StartUpload { .. }
                | Route::PatchUpload { .. }
                | Route::PutUpload { .. }
                | Route::DeleteUpload { .. }
                | Route::PutManifest { .. }
                | Route::DeleteManifest { .. }
                | Route::DeleteBlob { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::oci::Digest;

    #[test]
    fn test_serialization_compatibility() {
        // Test that the serialized format is consistent with the old ClientRequest

        // Test get-api-version (only action field)
        let route = Route::ApiVersion;
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["action"], "get-api-version");
        assert_eq!(json.get("namespace"), None);
        assert_eq!(json.get("digest"), None);
        assert_eq!(json.get("reference"), None);

        // Test get-manifest with namespace and reference
        let reference = Reference::from_str("v1.0.0").unwrap();
        let route = Route::GetManifest {
            namespace: "library/nginx",
            reference,
        };
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["action"], "get-manifest");
        assert_eq!(json["namespace"], "library/nginx");
        assert_eq!(
            json["reference"],
            serde_json::to_value(Reference::from_str("v1.0.0").unwrap()).unwrap()
        );
        assert_eq!(json.get("digest"), None);

        // Test get-blob with namespace and digest
        let digest = Digest::from_str(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        let route = Route::GetBlob {
            namespace: "library/nginx",
            digest,
        };
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["action"], "get-blob");
        assert_eq!(json["namespace"], "library/nginx");
        assert_eq!(
            json["digest"],
            serde_json::to_value(
                Digest::from_str(
                    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                )
                .unwrap()
            )
            .unwrap()
        );
        assert_eq!(json.get("reference"), None);

        // Test start-upload with namespace
        let route = Route::StartUpload {
            namespace: "library/nginx",
            digest: None,
        };
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["action"], "start-upload");
        assert_eq!(json["namespace"], "library/nginx");
        assert_eq!(json.get("digest"), None);

        // Test list-catalog (only action field)
        let route = Route::ListCatalog {
            n: None,
            last: None,
        };
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["action"], "list-catalog");
        assert_eq!(json.get("namespace"), None);

        // Test list-tags with namespace
        let route = Route::ListTags {
            namespace: "library/nginx",
            n: Some(10),
            last: Some("library/alpine".to_string()),
        };
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["action"], "list-tags");
        assert_eq!(json["namespace"], "library/nginx");
        // n and last are now included when present
        assert_eq!(json["n"], 10);
        assert_eq!(json["last"], "library/alpine");
    }

    #[test]
    fn test_is_write() {
        assert!(
            Route::StartUpload {
                namespace: "test",
                digest: None,
            }
            .is_write()
        );

        assert!(
            Route::PutManifest {
                namespace: "test",
                reference: Reference::from_str("v1.0.0").unwrap(),
            }
            .is_write()
        );

        assert!(
            !Route::GetManifest {
                namespace: "test",
                reference: Reference::from_str("v1.0.0").unwrap(),
            }
            .is_write()
        );

        assert!(!Route::ApiVersion.is_write());
    }

    #[test]
    fn test_get_namespace() {
        assert_eq!(
            Route::GetManifest {
                namespace: "library/nginx",
                reference: Reference::from_str("v1.0.0").unwrap(),
            }
            .get_namespace(),
            Some("library/nginx")
        );

        assert_eq!(Route::ApiVersion.get_namespace(), None);
        assert_eq!(
            Route::ListCatalog {
                n: None,
                last: None
            }
            .get_namespace(),
            None
        );
    }

    #[test]
    fn test_cel_policy_compatibility() {
        // Test that serialization provides the fields CEL policies expect

        // Test action-only routes
        let route = Route::ApiVersion;
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["action"], "get-api-version");
        assert!(json.is_object());

        // Test routes with namespace
        let route = Route::ListTags {
            namespace: "test-repo",
            n: None,
            last: None,
        };
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["action"], "list-tags");
        assert_eq!(json["namespace"], "test-repo");

        // Test routes with namespace and digest
        let digest = Digest::from_str(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        let route = Route::GetBlob {
            namespace: "test-repo",
            digest,
        };
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["action"], "get-blob");
        assert_eq!(json["namespace"], "test-repo");
        assert_eq!(
            json["digest"],
            serde_json::to_value(
                Digest::from_str(
                    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                )
                .unwrap()
            )
            .unwrap()
        );

        // Test routes with namespace and reference
        let reference = Reference::from_str("v1.0.0").unwrap();
        let route = Route::PutManifest {
            namespace: "test-repo",
            reference,
        };
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["action"], "put-manifest");
        assert_eq!(json["namespace"], "test-repo");
        assert_eq!(
            json["reference"],
            serde_json::to_value(Reference::from_str("v1.0.0").unwrap()).unwrap()
        );

        // Test routes with UUID
        let uuid = Uuid::nil();
        let route = Route::GetUpload {
            namespace: "test-repo",
            uuid,
        };
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["action"], "get-upload");
        assert_eq!(json["namespace"], "test-repo");
        assert_eq!(json["uuid"], serde_json::to_value(Uuid::nil()).unwrap());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_all_actions_have_correct_names() {
        // Verify all action names match the expected format from ClientRequest
        let test_cases = vec![
            (Route::ApiVersion, "get-api-version"),
            (Route::Healthz, "healthz"),
            (Route::Metrics, "metrics"),
            (
                Route::ListCatalog {
                    n: None,
                    last: None,
                },
                "list-catalog",
            ),
            (
                Route::ListTags {
                    namespace: "test",
                    n: None,
                    last: None,
                },
                "list-tags",
            ),
            (
                Route::StartUpload {
                    namespace: "test",
                    digest: None,
                },
                "start-upload",
            ),
            (
                Route::GetUpload {
                    namespace: "test",
                    uuid: Uuid::nil(),
                },
                "get-upload",
            ),
            (
                Route::PatchUpload {
                    namespace: "test",
                    uuid: Uuid::nil(),
                },
                "update-upload",
            ),
            (
                Route::PutUpload {
                    namespace: "test",
                    uuid: Uuid::nil(),
                    digest: Digest::from_str(
                        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    )
                    .unwrap(),
                },
                "complete-upload",
            ),
            (
                Route::DeleteUpload {
                    namespace: "test",
                    uuid: Uuid::nil(),
                },
                "cancel-upload",
            ),
            (
                Route::GetBlob {
                    namespace: "test",
                    digest: Digest::from_str(
                        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    )
                    .unwrap(),
                },
                "get-blob",
            ),
            (
                Route::HeadBlob {
                    namespace: "test",
                    digest: Digest::from_str(
                        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    )
                    .unwrap(),
                },
                "get-blob",
            ),
            (
                Route::DeleteBlob {
                    namespace: "test",
                    digest: Digest::from_str(
                        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    )
                    .unwrap(),
                },
                "delete-blob",
            ),
            (
                Route::GetManifest {
                    namespace: "test",
                    reference: Reference::from_str("v1.0.0").unwrap(),
                },
                "get-manifest",
            ),
            (
                Route::HeadManifest {
                    namespace: "test",
                    reference: Reference::from_str("v1.0.0").unwrap(),
                },
                "get-manifest",
            ),
            (
                Route::PutManifest {
                    namespace: "test",
                    reference: Reference::from_str("v1.0.0").unwrap(),
                },
                "put-manifest",
            ),
            (
                Route::DeleteManifest {
                    namespace: "test",
                    reference: Reference::from_str("v1.0.0").unwrap(),
                },
                "delete-manifest",
            ),
            (
                Route::GetReferrer {
                    namespace: "test",
                    digest: Digest::from_str(
                        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    )
                    .unwrap(),
                    artifact_type: None,
                },
                "get-referrers",
            ),
            (Route::Unknown, "unknown"),
        ];

        for (route, expected_action) in test_cases {
            let json = serde_json::to_value(&route).unwrap();
            assert_eq!(
                json["action"], expected_action,
                "Action mismatch for {route:?}",
            );
        }
    }
}
