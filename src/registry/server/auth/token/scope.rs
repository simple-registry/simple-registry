use crate::registry::server::route::Route;
use crate::registry::Error;
use serde::{Deserialize, Serialize};

const ACTION_PULL: &str = "pull";
const ACTION_PUSH: &str = "push";
const ACTION_DELETE: &str = "delete";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccessEntry {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub name: String,
    pub actions: Vec<String>,
}

pub fn parse_scopes(scopes: &[String]) -> Result<Vec<AccessEntry>, Error> {
    scopes
        .iter()
        .map(|scope| {
            let parts: Vec<&str> = scope.split(':').collect();
            if parts.len() != 3 {
                return Err(Error::Unauthorized(format!(
                    "Invalid scope format: {scope}"
                )));
            }

            Ok(AccessEntry {
                resource_type: parts[0].to_string(),
                name: parts[1].to_string(),
                actions: parts[2].split(',').map(String::from).collect(),
            })
        })
        .collect()
}

pub fn route_requires_scope(route: &Route, scope: &AccessEntry) -> bool {
    if scope.resource_type != "repository" {
        return false;
    }

    let (namespace, required_action) = match route {
        Route::GetManifest { namespace, .. }
        | Route::HeadManifest { namespace, .. }
        | Route::GetBlob { namespace, .. }
        | Route::HeadBlob { namespace, .. }
        | Route::ListTags { namespace, .. }
        | Route::GetReferrer { namespace, .. } => (Some(*namespace), ACTION_PULL),

        Route::PutManifest { namespace, .. }
        | Route::StartUpload { namespace, .. }
        | Route::GetUpload { namespace, .. }
        | Route::PatchUpload { namespace, .. }
        | Route::PutUpload { namespace, .. } => (Some(*namespace), ACTION_PUSH),

        Route::DeleteManifest { namespace, .. }
        | Route::DeleteBlob { namespace, .. }
        | Route::DeleteUpload { namespace, .. } => (Some(*namespace), ACTION_DELETE),

        _ => return false,
    };

    namespace == Some(scope.name.as_str()) && scope.actions.contains(&required_action.to_string())
}

pub fn route_to_scope(route: &Route) -> Option<String> {
    let (namespace, action) = match route {
        Route::GetManifest { namespace, .. }
        | Route::HeadManifest { namespace, .. }
        | Route::GetBlob { namespace, .. }
        | Route::HeadBlob { namespace, .. }
        | Route::ListTags { namespace, .. }
        | Route::GetReferrer { namespace, .. } => (namespace, ACTION_PULL),

        Route::PutManifest { namespace, .. }
        | Route::StartUpload { namespace, .. }
        | Route::GetUpload { namespace, .. }
        | Route::PatchUpload { namespace, .. }
        | Route::PutUpload { namespace, .. } => (namespace, ACTION_PUSH),

        Route::DeleteManifest { namespace, .. }
        | Route::DeleteBlob { namespace, .. }
        | Route::DeleteUpload { namespace, .. } => (namespace, ACTION_DELETE),

        _ => return None,
    };

    Some(format!("repository:{namespace}:{action}"))
}

pub fn get_all_routes_for_action<'a>(
    namespace: &'a str,
    action: &str,
) -> Result<Vec<Route<'a>>, Error> {
    let dummy_tag = crate::registry::oci::Reference::Tag("latest".to_string());
    let dummy_digest = crate::registry::oci::Digest::Sha256(
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    let dummy_uuid = uuid::Uuid::nil();

    match action {
        ACTION_PULL => Ok(vec![
            Route::GetManifest {
                namespace,
                reference: dummy_tag.clone(),
            },
            Route::HeadManifest {
                namespace,
                reference: dummy_tag,
            },
            Route::GetBlob {
                namespace,
                digest: dummy_digest.clone(),
            },
            Route::HeadBlob {
                namespace,
                digest: dummy_digest.clone(),
            },
            Route::ListTags {
                namespace,
                n: None,
                last: None,
            },
            Route::GetReferrer {
                namespace,
                digest: dummy_digest,
                artifact_type: None,
            },
        ]),
        ACTION_PUSH => Ok(vec![
            Route::PutManifest {
                namespace,
                reference: dummy_tag,
            },
            Route::StartUpload {
                namespace,
                digest: None,
            },
            Route::GetUpload {
                namespace,
                uuid: dummy_uuid,
            },
            Route::PatchUpload {
                namespace,
                uuid: dummy_uuid,
            },
            Route::PutUpload {
                namespace,
                uuid: dummy_uuid,
                digest: dummy_digest,
            },
        ]),
        ACTION_DELETE => Ok(vec![
            Route::DeleteManifest {
                namespace,
                reference: dummy_tag,
            },
            Route::DeleteBlob {
                namespace,
                digest: dummy_digest,
            },
            Route::DeleteUpload {
                namespace,
                uuid: dummy_uuid,
            },
        ]),
        _ => Err(Error::Unauthorized(format!("Unsupported action: {action}"))),
    }
}

pub fn validate_repository_access<'a>(
    namespace: &'a str,
    actions: &[String],
) -> Result<Vec<Route<'a>>, Error> {
    let mut all_routes = Vec::new();

    for action in actions {
        let routes = get_all_routes_for_action(namespace, action)?;
        all_routes.extend(routes);
    }

    Ok(all_routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scopes_valid() {
        let scopes = vec![
            "repository:myorg/myapp:pull".to_string(),
            "repository:test/app:pull,push".to_string(),
            "repository:foo/bar:pull,push,delete".to_string(),
        ];

        let result = parse_scopes(&scopes).unwrap();
        assert_eq!(result.len(), 3);

        assert_eq!(result[0].resource_type, "repository");
        assert_eq!(result[0].name, "myorg/myapp");
        assert_eq!(result[0].actions, vec!["pull"]);

        assert_eq!(result[1].name, "test/app");
        assert_eq!(result[1].actions, vec!["pull", "push"]);

        assert_eq!(result[2].name, "foo/bar");
        assert_eq!(result[2].actions, vec!["pull", "push", "delete"]);
    }

    #[test]
    fn test_parse_scopes_invalid_format() {
        let scopes = vec!["invalid-scope".to_string()];
        let result = parse_scopes(&scopes);
        assert!(result.is_err());

        let scopes = vec!["repository:myapp".to_string()];
        let result = parse_scopes(&scopes);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_repository_access() {
        let routes = validate_repository_access("myorg/myapp", &[ACTION_PULL.to_string()]).unwrap();
        assert_eq!(routes.len(), 6);

        let has_get_manifest = routes
            .iter()
            .any(|r| matches!(r, Route::GetManifest { .. }));
        let has_list_tags = routes.iter().any(|r| matches!(r, Route::ListTags { .. }));
        let has_get_blob = routes.iter().any(|r| matches!(r, Route::GetBlob { .. }));
        assert!(has_get_manifest);
        assert!(has_list_tags);
        assert!(has_get_blob);

        let routes = validate_repository_access("myorg/myapp", &[ACTION_PUSH.to_string()]).unwrap();
        assert_eq!(routes.len(), 5);

        let routes =
            validate_repository_access("myorg/myapp", &[ACTION_DELETE.to_string()]).unwrap();
        assert_eq!(routes.len(), 3);

        let routes = validate_repository_access(
            "myorg/myapp",
            &[ACTION_PULL.to_string(), ACTION_PUSH.to_string()],
        )
        .unwrap();
        assert_eq!(routes.len(), 11);

        let result = validate_repository_access("myorg/myapp", &["invalid".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_route_requires_scope() {
        let pull_scope = AccessEntry {
            resource_type: "repository".to_string(),
            name: "myorg/myapp".to_string(),
            actions: vec![ACTION_PULL.to_string()],
        };

        // Test read operations require pull
        assert!(route_requires_scope(
            &Route::GetManifest {
                namespace: "myorg/myapp",
                reference: crate::registry::oci::Reference::Tag("latest".to_string()),
            },
            &pull_scope
        ));

        assert!(route_requires_scope(
            &Route::GetBlob {
                namespace: "myorg/myapp",
                digest: crate::registry::oci::Digest::Sha256("abc123".to_string()),
            },
            &pull_scope
        ));

        // Test wrong namespace
        assert!(!route_requires_scope(
            &Route::GetManifest {
                namespace: "other/app",
                reference: crate::registry::oci::Reference::Tag("latest".to_string()),
            },
            &pull_scope
        ));

        let push_scope = AccessEntry {
            resource_type: "repository".to_string(),
            name: "myorg/myapp".to_string(),
            actions: vec![ACTION_PUSH.to_string()],
        };

        assert!(route_requires_scope(
            &Route::PutManifest {
                namespace: "myorg/myapp",
                reference: crate::registry::oci::Reference::Tag("latest".to_string()),
            },
            &push_scope
        ));
    }

    #[test]
    fn test_route_to_scope() {
        // Test read operations map to pull
        assert_eq!(
            route_to_scope(&Route::GetManifest {
                namespace: "myorg/myapp",
                reference: crate::registry::oci::Reference::Tag("latest".to_string()),
            }),
            Some("repository:myorg/myapp:pull".to_string())
        );

        // Test write operations map to push
        assert_eq!(
            route_to_scope(&Route::PutManifest {
                namespace: "myorg/myapp",
                reference: crate::registry::oci::Reference::Tag("latest".to_string()),
            }),
            Some("repository:myorg/myapp:push".to_string())
        );

        // Test delete operations map to delete
        assert_eq!(
            route_to_scope(&Route::DeleteManifest {
                namespace: "myorg/myapp",
                reference: crate::registry::oci::Reference::Tag("latest".to_string()),
            }),
            Some("repository:myorg/myapp:delete".to_string())
        );

        // Test non-repository routes return None
        assert_eq!(route_to_scope(&Route::ApiVersion), None);
        assert_eq!(route_to_scope(&Route::Healthz), None);
    }
}
