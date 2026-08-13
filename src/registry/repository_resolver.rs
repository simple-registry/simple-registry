//! Deterministic repository resolution for namespace-to-repository mapping.
//!
//! [`RepositoryResolver`] wraps an `Arc<HashMap<String, Repository>>` and
//! rejects overlapping repository prefixes at construction. Two prefixes
//! overlap when one is a namespace-prefix of the other (e.g. `team` and
//! `team/app`). The rejection makes startup fail fast on misconfigured
//! repositories rather than allowing non-deterministic runtime behavior driven
//! by `HashMap` iteration order.

use std::{collections::HashMap, fmt, sync::Arc};

use crate::{oci::namespace_belongs_to, registry::Repository};

/// The `ns` a repository key mirrors, for the construction-time uniqueness
/// check.
fn mirrored<'a>(repositories: &'a HashMap<String, Repository>, key: &str) -> Option<&'a str> {
    repositories.get(key).and_then(|r| r.namespace.as_deref())
}

/// A repository map that rejects overlapping repository prefixes at
/// construction and provides deterministic namespace resolution.
///
/// Two prefixes overlap when one is a namespace-prefix of another:
/// `namespace_belongs_to(a, b) || namespace_belongs_to(b, a)` for any two
/// distinct keys `a` and `b`.
pub struct RepositoryResolver {
    inner: Arc<HashMap<String, Repository>>,
}

impl fmt::Debug for RepositoryResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RepositoryResolver")
            .field("repositories", &self.inner.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Error returned when two repositories cannot be told apart: their prefixes
/// overlap, or they claim the same `ns`.
///
/// The error names both offenders so the operator can disambiguate.
#[derive(Debug, thiserror::Error)]
pub enum OverlapError {
    #[error("repository prefixes overlap: '{0}' and '{1}'")]
    Prefix(String, String),
    #[error("repositories '{0}' and '{1}' both mirror the namespace '{2}'")]
    Namespace(String, String, String),
}

impl RepositoryResolver {
    /// Constructs a resolver from the given map.
    ///
    /// # Errors
    ///
    /// Returns [`OverlapError`] if any two keys are namespace-prefixes of each
    /// other. The error names the first pair of overlapping prefixes found.
    pub fn new(repositories: Arc<HashMap<String, Repository>>) -> Result<Self, OverlapError> {
        let keys: Vec<&str> = repositories.keys().map(String::as_str).collect();
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                let a = keys[i];
                let b = keys[j];
                if namespace_belongs_to(a, b) || namespace_belongs_to(b, a) {
                    return Err(OverlapError::Prefix(a.to_string(), b.to_string()));
                }
                // A `?ns=` value must resolve to one repository, so two
                // claiming the same one is a misconfiguration, not a race.
                if let (Some(left), Some(right)) =
                    (mirrored(&repositories, a), mirrored(&repositories, b))
                    && left == right
                {
                    return Err(OverlapError::Namespace(
                        a.to_string(),
                        b.to_string(),
                        left.to_string(),
                    ));
                }
            }
        }
        Ok(Self {
            inner: repositories,
        })
    }

    /// Resolves the repository mirroring `ns`, the value of a request's proxy
    /// `?ns=` parameter. `None` when no repository claims it, which leaves the
    /// parameter without effect.
    pub fn resolve_ns(&self, ns: &str) -> Option<&Repository> {
        self.inner
            .values()
            .find(|repository| repository.namespace.as_deref() == Some(ns))
    }

    /// Resolves the repository for a namespace.
    ///
    /// Returns the first repository whose key is a namespace-prefix of
    /// `namespace`, or `None` when no match exists. Because overlapping
    /// prefixes are rejected at construction, at most one match is possible.
    pub fn resolve(&self, namespace: impl AsRef<str>) -> Option<&Repository> {
        let namespace = namespace.as_ref();
        self.inner
            .iter()
            .find(|(key, _)| namespace_belongs_to(namespace, key))
            .map(|(_, repo)| repo)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.inner.keys().map(String::as_str)
    }

    pub fn contains_key(&self, name: &str) -> bool {
        self.inner.contains_key(name)
    }

    pub fn get(&self, name: &str) -> Option<&Repository> {
        self.inner.get(name)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use super::*;
    use crate::{
        oci::Namespace,
        policy::{RetentionPolicy, RetentionPolicyConfig, SystemClock},
        registry::Repository,
    };

    fn repo(name: &str) -> Repository {
        Repository {
            name: Namespace::new(name).unwrap(),
            namespace: None,
            upstreams: Vec::new(),
            replication: Vec::new(),
            retention_policy: RetentionPolicy::new(
                &RetentionPolicyConfig::default(),
                Arc::new(SystemClock),
            ),
            immutable_tags: false,
            immutable_tags_exclusions: Vec::new(),
        }
    }

    fn resolver(pairs: &[(&str, &str)]) -> Result<RepositoryResolver, OverlapError> {
        let mut map = HashMap::new();
        for (key, name) in pairs {
            map.insert(key.to_string(), repo(name));
        }
        RepositoryResolver::new(Arc::new(map))
    }

    #[test]
    fn overlapping_shallow_and_nested_rejected() {
        let result = resolver(&[("team", "team"), ("team/app", "team/app")]);
        assert!(
            result.is_err(),
            "overlapping prefixes team and team/app must be rejected"
        );
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("team") && msg.contains("team/app"),
            "error message must name both prefixes: {msg}"
        );
    }

    #[test]
    fn overlapping_nested_variant_rejected() {
        // parent contains child: "org/team" overlaps "org/team/sub"
        let result = resolver(&[("org/team", "org/team"), ("org/team/sub", "sub")]);
        assert!(
            result.is_err(),
            "org/team and org/team/sub must be rejected"
        );
    }

    /// A `?ns=` must name one repository, so two claiming the same registry
    /// namespace fail at startup rather than resolving by map order.
    #[test]
    fn repositories_mirroring_the_same_namespace_rejected() {
        let mut mirror = repo("docker-hub");
        mirror.namespace = Some("docker.io".to_string());
        let mut second = repo("hub-mirror");
        second.namespace = Some("docker.io".to_string());

        let repositories = Arc::new(HashMap::from([
            ("docker-hub".to_string(), mirror),
            ("hub-mirror".to_string(), second),
        ]));
        let error = RepositoryResolver::new(repositories)
            .expect_err("two repositories mirroring docker.io must be refused");

        let message = error.to_string();
        assert!(
            message.contains("docker.io"),
            "the error must name the namespace both claim: {message}"
        );
    }

    #[test]
    fn resolve_ns_finds_the_mirroring_repository() {
        let mut mirror = repo("docker-hub");
        mirror.namespace = Some("docker.io".to_string());
        let repositories = Arc::new(HashMap::from([
            ("docker-hub".to_string(), mirror),
            ("internal".to_string(), repo("internal")),
        ]));
        let resolver = RepositoryResolver::new(repositories).unwrap();

        assert_eq!(
            resolver.resolve_ns("docker.io").map(|r| r.name.to_string()),
            Some("docker-hub".to_string())
        );
        assert!(resolver.resolve_ns("quay.io").is_none());
    }

    #[test]
    fn sibling_disjoint_prefixes_accepted() {
        let result = resolver(&[("alpha", "alpha"), ("beta", "beta")]);
        assert!(result.is_ok(), "disjoint siblings must be accepted");
    }

    #[test]
    fn sibling_prefixes_with_shared_root_accepted() {
        // "team/backend" and "team/frontend" share the "team" root but neither
        // is a namespace-prefix of the other.
        let result = resolver(&[("team/backend", "backend"), ("team/frontend", "frontend")]);
        assert!(
            result.is_ok(),
            "team/backend and team/frontend must be accepted"
        );
    }

    #[test]
    fn exact_match_returns_repository() {
        let r = resolver(&[("myrepo", "myrepo"), ("other", "other")]).unwrap();
        let found = r.resolve("myrepo");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "myrepo");
    }

    #[test]
    fn sub_namespace_matches_parent_prefix() {
        let r = resolver(&[("myrepo", "myrepo")]).unwrap();
        let found = r.resolve("myrepo/sub/path");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "myrepo");
    }

    #[test]
    fn unrelated_namespace_returns_none() {
        let r = resolver(&[("myrepo", "myrepo")]).unwrap();
        assert!(r.resolve("completely-different").is_none());
    }

    #[test]
    fn empty_map_returns_none() {
        let r = resolver(&[]).unwrap();
        assert!(r.resolve("anything").is_none());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn adjacent_string_non_match() {
        // "myrepo2" must NOT match a resolver configured for "myrepo".
        let r = resolver(&[("myrepo", "myrepo")]).unwrap();
        assert!(
            r.resolve("myrepo2").is_none(),
            "myrepo2 must not match prefix myrepo"
        );
    }

    #[test]
    fn contains_key_and_get_work_on_exact_keys() {
        let r = resolver(&[("repo-a", "repo-a"), ("repo-b", "repo-b")]).unwrap();
        assert!(r.contains_key("repo-a"));
        assert!(r.contains_key("repo-b"));
        assert!(!r.contains_key("repo-c"));
        assert_eq!(r.get("repo-a").unwrap().name, "repo-a");
        assert!(r.get("repo-c").is_none());
    }

    #[test]
    fn len_and_keys_reflect_map_contents() {
        let r = resolver(&[("a", "a"), ("b", "b"), ("c", "c")]).unwrap();
        assert_eq!(r.len(), 3);
        let mut keys: Vec<&str> = r.keys().collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }
}
