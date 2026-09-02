//! The store roots, shared layout vocabulary because the maintenance walk
//! matches all six in one dispatch.
//!
//! Every other key lives on the type that owns it, in
//! [`crate::registry::keys`] and beside the structs that write them.

pub const BLOBS_ROOT: &str = "v2/blobs";
pub const REPOS_ROOT: &str = "v2/repositories";
pub const REF_ROOT: &str = "v2/ref";
pub const NS_ROOT: &str = "v2/ns";
pub const CAT_ROOT: &str = "v2/cat";
pub const GC_ROOT: &str = "v2/gc";

/// Root directory and namespace-name prefix for a namespace tree walk;
/// `Some(repository)` restricts the walk to that repository's subtree while
/// keeping the repository segment in the returned namespace names.
pub fn namespace_walk_root(scope: Option<&str>) -> (String, String) {
    match scope {
        Some(repository) => (
            format!("{REPOS_ROOT}/{repository}"),
            format!("{repository}/"),
        ),
        None => (REPOS_ROOT.to_string(), String::new()),
    }
}
