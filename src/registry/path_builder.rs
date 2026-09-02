//! Legacy storage shapes, read only as a fallback and retired as scrub
//! converts stores; the whole module goes once conversion completes.
//!
//! Current-shape keys live on the type that owns them, in
//! [`crate::registry::keys`] and beside the structs that write them. The store
//! roots stay here as shared layout vocabulary because the maintenance walk
//! matches all six in one dispatch.

use angos_oci::{Digest, Namespace};

#[cfg(test)]
use crate::registry::metadata_store::LinkKind;

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

pub fn manifest_revisions_link_root_dir(namespace: &Namespace, algorithm: &str) -> String {
    format!("{REPOS_ROOT}/{namespace}/_manifests/revisions/{algorithm}")
}

pub fn manifest_tags_dir(namespace: &Namespace) -> String {
    format!("{REPOS_ROOT}/{namespace}/_manifests/tags")
}

pub fn manifest_referrers_dir(namespace: &Namespace, subject: &Digest) -> String {
    format!(
        "{REPOS_ROOT}/{namespace}/_manifests/referrers/{}/{}",
        subject.algorithm(),
        subject.hash()
    )
}

/// The legacy `link` file of a kind that had one, for the tests that still seed
/// the shape `angos migrate` rewrites and the catalog tree walks read.
#[cfg(test)]
pub fn link_path(link: &LinkKind, namespace: &Namespace) -> Option<String> {
    let container = match link {
        LinkKind::Blob(digest) => format!(
            "{REPOS_ROOT}/{namespace}/_blobs/{}/{}",
            digest.algorithm(),
            digest.hash()
        ),
        LinkKind::Tag(tag) => format!("{REPOS_ROOT}/{namespace}/_manifests/tags/{tag}/current"),
        LinkKind::Digest(digest) => format!(
            "{REPOS_ROOT}/{namespace}/_manifests/revisions/{}/{}",
            digest.algorithm(),
            digest.hash()
        ),
        LinkKind::Layer(digest) => format!(
            "{REPOS_ROOT}/{namespace}/_layers/{}/{}",
            digest.algorithm(),
            digest.hash()
        ),
        LinkKind::Config(digest) => format!(
            "{REPOS_ROOT}/{namespace}/_config/{}/{}",
            digest.algorithm(),
            digest.hash()
        ),
        LinkKind::Referrer { subject, referrer } => format!(
            "{REPOS_ROOT}/{namespace}/_manifests/referrers/{}/{}/{}/{}",
            subject.algorithm(),
            subject.hash(),
            referrer.algorithm(),
            referrer.hash()
        ),
        LinkKind::Manifest { index, child } => format!(
            "{REPOS_ROOT}/{namespace}/_manifests/index/{}/{}/{}/{}",
            index.algorithm(),
            index.hash(),
            child.algorithm(),
            child.hash()
        ),
        // A reference-key-only kind no writer ever gave a link file.
        LinkKind::ReferencedBy(_) => return None,
    };
    Some(format!("{container}/link"))
}

#[cfg(test)]
mod tests {
    use crate::registry::path_builder::*;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn test_manifest_paths() {
        let ns = Namespace::new("ns").unwrap();
        assert_eq!(
            manifest_revisions_link_root_dir(&ns, "sha256"),
            "v2/repositories/ns/_manifests/revisions/sha256"
        );
        assert_eq!(manifest_tags_dir(&ns), "v2/repositories/ns/_manifests/tags");

        let subject = Digest::sha256(HASH_A).unwrap();
        assert_eq!(
            manifest_referrers_dir(&ns, &subject),
            format!("v2/repositories/ns/_manifests/referrers/sha256/{HASH_A}")
        );
    }
}
