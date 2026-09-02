//! Legacy storage shapes, read only as a fallback and retired as scrub
//! converts stores; the whole module goes once conversion completes.
//!
//! Current-shape keys live on the type that owns them, in
//! [`crate::registry::keys`] and beside the structs that write them. The store
//! roots stay here as shared layout vocabulary because the maintenance walk
//! matches all six in one dispatch.

use angos_oci::{Digest, Namespace, Tag, UploadSessionId};

use crate::registry::{keys::DigestKeys, metadata_store::LinkKind};

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

/// Directory of a blob's legacy per-namespace shard files.
pub fn blob_index_refs_dir(digest: &Digest) -> String {
    format!("{}/refs", digest.blob_dir())
}

/// One namespace's legacy shard file listing its links to a blob.
pub fn blob_index_shard_path(digest: &Digest, namespace: &Namespace) -> String {
    // Percent-encoded rather than mapped to '_': namespaces can contain
    // underscores, so that substitution would not round-trip.
    let safe_ns = namespace.replace('%', "%25").replace('/', "%2F");
    format!("{}/refs/{safe_ns}.json", digest.blob_dir())
}

/// Legacy advisory last-pull timestamp for a tag.
pub fn tag_atime_path(namespace: &Namespace, tag: &Tag) -> String {
    format!("{NS_ROOT}/{namespace}!atime/tag/{tag}")
}

/// Legacy advisory last-pull timestamp for a manifest revision.
pub fn revision_atime_path(namespace: &Namespace, digest: &Digest) -> String {
    format!(
        "{NS_ROOT}/{namespace}!atime/rev/{}/{}",
        digest.algorithm(),
        digest.hash()
    )
}

/// Legacy directory of per-offset hasher-state checkpoints, read only as a
/// fallback when `session.json` is absent.
pub fn upload_hash_context_dir(namespace: &Namespace, session_id: &UploadSessionId) -> String {
    format!("{REPOS_ROOT}/{namespace}/_uploads/{session_id}/hashstates")
}

/// One legacy hasher-state checkpoint after consuming the upload's bytes up to
/// `offset`.
pub fn upload_hash_context_path(
    namespace: &Namespace,
    session_id: &UploadSessionId,
    offset: u64,
) -> String {
    format!("{REPOS_ROOT}/{namespace}/_uploads/{session_id}/hashstates/{offset}")
}

/// Legacy RFC3339 last-activity marker, read only as a fallback when
/// `session.json` is absent.
pub fn upload_start_date_path(namespace: &Namespace, session_id: &UploadSessionId) -> String {
    format!("{REPOS_ROOT}/{namespace}/_uploads/{session_id}/startedat")
}

pub fn manifest_revisions_link_root_dir(namespace: &Namespace, algorithm: &str) -> String {
    format!("{REPOS_ROOT}/{namespace}/_manifests/revisions/{algorithm}")
}

pub fn manifest_tags_dir(namespace: &Namespace) -> String {
    format!("{REPOS_ROOT}/{namespace}/_manifests/tags")
}

/// Directory holding a single tag's `current/link`. Scrub uses this to remove a
/// tag directory whose name is invalid (and so cannot form a `LinkKind::Tag`).
pub fn manifest_tag_dir(namespace: &Namespace, tag: &str) -> String {
    format!("{REPOS_ROOT}/{namespace}/_manifests/tags/{tag}")
}

pub fn manifest_referrers_dir(namespace: &Namespace, subject: &Digest) -> String {
    format!(
        "{REPOS_ROOT}/{namespace}/_manifests/referrers/{}/{}",
        subject.algorithm(),
        subject.hash()
    )
}

/// `None` for the kinds that have no legacy link file.
pub fn link_path(link: &LinkKind, namespace: &Namespace) -> Option<String> {
    Some(format!("{}/link", link_container_path(link, namespace)?))
}

/// `None` for [`LinkKind::ReferencedBy`], a reference-key-only kind no writer
/// ever gave a link file.
fn link_container_path(link: &LinkKind, namespace: &Namespace) -> Option<String> {
    let path = match link {
        LinkKind::Blob(digest) => {
            format!(
                "{REPOS_ROOT}/{namespace}/_blobs/{}/{}",
                digest.algorithm(),
                digest.hash()
            )
        }
        LinkKind::Tag(tag) => {
            format!("{REPOS_ROOT}/{namespace}/_manifests/tags/{tag}/current")
        }
        LinkKind::Digest(digest) => {
            format!(
                "{REPOS_ROOT}/{namespace}/_manifests/revisions/{}/{}",
                digest.algorithm(),
                digest.hash()
            )
        }
        LinkKind::Layer(digest) => {
            format!(
                "{REPOS_ROOT}/{namespace}/_layers/{}/{}",
                digest.algorithm(),
                digest.hash()
            )
        }
        LinkKind::Config(digest) => {
            format!(
                "{REPOS_ROOT}/{namespace}/_config/{}/{}",
                digest.algorithm(),
                digest.hash()
            )
        }
        LinkKind::Referrer { subject, referrer } => {
            format!(
                "{REPOS_ROOT}/{namespace}/_manifests/referrers/{}/{}/{}/{}",
                subject.algorithm(),
                subject.hash(),
                referrer.algorithm(),
                referrer.hash()
            )
        }
        LinkKind::Manifest { index, child } => {
            format!(
                "{REPOS_ROOT}/{namespace}/_manifests/index/{}/{}/{}/{}",
                index.algorithm(),
                index.hash(),
                child.algorithm(),
                child.hash()
            )
        }
        LinkKind::ReferencedBy(_) => return None,
    };
    Some(path)
}

#[cfg(test)]
mod tests {
    use crate::registry::path_builder::*;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn test_upload_paths() {
        let ns = Namespace::new("ns").unwrap();
        let id = UploadSessionId::new("067e6162-3b6f-4ae2-a171-2470b63dff00").unwrap();
        assert_eq!(
            upload_hash_context_path(&ns, &id, 42),
            format!("v2/repositories/ns/_uploads/{id}/hashstates/42")
        );
        assert_eq!(
            upload_start_date_path(&ns, &id),
            format!("v2/repositories/ns/_uploads/{id}/startedat")
        );
    }

    #[test]
    fn test_manifest_paths() {
        let ns = Namespace::new("ns").unwrap();
        assert_eq!(
            manifest_revisions_link_root_dir(&ns, "sha256"),
            "v2/repositories/ns/_manifests/revisions/sha256"
        );
        assert_eq!(manifest_tags_dir(&ns), "v2/repositories/ns/_manifests/tags");
        assert_eq!(
            manifest_tag_dir(&ns, "v1.0"),
            "v2/repositories/ns/_manifests/tags/v1.0"
        );

        let subject = Digest::sha256(HASH_A).unwrap();
        assert_eq!(
            manifest_referrers_dir(&ns, &subject),
            format!("v2/repositories/ns/_manifests/referrers/sha256/{HASH_A}")
        );
    }

    #[test]
    fn test_link_paths() {
        let ns = Namespace::new("ns").unwrap();
        let digest = Digest::sha256(HASH_A).unwrap();

        let blob = LinkKind::Blob(digest.clone());
        assert_eq!(
            link_path(&blob, &ns).unwrap(),
            format!("v2/repositories/ns/_blobs/sha256/{HASH_A}/link")
        );
        assert_eq!(
            link_container_path(&blob, &ns).unwrap(),
            format!("v2/repositories/ns/_blobs/sha256/{HASH_A}")
        );

        let tag = LinkKind::Tag(Tag::new("v1.0").unwrap());
        assert_eq!(
            link_path(&tag, &ns).unwrap(),
            "v2/repositories/ns/_manifests/tags/v1.0/current/link"
        );
        assert_eq!(
            link_container_path(&tag, &ns).unwrap(),
            "v2/repositories/ns/_manifests/tags/v1.0/current"
        );

        let revision = LinkKind::Digest(digest.clone());
        assert_eq!(
            link_path(&revision, &ns).unwrap(),
            format!("v2/repositories/ns/_manifests/revisions/sha256/{HASH_A}/link")
        );
        assert_eq!(
            link_container_path(&revision, &ns).unwrap(),
            format!("v2/repositories/ns/_manifests/revisions/sha256/{HASH_A}")
        );

        let layer = LinkKind::Layer(digest.clone());
        assert_eq!(
            link_path(&layer, &ns).unwrap(),
            format!("v2/repositories/ns/_layers/sha256/{HASH_A}/link")
        );
        assert_eq!(
            link_container_path(&layer, &ns).unwrap(),
            format!("v2/repositories/ns/_layers/sha256/{HASH_A}")
        );

        let config = LinkKind::Config(digest.clone());
        assert_eq!(
            link_path(&config, &ns).unwrap(),
            format!("v2/repositories/ns/_config/sha256/{HASH_A}/link")
        );
        assert_eq!(
            link_container_path(&config, &ns).unwrap(),
            format!("v2/repositories/ns/_config/sha256/{HASH_A}")
        );

        let subject = Digest::sha256(HASH_A).unwrap();
        let referrer = Digest::sha256(HASH_B).unwrap();
        let referrer_link = LinkKind::Referrer { subject, referrer };
        assert_eq!(
            link_path(&referrer_link, &ns).unwrap(),
            format!("v2/repositories/ns/_manifests/referrers/sha256/{HASH_A}/sha256/{HASH_B}/link")
        );
        assert_eq!(
            link_container_path(&referrer_link, &ns).unwrap(),
            format!("v2/repositories/ns/_manifests/referrers/sha256/{HASH_A}/sha256/{HASH_B}")
        );

        let index = Digest::sha256(HASH_A).unwrap();
        let child = Digest::sha256(HASH_B).unwrap();
        let manifest_link = LinkKind::Manifest { index, child };
        assert_eq!(
            link_path(&manifest_link, &ns).unwrap(),
            format!("v2/repositories/ns/_manifests/index/sha256/{HASH_A}/sha256/{HASH_B}/link")
        );
        assert_eq!(
            link_container_path(&manifest_link, &ns).unwrap(),
            format!("v2/repositories/ns/_manifests/index/sha256/{HASH_A}/sha256/{HASH_B}")
        );
    }
}
