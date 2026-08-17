use std::str::FromStr;

use angos_oci::{Algorithm, Digest, Namespace, Tag, UploadSessionId};

use crate::registry::metadata_store::LinkKind;

pub const BLOBS_ROOT: &str = "v2/blobs";
pub const REPOS_ROOT: &str = "v2/repositories";
pub const REF_ROOT: &str = "v2/ref";

/// Root directory and namespace-name prefix for a namespace tree walk. `None`
/// walks the whole repositories tree; `Some(repository)` restricts the walk to
/// that repository's subtree while keeping the repository segment in the
/// returned namespace names.
pub fn namespace_walk_root(scope: Option<&str>) -> (String, String) {
    match scope {
        Some(repository) => (
            format!("{REPOS_ROOT}/{repository}"),
            format!("{repository}/"),
        ),
        None => (REPOS_ROOT.to_string(), String::new()),
    }
}

/// Storage prefix for a namespace's repository subtree addressed by its raw
/// on-disk name, so scrub can reclaim a directory whose name fails `Namespace`
/// validation (out-of-band corruption). Returns `None` when a path segment is
/// empty, `.`, or `..`, which could escape the repositories root.
pub fn namespace_dir(name: &str) -> Option<String> {
    if name.is_empty()
        || name
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return None;
    }
    Some(format!("{REPOS_ROOT}/{name}"))
}

pub fn blob_dir(digest: &Digest) -> String {
    format!(
        "{BLOBS_ROOT}/{}/{}/{}",
        digest.algorithm(),
        digest.hash_prefix(),
        digest.hash()
    )
}

pub fn blob_path(digest: &Digest) -> String {
    format!("{}/data", blob_dir(digest))
}

pub fn blob_index_refs_dir(digest: &Digest) -> String {
    format!("{}/refs", blob_dir(digest))
}

/// Directory holding every reference key for `digest`, one key per
/// (namespace, link). Lives under its own `v2/ref/` root so metadata keys no
/// longer interleave with the blob store's `v2/blobs/` tree.
pub fn blob_ref_dir(digest: &Digest) -> String {
    format!(
        "{REF_ROOT}/{}/{}/{}",
        digest.algorithm(),
        digest.hash_prefix(),
        digest.hash()
    )
}

/// One namespace's reference key for `digest`: ownership is the `<ns>!own`
/// leaf, every other link kind is a leaf under the `<ns>!r/` subtree. `!`
/// terminates the namespace: it is outside the namespace grammar so the name
/// always parses back out, and it keeps namespace `a`'s leaves from colliding
/// with namespace `a/b`'s directories on FS.
pub fn blob_ref_path(digest: &Digest, namespace: &Namespace, link: &LinkKind) -> String {
    format!("{}/{namespace}!{}", blob_ref_dir(digest), ref_entry(link))
}

pub fn blob_ref_own_path(digest: &Digest, namespace: &Namespace) -> String {
    format!("{}/{namespace}!own", blob_ref_dir(digest))
}

/// Directory holding `namespace`'s non-ownership reference keys for `digest`.
/// A directory boundary on both backends, so it lists without partial-name
/// prefix support.
pub fn blob_ref_namespace_dir(digest: &Digest, namespace: &Namespace) -> String {
    format!("{}/{namespace}!r", blob_ref_dir(digest))
}

/// The key tail after `<ns>!`. The digest-bearing kinds omit digests equal to
/// the blob's own (which is what their insertion always targets) and spell
/// out only the foreign one: a referrer entry names its subject, an index
/// child entry names its index.
fn ref_entry(link: &LinkKind) -> String {
    match link {
        LinkKind::Blob(_) => "own".to_string(),
        LinkKind::Digest(_) => "r/rev".to_string(),
        LinkKind::Layer(_) => "r/layer".to_string(),
        LinkKind::Config(_) => "r/config".to_string(),
        LinkKind::Tag(tag) => format!("r/tag.{tag}"),
        LinkKind::Referrer { subject, .. } => {
            format!("r/sub.{}.{}", subject.algorithm(), subject.hash())
        }
        LinkKind::Manifest { index, .. } => {
            format!("r/idx.{}.{}", index.algorithm(), index.hash())
        }
    }
}

/// Decode one key of [`blob_ref_dir`] (relative to that directory) back into
/// its raw namespace (validity is the caller's concern) and the link it
/// records. `None` means the key is not a shape this version writes.
pub fn parse_blob_ref(digest: &Digest, key: &str) -> Option<(String, LinkKind)> {
    let (namespace, entry) = key.split_once('!')?;
    let link = match entry.strip_prefix("r/") {
        None => (entry == "own").then(|| LinkKind::Blob(digest.clone()))?,
        Some(entry) => parse_blob_ref_entry(digest, entry)?,
    };
    Some((namespace.to_string(), link))
}

/// Decode one key of [`blob_ref_namespace_dir`] (relative to that directory).
pub fn parse_blob_ref_entry(digest: &Digest, entry: &str) -> Option<LinkKind> {
    match entry {
        "rev" => Some(LinkKind::Digest(digest.clone())),
        "layer" => Some(LinkKind::Layer(digest.clone())),
        "config" => Some(LinkKind::Config(digest.clone())),
        _ => {
            if let Some(tag) = entry.strip_prefix("tag.") {
                Some(LinkKind::Tag(Tag::new(tag).ok()?))
            } else if let Some(subject) = entry.strip_prefix("sub.") {
                Some(LinkKind::Referrer {
                    subject: parse_ref_digest(subject)?,
                    referrer: digest.clone(),
                })
            } else if let Some(index) = entry.strip_prefix("idx.") {
                Some(LinkKind::Manifest {
                    index: parse_ref_digest(index)?,
                    child: digest.clone(),
                })
            } else {
                None
            }
        }
    }
}

/// `<algo>.<hash>` inside a reference-key entry. `.` separates unambiguously:
/// algorithm names never contain it.
fn parse_ref_digest(s: &str) -> Option<Digest> {
    let (algorithm, hash) = s.split_once('.')?;
    Digest::with_algorithm(Algorithm::from_str(algorithm).ok()?, hash).ok()
}

pub fn blob_index_shard_path(digest: &Digest, namespace: &Namespace) -> String {
    // Encode namespace as a safe filename: percent-encode '/' and '%' to avoid
    // ambiguity (namespaces can contain underscores, so '/' -> '_' is lossy).
    let safe_ns = namespace.replace('%', "%25").replace('/', "%2F");
    format!("{}/refs/{safe_ns}.json", blob_dir(digest))
}

/// Root directory holding every upload container for a namespace. Used to
/// enumerate the namespace's active sessions (one child directory per session).
pub fn uploads_root_dir(namespace: &Namespace) -> String {
    format!("{REPOS_ROOT}/{namespace}/_uploads")
}

pub fn upload_container_path(namespace: &Namespace, session_id: &UploadSessionId) -> String {
    format!("{REPOS_ROOT}/{namespace}/_uploads/{session_id}")
}

pub fn upload_path(namespace: &Namespace, session_id: &UploadSessionId) -> String {
    format!("{REPOS_ROOT}/{namespace}/_uploads/{session_id}/data")
}

/// Directory holding an upload's hasher-state checkpoints, one file per offset.
/// Used to enumerate checkpoints and pick the most recent.
pub fn upload_hash_context_dir(namespace: &Namespace, session_id: &UploadSessionId) -> String {
    format!("{REPOS_ROOT}/{namespace}/_uploads/{session_id}/hashstates")
}

/// An upload's serialised hasher-state checkpoint after consuming its bytes up
/// to `offset`. One file per offset, allowing hash resumption after a crash
/// without re-reading the uploaded bytes.
pub fn upload_hash_context_path(
    namespace: &Namespace,
    session_id: &UploadSessionId,
    offset: u64,
) -> String {
    format!("{REPOS_ROOT}/{namespace}/_uploads/{session_id}/hashstates/{offset}")
}

/// RFC3339 timestamp marking when the upload session was created. Used for
/// age-based orphan detection during scrub.
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

pub fn link_path(link: &LinkKind, namespace: &Namespace) -> String {
    format!("{}/link", link_container_path(link, namespace))
}

pub fn link_container_path(link: &LinkKind, namespace: &Namespace) -> String {
    match link {
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
    }
}

#[cfg(test)]
mod tests {
    use angos_oci::Tag;

    use crate::registry::path_builder::*;

    // Valid 64-char lowercase-hex sha256 hashes (the only shape `Digest` accepts).
    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    // Valid 128-char lowercase-hex sha512 hash.
    const HASH_512: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[test]
    fn test_blob_paths() {
        let digest = Digest::sha256(HASH_A).unwrap();
        assert_eq!(
            blob_path(&digest),
            format!("v2/blobs/sha256/aa/{HASH_A}/data")
        );
        assert_eq!(blob_dir(&digest), format!("v2/blobs/sha256/aa/{HASH_A}"));
    }

    #[test]
    fn test_blob_paths_sha512() {
        let digest = Digest::sha512(HASH_512).unwrap();
        assert_eq!(
            blob_path(&digest),
            format!("v2/blobs/sha512/cc/{HASH_512}/data")
        );
    }

    #[test]
    fn test_upload_paths() {
        let ns = Namespace::new("ns").unwrap();
        let id = UploadSessionId::new("067e6162-3b6f-4ae2-a171-2470b63dff00").unwrap();
        assert_eq!(
            upload_container_path(&ns, &id),
            format!("v2/repositories/ns/_uploads/{id}")
        );
        assert_eq!(
            upload_path(&ns, &id),
            format!("v2/repositories/ns/_uploads/{id}/data")
        );
        assert_eq!(uploads_root_dir(&ns), "v2/repositories/ns/_uploads");
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
    fn test_namespace_dir() {
        assert_eq!(namespace_dir("ns").unwrap(), "v2/repositories/ns");
        assert_eq!(namespace_dir("org/app").unwrap(), "v2/repositories/org/app");
        // Uppercase fails `Namespace` validation but is safe as a directory name.
        assert_eq!(namespace_dir("BadNS").unwrap(), "v2/repositories/BadNS");
        // Empty, traversal, and empty-segment names are rejected.
        for unsafe_name in ["", "..", ".", "a/../b", "a//b", "/a", "a/", "a/."] {
            assert!(
                namespace_dir(unsafe_name).is_none(),
                "'{unsafe_name}' must be rejected"
            );
        }
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

    /// Every link kind's reference key must decode back to the namespace and
    /// link it was built from, digest-bearing kinds included.
    #[test]
    fn blob_ref_paths_round_trip() {
        let ns = Namespace::new("org/app").unwrap();
        let digest = Digest::sha256(HASH_A).unwrap();
        let other = Digest::sha256(HASH_B).unwrap();
        let links = [
            LinkKind::Blob(digest.clone()),
            LinkKind::Digest(digest.clone()),
            LinkKind::Layer(digest.clone()),
            LinkKind::Config(digest.clone()),
            LinkKind::Tag(Tag::new("v1.2-rc.1_x").unwrap()),
            LinkKind::Referrer {
                subject: other.clone(),
                referrer: digest.clone(),
            },
            LinkKind::Manifest {
                index: other.clone(),
                child: digest.clone(),
            },
        ];
        let dir = blob_ref_dir(&digest);
        for link in links {
            let key = blob_ref_path(&digest, &ns, &link);
            let relative = key.strip_prefix(&format!("{dir}/")).unwrap();
            assert_eq!(
                parse_blob_ref(&digest, relative),
                Some(("org/app".to_string(), link.clone())),
                "{link} must round-trip through its reference key"
            );
        }
    }

    #[test]
    fn blob_ref_own_and_namespace_dirs_agree_with_the_full_paths() {
        let ns = Namespace::new("org/app").unwrap();
        let digest = Digest::sha256(HASH_A).unwrap();
        assert_eq!(
            blob_ref_own_path(&digest, &ns),
            blob_ref_path(&digest, &ns, &LinkKind::Blob(digest.clone()))
        );
        let layer_key = blob_ref_path(&digest, &ns, &LinkKind::Layer(digest.clone()));
        assert_eq!(
            layer_key,
            format!("{}/layer", blob_ref_namespace_dir(&digest, &ns))
        );
    }

    #[test]
    fn foreign_ref_shapes_do_not_parse() {
        let digest = Digest::sha256(HASH_A).unwrap();
        for key in [
            "ns",
            "ns!x",
            "ns!r/unknown",
            "ns!r/tag.",
            "ns!r/sub.sha256",
            "ns!r/sub.sha3.abcd",
            &format!("ns!r/idx.sha256.{}", "z".repeat(64)),
        ] {
            assert_eq!(parse_blob_ref(&digest, key), None, "key {key:?}");
        }
    }

    #[test]
    fn test_link_paths() {
        let ns = Namespace::new("ns").unwrap();
        let digest = Digest::sha256(HASH_A).unwrap();

        let blob = LinkKind::Blob(digest.clone());
        assert_eq!(
            link_path(&blob, &ns),
            format!("v2/repositories/ns/_blobs/sha256/{HASH_A}/link")
        );
        assert_eq!(
            link_container_path(&blob, &ns),
            format!("v2/repositories/ns/_blobs/sha256/{HASH_A}")
        );

        let tag = LinkKind::Tag(Tag::new("v1.0").unwrap());
        assert_eq!(
            link_path(&tag, &ns),
            "v2/repositories/ns/_manifests/tags/v1.0/current/link"
        );
        assert_eq!(
            link_container_path(&tag, &ns),
            "v2/repositories/ns/_manifests/tags/v1.0/current"
        );

        let revision = LinkKind::Digest(digest.clone());
        assert_eq!(
            link_path(&revision, &ns),
            format!("v2/repositories/ns/_manifests/revisions/sha256/{HASH_A}/link")
        );
        assert_eq!(
            link_container_path(&revision, &ns),
            format!("v2/repositories/ns/_manifests/revisions/sha256/{HASH_A}")
        );

        let layer = LinkKind::Layer(digest.clone());
        assert_eq!(
            link_path(&layer, &ns),
            format!("v2/repositories/ns/_layers/sha256/{HASH_A}/link")
        );
        assert_eq!(
            link_container_path(&layer, &ns),
            format!("v2/repositories/ns/_layers/sha256/{HASH_A}")
        );

        let config = LinkKind::Config(digest.clone());
        assert_eq!(
            link_path(&config, &ns),
            format!("v2/repositories/ns/_config/sha256/{HASH_A}/link")
        );
        assert_eq!(
            link_container_path(&config, &ns),
            format!("v2/repositories/ns/_config/sha256/{HASH_A}")
        );

        let subject = Digest::sha256(HASH_A).unwrap();
        let referrer = Digest::sha256(HASH_B).unwrap();
        let referrer_link = LinkKind::Referrer { subject, referrer };
        assert_eq!(
            link_path(&referrer_link, &ns),
            format!("v2/repositories/ns/_manifests/referrers/sha256/{HASH_A}/sha256/{HASH_B}/link")
        );
        assert_eq!(
            link_container_path(&referrer_link, &ns),
            format!("v2/repositories/ns/_manifests/referrers/sha256/{HASH_A}/sha256/{HASH_B}")
        );

        let index = Digest::sha256(HASH_A).unwrap();
        let child = Digest::sha256(HASH_B).unwrap();
        let manifest_link = LinkKind::Manifest { index, child };
        assert_eq!(
            link_path(&manifest_link, &ns),
            format!("v2/repositories/ns/_manifests/index/sha256/{HASH_A}/sha256/{HASH_B}/link")
        );
        assert_eq!(
            link_container_path(&manifest_link, &ns),
            format!("v2/repositories/ns/_manifests/index/sha256/{HASH_A}/sha256/{HASH_B}")
        );
    }
}
