use std::str::FromStr;

use chrono::{DateTime, Utc};

use angos_oci::{Algorithm, Digest, Namespace, Tag, UploadSessionId};

use crate::registry::metadata_store::LinkKind;

pub const BLOBS_ROOT: &str = "v2/blobs";
pub const REPOS_ROOT: &str = "v2/repositories";
pub const REF_ROOT: &str = "v2/ref";
pub const NS_ROOT: &str = "v2/ns";
pub const CAT_ROOT: &str = "v2/cat";
pub const GC_ROOT: &str = "v2/gc";

/// One collector run's range marker: the only key a writer and the collector
/// both consult.
pub fn gc_run_path(run: &str) -> String {
    format!("{GC_ROOT}/{run}")
}

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
        LinkKind::ReferencedBy(referrer) => {
            format!("r/{}.{}", referrer.algorithm(), referrer.hash())
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
                // A bare `<algo>.<hash>` names the referring manifest.
                // Unambiguous against the prefixed shapes: no algorithm is
                // named `rev`, `layer`, `config`, `tag`, `sub`, or `idx`.
                Some(LinkKind::ReferencedBy(parse_ref_digest(entry)?))
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

/// Directory holding every tag-entry directory of `namespace`. `!` terminates
/// the namespace for the same reasons as the reference keys.
pub fn tag_entries_root(namespace: &Namespace) -> String {
    format!("{NS_ROOT}/{namespace}!tag")
}

/// Directory holding one tag's ordered entries. The `!` suffix keeps a name
/// that is a prefix of another (`v1`, `v1.1`) sorting first in a flat listing,
/// which is what lets the tag list serve lexical order straight off it.
pub fn tag_entry_dir(namespace: &Namespace, tag: &Tag) -> String {
    format!("{}/{tag}!", tag_entries_root(namespace))
}

/// One tag event: `<ord>.<kind>.<algo>.<hash>`, where `<ord>` inverts the
/// author's unix-millisecond timestamp so entries list newest first, and
/// `<kind>` is `set` or `del` (a deletion still names the digest the tag
/// held, which tag history requires).
pub fn tag_entry_path(
    namespace: &Namespace,
    tag: &Tag,
    ord: u64,
    deletion: bool,
    digest: &Digest,
) -> String {
    let kind = if deletion { "del" } else { "set" };
    format!(
        "{}/{ord:016x}.{kind}.{}.{}",
        tag_entry_dir(namespace, tag),
        digest.algorithm(),
        digest.hash()
    )
}

/// Directory holding every demoted tag-history directory of `namespace`.
/// Nothing reads `!hist/` yet: it retains superseded entries for the future
/// tag-history endpoint while `!tag/` keeps only each tag's current group.
pub fn tag_hist_root(namespace: &Namespace) -> String {
    format!("{NS_ROOT}/{namespace}!hist")
}

/// Directory holding one tag's demoted entries, `!`-terminated like
/// [`tag_entry_dir`].
pub fn tag_hist_dir(namespace: &Namespace, tag: &Tag) -> String {
    format!("{}/{tag}!", tag_hist_root(namespace))
}

/// A demoted entry keeps its [`tag_entry_path`] file name, so history stays
/// in newest-first order.
pub fn tag_hist_path(namespace: &Namespace, tag: &Tag, entry_name: &str) -> String {
    format!("{}/{entry_name}", tag_hist_dir(namespace, tag))
}

/// Advisory last-pull timestamp for a tag, overwritten in place. Kept apart
/// from the write-once entries so those never mutate.
pub fn tag_atime_path(namespace: &Namespace, tag: &Tag) -> String {
    format!("{NS_ROOT}/{namespace}!atime/tag/{tag}")
}

/// One namespace's catalog index key: empty, write-once, one per namespace.
/// The `!` terminator is what lets `a` and `a/b` coexist on FS (a file cannot
/// also be a directory) while keeping the flat listing in lexical order.
pub fn catalog_index_path(namespace: &Namespace) -> String {
    format!("{CAT_ROOT}/{namespace}!")
}

/// The immutable record of a stored manifest revision. Its existence is what
/// makes the digest resolvable; its body carries what a HEAD needs.
pub fn revision_record_path(namespace: &Namespace, digest: &Digest) -> String {
    format!(
        "{}/{}/{}/{}",
        revision_records_root(namespace),
        digest.algorithm(),
        digest.hash_prefix(),
        digest.hash()
    )
}

/// Directory holding every revision record of `namespace`.
pub fn revision_records_root(namespace: &Namespace) -> String {
    format!("{NS_ROOT}/{namespace}!rev")
}

/// Directory holding `subject`'s referrer records: one key per referring
/// manifest, whose body is that manifest's descriptor.
pub fn referrer_record_dir(namespace: &Namespace, subject: &Digest) -> String {
    format!(
        "{NS_ROOT}/{namespace}!sub/{}/{}/{}",
        subject.algorithm(),
        subject.hash_prefix(),
        subject.hash()
    )
}

pub fn referrer_record_path(namespace: &Namespace, subject: &Digest, referrer: &Digest) -> String {
    format!(
        "{}/{}.{}",
        referrer_record_dir(namespace, subject),
        referrer.algorithm(),
        referrer.hash()
    )
}

/// Advisory last-pull timestamp for a manifest revision, overwritten in
/// place, kept apart from the immutable record it annotates.
pub fn revision_atime_path(namespace: &Namespace, digest: &Digest) -> String {
    format!(
        "{NS_ROOT}/{namespace}!atime/rev/{}/{}",
        digest.algorithm(),
        digest.hash()
    )
}

/// The inverted-timestamp ordinal of `ts`: entries sort newest first.
/// `u64::MAX` is reserved for a missing timestamp: it sorts last and never
/// wins resolution, mirroring how a link without `created_at` never won
/// last-writer-wins, and stays distinct from a real epoch timestamp.
pub fn tag_ord(ts: Option<DateTime<Utc>>) -> u64 {
    match ts {
        None => u64::MAX,
        Some(ts) => u64::MAX - 1 - ts.timestamp_millis().max(0).unsigned_abs(),
    }
}

/// The author timestamp `ord` encodes; `None` for the never-wins ordinal.
pub fn tag_ord_ts(ord: u64) -> Option<DateTime<Utc>> {
    if ord == u64::MAX {
        return None;
    }
    DateTime::from_timestamp_millis(i64::try_from(u64::MAX - 1 - ord).ok()?)
}

/// Decode one entry filename of [`tag_entry_dir`] back into
/// `(ord, deletion, digest)`. `None` = not a shape this version writes.
pub fn parse_tag_entry(name: &str) -> Option<(u64, bool, Digest)> {
    let mut parts = name.splitn(4, '.');
    let (Some(ord), Some(kind), Some(algorithm), Some(hash)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if ord.len() != 16 {
        return None;
    }
    let ord = u64::from_str_radix(ord, 16).ok()?;
    let deletion = match kind {
        "set" => false,
        "del" => true,
        _ => return None,
    };
    let digest = Digest::with_algorithm(Algorithm::from_str(algorithm).ok()?, hash).ok()?;
    Some((ord, deletion, digest))
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
        // No writer ever creates this path; it exists only so the match is
        // total. Reads of it yield NotFound and every caller treats that as
        // absent/unbacked.
        LinkKind::ReferencedBy(referrer) => {
            format!(
                "{REPOS_ROOT}/{namespace}/_refs/referenced-by/{}/{}",
                referrer.algorithm(),
                referrer.hash()
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

    /// The whole listing story rests on `!` sorting below every byte a
    /// namespace or tag can contain, so a name that is a prefix of another
    /// sorts first and flat listings yield true lexical order. A grammar
    /// relaxation admitting a lower byte would break tag ordering silently.
    #[test]
    fn the_separator_sorts_below_both_grammars() {
        let namespace_alphabet = "abcdefghijklmnopqrstuvwxyz0123456789._-/";
        let tag_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
        for byte in namespace_alphabet.bytes().chain(tag_alphabet.bytes()) {
            assert!(
                b'!' < byte,
                "'!' must sort below {:?} or listings lose lexical order",
                byte as char
            );
        }
    }

    #[test]
    fn tag_entries_round_trip_and_sort_newest_first() {
        let ns = Namespace::new("org/app").unwrap();
        let tag = Tag::new("v1").unwrap();
        let digest = Digest::sha256(HASH_A).unwrap();
        let older = DateTime::from_timestamp_millis(1_000_000).unwrap();
        let newer = DateTime::from_timestamp_millis(2_000_000).unwrap();

        let older_key = tag_entry_path(&ns, &tag, tag_ord(Some(older)), false, &digest);
        let newer_key = tag_entry_path(&ns, &tag, tag_ord(Some(newer)), true, &digest);
        assert!(
            newer_key < older_key,
            "a newer entry must sort before an older one"
        );

        let file = newer_key.rsplit_once('/').unwrap().1;
        assert_eq!(
            parse_tag_entry(file),
            Some((tag_ord(Some(newer)), true, digest.clone()))
        );
        assert_eq!(tag_ord_ts(tag_ord(Some(newer))), Some(newer));
        assert_eq!(tag_ord_ts(tag_ord(None)), None, "the never-wins ordinal");
        assert!(
            tag_ord(None) > tag_ord(Some(DateTime::from_timestamp_millis(0).unwrap())),
            "a missing timestamp must sort after a real epoch one"
        );
    }

    #[test]
    fn tag_hist_paths_mirror_tag_entry_paths() {
        let ns = Namespace::new("org/app").unwrap();
        let tag = Tag::new("v1").unwrap();
        let digest = Digest::sha256(HASH_A).unwrap();
        let entry_key = tag_entry_path(&ns, &tag, 7, true, &digest);
        let file = entry_key.rsplit_once('/').unwrap().1;
        let hist_key = tag_hist_path(&ns, &tag, file);
        assert_eq!(hist_key, format!("v2/ns/org/app!hist/v1!/{file}"));
        assert_eq!(hist_key, format!("{}/{file}", tag_hist_dir(&ns, &tag)));
        assert!(hist_key.starts_with(&format!("{}/", tag_hist_root(&ns))));
        assert_eq!(parse_tag_entry(file), Some((7, true, digest)));
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
            LinkKind::ReferencedBy(other.clone()),
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
            "ns!r/sha256",
            "ns!r/sha3.abcd",
            &format!("ns!r/sha256.{}", "z".repeat(64)),
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
