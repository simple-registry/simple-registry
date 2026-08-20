//! Pure key categorization for the maintenance walks (scrub, prune's sweeps).
//!
//! [`categorize`] maps a raw object-store key onto the union of both stores'
//! layouts (the blob and metadata stores can share one physical root, so a
//! walk of either may see the other's keys). It performs no I/O; validation
//! of an object's content and references happens in `validate`.
//!
//! A key that matches no known shape is [`KeyCategory::Unknown`] and gets
//! quarantined under the lost-and-found prefix, so a shape a newer angos
//! version writes is recoverable rather than destroyed.

use std::str::FromStr;

use angos_oci::{Algorithm, Digest, Namespace, Tag, UploadSessionId};

use crate::command::maintenance::action::LOST_AND_FOUND_PREFIX;
use crate::{
    jobs::{JobState, Queue, store::JOBS_ROOT},
    registry::{
        metadata_store::{LinkKind, decode_blob_index_shard_namespace},
        path_builder::{
            BLOBS_ROOT, CAT_ROOT, GC_ROOT, NS_ROOT, REF_ROOT, REPOS_ROOT, parse_atime_entry,
            parse_blob_ref, parse_tag_entry,
        },
    },
};

/// Everything a key in either store can be.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyCategory {
    /// `v2/blobs/{alg}/{prefix}/{hash}/data` (blob store).
    BlobData { digest: Digest },
    /// `v2/blobs/{alg}/{prefix}/{hash}/refs/{encoded-ns}.json` (metadata store).
    BlobIndexShard { digest: Digest, namespace: String },
    /// `v2/ref/{alg}/{prefix}/{hash}/{ns}!own` or `.../{ns}!r/{entry}`
    /// (metadata store). The namespace is raw: its validity is a validation
    /// concern.
    BlobRef {
        digest: Digest,
        namespace: String,
        link: LinkKind,
    },
    /// `v2/ns/{ns}!tag/{tag}!/{ord}.{kind}.{alg}.{hash}` (metadata store): one
    /// write-once tag event. Grammars are checked at categorization, so both
    /// names are known valid.
    TagEntry { namespace: String, tag: String },
    /// `v2/ns/{ns}!hist/{tag}!/{ord}.{kind}.{alg}.{hash}` (metadata store):
    /// one demoted tag-history entry, write-once and never validated.
    TagHistory,
    /// `v2/ns/{ns}!atime/tag/{tag}` or `v2/ns/{ns}!atime/rev/{alg}/{hash}`
    /// (metadata store): a legacy advisory last-pull timestamp, retired once
    /// an access entry exists.
    TagAccessTime,
    /// `v2/ns/{ns}!atime/tag/{tag}!/{ord}.{suffix}` (metadata store): one
    /// append-only tag access entry. Grammars are checked at categorization.
    TagAtimeEntry { namespace: String, tag: String },
    /// `v2/ns/{ns}!atime/rev/{alg}/{hash}!/{ord}.{suffix}` (metadata store):
    /// one append-only revision access entry.
    RevisionAtimeEntry { namespace: String, digest: Digest },
    /// `v2/ns/{ns}!rev/{alg}/{prefix}/{hash}` (metadata store): the immutable
    /// record of a stored manifest revision.
    RevisionRecord { namespace: String, digest: Digest },
    /// `v2/ns/{ns}!sub/{alg}/{prefix}/{hash}/{r-alg}.{r-hash}` (metadata
    /// store): one referrer record under its subject.
    ReferrerRecord {
        namespace: String,
        subject: Digest,
        referrer: Digest,
    },
    /// `v2/cat/{ns}!` (metadata store): a namespace's catalog index key.
    CatalogIndex { namespace: String },
    /// A link file under `v2/repositories/{ns}/...` (metadata store). The
    /// namespace is raw: its validity is a validation concern.
    Link { namespace: String, link: ParsedLink },
    /// An upload-session artifact under `v2/repositories/{ns}/_uploads/{uuid}/`
    /// (blob store).
    UploadArtifact {
        namespace: String,
        artifact: UploadArtifact,
    },
    /// A pending or dead-lettered job envelope (metadata store).
    JobRecord { queue: Queue, state: JobState },
    /// A `lock_key` dedup index entry (metadata store).
    JobIndex { queue: Queue },
    /// A worker's leased claim key under `_jobs/claims/` (metadata store).
    JobClaim,
    /// A collector run marker under `v2/gc/` (metadata store). The one key a
    /// writer and the collector must both observe; the walk recognizes it and
    /// never touches it (a crashed run's marker expires by its own TTL).
    GcMarker,
    /// A leftover of the removed transaction engine (`.tx-log/`,
    /// `.tx-bodies/`, `.tx-locks/`). Garbage a previous binary left behind;
    /// scrub reclaims it once it is older than the grace period.
    TxLeftover,
    /// Already quarantined; never re-processed.
    LostAndFound,
    /// A leaked startup CAS-probe object at the store root.
    Probe,
    /// Matches no known angos layout.
    Unknown,
}

/// A link-shaped key, parsed by path grammar only (body parsing is a
/// validation concern).
#[derive(Debug, PartialEq, Eq)]
pub enum ParsedLink {
    /// `_manifests/tags/{name}/current/link`. The name is raw: an invalid tag
    /// directory is a categorized defect (deleted by validation), not an
    /// unknown key.
    Tag { name: String },
    /// `_manifests/revisions/{alg}/{hash}/link`.
    Revision(Digest),
    /// `_blobs/{alg}/{hash}/link`.
    Blob(Digest),
    /// `_layers/{alg}/{hash}/link`.
    Layer(Digest),
    /// `_config/{alg}/{hash}/link`.
    Config(Digest),
    /// `_manifests/referrers/{subject}/{referrer}/link`.
    Referrer { subject: Digest, referrer: Digest },
    /// `_manifests/index/{index}/{child}/link`.
    ManifestIndex { index: Digest, child: Digest },
}

/// The per-file artifacts of one upload session.
#[derive(Debug, PartialEq, Eq)]
pub enum UploadArtifact {
    /// `data`: the assembled upload bytes.
    Data,
    /// `session.json`: the session's single durable record.
    SessionJson,
    /// `startedat`: legacy RFC3339 last-activity marker.
    StartedAt,
    /// `hashstates/{offset}`: a legacy resumable-hash checkpoint.
    HashState,
    /// `staged/{offset}`: an S3 multipart sub-part remainder.
    Staged,
}

/// Leftover prefixes of the removed transaction engine; nothing writes them,
/// and scrub reclaims them age-gated.
pub const TX_LEFTOVER_PREFIXES: [&str; 3] = [".tx-log", ".tx-bodies", ".tx-locks"];

/// Prefix of the startup CAS-probe objects previous angos versions wrote at
/// the store root.
const PROBE_KEY_PREFIX: &str = "_angos_probe_";

/// Namespace markers: the reserved first path segment after the namespace in
/// a repository key. Valid namespace components never start with `_`, so the
/// first marker segment unambiguously ends the namespace.
const NAMESPACE_MARKERS: [&str; 5] = ["_uploads", "_manifests", "_blobs", "_layers", "_config"];

/// Categorize a raw store key against the union of both stores' layouts.
pub fn categorize(key: &str) -> KeyCategory {
    // A degenerate segment can never come from an angos writer and could
    // escape a directory boundary if echoed into a path; refuse the shape.
    if key.is_empty()
        || key
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return KeyCategory::Unknown;
    }

    if TX_LEFTOVER_PREFIXES
        .iter()
        .any(|prefix| strip_prefix_dir(key, prefix).is_some())
    {
        return KeyCategory::TxLeftover;
    }
    if strip_prefix_dir(key, LOST_AND_FOUND_PREFIX).is_some() {
        return KeyCategory::LostAndFound;
    }
    if !key.contains('/') && key.starts_with(PROBE_KEY_PREFIX) {
        return KeyCategory::Probe;
    }
    if let Some(rest) = strip_prefix_dir(key, GC_ROOT) {
        return if rest.contains('/') {
            KeyCategory::Unknown
        } else {
            KeyCategory::GcMarker
        };
    }
    if let Some(rest) = strip_prefix_dir(key, JOBS_ROOT) {
        return categorize_job(rest);
    }
    if let Some(rest) = strip_prefix_dir(key, BLOBS_ROOT) {
        return categorize_blob(rest);
    }
    if let Some(rest) = strip_prefix_dir(key, REF_ROOT) {
        return categorize_ref(rest);
    }
    if let Some(rest) = strip_prefix_dir(key, NS_ROOT) {
        return categorize_ns(rest);
    }
    if let Some(rest) = strip_prefix_dir(key, CAT_ROOT) {
        return match rest.strip_suffix('!') {
            Some(name) if Namespace::new(name).is_ok() => KeyCategory::CatalogIndex {
                namespace: name.to_string(),
            },
            _ => KeyCategory::Unknown,
        };
    }
    if let Some(rest) = strip_prefix_dir(key, REPOS_ROOT) {
        return categorize_repository(rest);
    }

    KeyCategory::Unknown
}

/// The remainder of `key` below the directory `prefix`. `None` when `key` is
/// not under it; a bare string prefix never matches (`v2/blobsx` is not under
/// `v2/blobs`).
fn strip_prefix_dir<'a>(key: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = key.strip_prefix(prefix)?;
    rest.strip_prefix('/')
}

/// `{alg}/{prefix}/{hash}/data` or `{alg}/{prefix}/{hash}/refs/{ns}.json`.
fn categorize_blob(rest: &str) -> KeyCategory {
    let segments: Vec<&str> = rest.split('/').collect();
    let [algorithm, prefix, hash, tail @ ..] = segments.as_slice() else {
        return KeyCategory::Unknown;
    };
    let Some(digest) = parse_digest(algorithm, hash) else {
        return KeyCategory::Unknown;
    };
    if hash.as_bytes().get(..2) != Some(prefix.as_bytes()) {
        return KeyCategory::Unknown;
    }

    match *tail {
        ["data"] => KeyCategory::BlobData { digest },
        ["refs", shard] => match shard.strip_suffix(".json") {
            Some(encoded) => KeyCategory::BlobIndexShard {
                digest,
                namespace: decode_blob_index_shard_namespace(encoded),
            },
            None => KeyCategory::Unknown,
        },
        _ => KeyCategory::Unknown,
    }
}

/// `{alg}/{prefix}/{hash}/{ns}!own` or `{alg}/{prefix}/{hash}/{ns}!r/{entry}`.
fn categorize_ref(rest: &str) -> KeyCategory {
    let mut segments = rest.splitn(4, '/');
    let (Some(algorithm), Some(prefix), Some(hash), Some(tail)) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return KeyCategory::Unknown;
    };
    let Some(digest) = parse_digest(algorithm, hash) else {
        return KeyCategory::Unknown;
    };
    if hash.as_bytes().get(..2) != Some(prefix.as_bytes()) {
        return KeyCategory::Unknown;
    }
    match parse_blob_ref(&digest, tail) {
        Some((namespace, link)) => KeyCategory::BlobRef {
            digest,
            namespace,
            link,
        },
        None => KeyCategory::Unknown,
    }
}

/// `{ns}!tag/{tag}!/{ord}.{kind}.{alg}.{hash}` or `{ns}!atime/tag/{tag}`.
/// Grammars are checked here: a shape no angos writer can produce is unknown
/// and gets quarantined rather than trusted.
fn categorize_ns(rest: &str) -> KeyCategory {
    let Some((namespace, marker)) = rest.split_once('!') else {
        return KeyCategory::Unknown;
    };
    if Namespace::new(namespace).is_err() {
        return KeyCategory::Unknown;
    }
    if let Some(tag_rest) = marker.strip_prefix("tag/") {
        let Some((tag, entry)) = tag_rest.split_once("!/") else {
            return KeyCategory::Unknown;
        };
        if Tag::new(tag).is_ok() && parse_tag_entry(entry).is_some() {
            return KeyCategory::TagEntry {
                namespace: namespace.to_string(),
                tag: tag.to_string(),
            };
        }
        return KeyCategory::Unknown;
    }
    if let Some(hist_rest) = marker.strip_prefix("hist/") {
        let Some((tag, entry)) = hist_rest.split_once("!/") else {
            return KeyCategory::Unknown;
        };
        if Tag::new(tag).is_ok() && parse_tag_entry(entry).is_some() {
            return KeyCategory::TagHistory;
        }
        return KeyCategory::Unknown;
    }
    if let Some(rest) = marker.strip_prefix("atime/") {
        return categorize_atime(namespace, rest);
    }
    if let Some(rest) = marker.strip_prefix("rev/") {
        let segments: Vec<&str> = rest.split('/').collect();
        let [algorithm, prefix, hash] = segments.as_slice() else {
            return KeyCategory::Unknown;
        };
        let Some(digest) = parse_digest(algorithm, hash) else {
            return KeyCategory::Unknown;
        };
        if hash.as_bytes().get(..2) != Some(prefix.as_bytes()) {
            return KeyCategory::Unknown;
        }
        return KeyCategory::RevisionRecord {
            namespace: namespace.to_string(),
            digest,
        };
    }
    if let Some(rest) = marker.strip_prefix("sub/") {
        let segments: Vec<&str> = rest.split('/').collect();
        let [algorithm, prefix, hash, entry] = segments.as_slice() else {
            return KeyCategory::Unknown;
        };
        let Some(subject) = parse_digest(algorithm, hash) else {
            return KeyCategory::Unknown;
        };
        if hash.as_bytes().get(..2) != Some(prefix.as_bytes()) {
            return KeyCategory::Unknown;
        }
        let Some((r_algorithm, r_hash)) = entry.split_once('.') else {
            return KeyCategory::Unknown;
        };
        let Some(referrer) = parse_digest(r_algorithm, r_hash) else {
            return KeyCategory::Unknown;
        };
        return KeyCategory::ReferrerRecord {
            namespace: namespace.to_string(),
            subject,
            referrer,
        };
    }
    KeyCategory::Unknown
}

/// `tag/{tag}!/{ord}.{suffix}` or `rev/{alg}/{hash}!/{ord}.{suffix}` (one
/// append-only access entry), or the legacy single keys `tag/{tag}` and
/// `rev/{alg}/{hash}`.
fn categorize_atime(namespace: &str, rest: &str) -> KeyCategory {
    if let Some(tag_rest) = rest.strip_prefix("tag/") {
        if let Some((tag, entry)) = tag_rest.split_once("!/") {
            if Tag::new(tag).is_ok() && parse_atime_entry(entry).is_some() {
                return KeyCategory::TagAtimeEntry {
                    namespace: namespace.to_string(),
                    tag: tag.to_string(),
                };
            }
            return KeyCategory::Unknown;
        }
        if Tag::new(tag_rest).is_ok() {
            return KeyCategory::TagAccessTime;
        }
        return KeyCategory::Unknown;
    }
    if let Some(rev_rest) = rest.strip_prefix("rev/") {
        if let Some((target, entry)) = rev_rest.split_once("!/") {
            let mut parts = target.splitn(2, '/');
            if let (Some(algorithm), Some(hash)) = (parts.next(), parts.next())
                && let Some(digest) = parse_digest(algorithm, hash)
                && parse_atime_entry(entry).is_some()
            {
                return KeyCategory::RevisionAtimeEntry {
                    namespace: namespace.to_string(),
                    digest,
                };
            }
            return KeyCategory::Unknown;
        }
        let mut parts = rev_rest.splitn(2, '/');
        if let (Some(algorithm), Some(hash)) = (parts.next(), parts.next())
            && parse_digest(algorithm, hash).is_some()
        {
            return KeyCategory::TagAccessTime;
        }
    }
    KeyCategory::Unknown
}

/// `pending/{queue}/{stem}.json`, `failed/{queue}/{stem}.json`,
/// `index/{queue}/{encoded}.json`, or `claims/{encoded}.json`.
fn categorize_job(rest: &str) -> KeyCategory {
    // Claim keys are leases the workers own; the walk recognizes and never
    // touches them (a lapsed one is taken over by the next claimant).
    if let Some(file) = rest.strip_prefix("claims/")
        && !file.contains('/')
    {
        return KeyCategory::JobClaim;
    }
    let segments: Vec<&str> = rest.split('/').collect();
    let [partition, queue, file] = segments.as_slice() else {
        return KeyCategory::Unknown;
    };
    // An unknown queue name may belong to a newer angos; quarantine, never
    // delete.
    let Ok(queue) = Queue::from_str(queue) else {
        return KeyCategory::Unknown;
    };
    if file.strip_suffix(".json").is_none() {
        return KeyCategory::Unknown;
    }

    match *partition {
        "pending" => KeyCategory::JobRecord {
            queue,
            state: JobState::Pending,
        },
        "failed" => KeyCategory::JobRecord {
            queue,
            state: JobState::Failed,
        },
        "index" => KeyCategory::JobIndex { queue },
        _ => KeyCategory::Unknown,
    }
}

/// `{ns...}/{marker}/{...}` where `{ns...}` is one or more namespace segments
/// and `{marker}` is the first reserved `_`-segment.
fn categorize_repository(rest: &str) -> KeyCategory {
    let segments: Vec<&str> = rest.split('/').collect();
    let Some(marker_at) = segments
        .iter()
        .position(|segment| NAMESPACE_MARKERS.contains(segment))
    else {
        return KeyCategory::Unknown;
    };
    if marker_at == 0 {
        // No namespace before the marker; not addressable by any angos API.
        return KeyCategory::Unknown;
    }
    let namespace = segments[..marker_at].join("/");
    let tail = &segments[marker_at + 1..];

    match segments[marker_at] {
        "_uploads" => categorize_upload(namespace, tail),
        "_blobs" => single_digest_link(namespace, tail, ParsedLink::Blob),
        "_layers" => single_digest_link(namespace, tail, ParsedLink::Layer),
        "_config" => single_digest_link(namespace, tail, ParsedLink::Config),
        "_manifests" => categorize_manifest(namespace, tail),
        _ => KeyCategory::Unknown,
    }
}

/// `{uuid}/data`, `{uuid}/session.json`, `{uuid}/startedat`,
/// `{uuid}/hashstates/{offset}`, or `{uuid}/staged/{offset}`.
fn categorize_upload(namespace: String, tail: &[&str]) -> KeyCategory {
    let (session_id, artifact) = match tail {
        [session_id, "data"] => (session_id, UploadArtifact::Data),
        [session_id, "session.json"] => (session_id, UploadArtifact::SessionJson),
        [session_id, "startedat"] => (session_id, UploadArtifact::StartedAt),
        [session_id, "hashstates", offset] if offset.parse::<u64>().is_ok() => {
            (session_id, UploadArtifact::HashState)
        }
        [session_id, "staged", offset] if offset.parse::<u64>().is_ok() => {
            (session_id, UploadArtifact::Staged)
        }
        _ => return KeyCategory::Unknown,
    };
    // A directory angos never opened: leave it to the unknown-key quarantine
    // rather than reporting it as a session the upload passes can address.
    if UploadSessionId::from_str(session_id).is_err() {
        return KeyCategory::Unknown;
    }
    KeyCategory::UploadArtifact {
        namespace,
        artifact,
    }
}

/// `tags/{name}/current/link`, `revisions/{alg}/{hash}/link`,
/// `referrers/{s-alg}/{s-hash}/{r-alg}/{r-hash}/link`, or
/// `index/{i-alg}/{i-hash}/{c-alg}/{c-hash}/link`.
fn categorize_manifest(namespace: String, tail: &[&str]) -> KeyCategory {
    let link = match tail {
        ["tags", name, "current", "link"] => ParsedLink::Tag {
            name: (*name).to_string(),
        },
        ["revisions", algorithm, hash, "link"] => match parse_digest(algorithm, hash) {
            Some(digest) => ParsedLink::Revision(digest),
            None => return KeyCategory::Unknown,
        },
        [
            "referrers",
            s_algorithm,
            s_hash,
            r_algorithm,
            r_hash,
            "link",
        ] => {
            match (
                parse_digest(s_algorithm, s_hash),
                parse_digest(r_algorithm, r_hash),
            ) {
                (Some(subject), Some(referrer)) => ParsedLink::Referrer { subject, referrer },
                _ => return KeyCategory::Unknown,
            }
        }
        ["index", i_algorithm, i_hash, c_algorithm, c_hash, "link"] => {
            match (
                parse_digest(i_algorithm, i_hash),
                parse_digest(c_algorithm, c_hash),
            ) {
                (Some(index), Some(child)) => ParsedLink::ManifestIndex { index, child },
                _ => return KeyCategory::Unknown,
            }
        }
        _ => return KeyCategory::Unknown,
    };
    KeyCategory::Link { namespace, link }
}

/// `{alg}/{hash}/link` for the single-digest link kinds.
fn single_digest_link(
    namespace: String,
    tail: &[&str],
    build: fn(Digest) -> ParsedLink,
) -> KeyCategory {
    let [algorithm, hash, "link"] = tail else {
        return KeyCategory::Unknown;
    };
    match parse_digest(algorithm, hash) {
        Some(digest) => KeyCategory::Link {
            namespace,
            link: build(digest),
        },
        None => KeyCategory::Unknown,
    }
}

/// A digest from separate path segments; `None` (an unknown algorithm or a
/// malformed hash) means the key cannot belong to this angos version.
fn parse_digest(algorithm: &str, hash: &str) -> Option<Digest> {
    let algorithm = Algorithm::from_str(algorithm).ok()?;
    Digest::with_algorithm(algorithm, hash).ok()
}

#[cfg(test)]
mod tests {
    use angos_oci::{Namespace, Tag};

    use crate::command::maintenance::categorize::*;
    use crate::{
        jobs::store::{LockKey, job_failed_path, job_lock_key_index_path, job_pending_path},
        registry::{
            metadata_store::LinkKind,
            path_builder::{
                atime_client_suffix, atime_entry_name, blob_index_shard_path, blob_path,
                blob_ref_own_path, blob_ref_path, link_path, revision_atime_entry_dir,
                tag_atime_entry_dir, tag_atime_path, tag_entry_path, tag_hist_path,
                upload_hash_context_path, upload_path, upload_session_path, upload_start_date_path,
            },
        },
    };

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn digest_a() -> Digest {
        Digest::sha256(HASH_A).unwrap()
    }

    fn digest_b() -> Digest {
        Digest::sha256(HASH_B).unwrap()
    }

    fn namespace() -> Namespace {
        Namespace::new("org/app").unwrap()
    }

    #[test]
    fn blob_data_path_round_trips() {
        assert_eq!(
            categorize(&blob_path(&digest_a())),
            KeyCategory::BlobData { digest: digest_a() }
        );
    }

    #[test]
    fn blob_index_shard_path_round_trips_with_multi_segment_namespace() {
        assert_eq!(
            categorize(&blob_index_shard_path(&digest_a(), &namespace())),
            KeyCategory::BlobIndexShard {
                digest: digest_a(),
                namespace: "org/app".to_string(),
            }
        );
    }

    #[test]
    fn blob_ref_paths_round_trip() {
        let links = [
            LinkKind::Blob(digest_a()),
            LinkKind::Digest(digest_a()),
            LinkKind::Layer(digest_a()),
            LinkKind::Config(digest_a()),
            LinkKind::Tag(Tag::new("v1.0").unwrap()),
            LinkKind::Referrer {
                subject: digest_b(),
                referrer: digest_a(),
            },
            LinkKind::Manifest {
                index: digest_b(),
                child: digest_a(),
            },
        ];
        for link in links {
            assert_eq!(
                categorize(&blob_ref_path(&digest_a(), &namespace(), &link)),
                KeyCategory::BlobRef {
                    digest: digest_a(),
                    namespace: "org/app".to_string(),
                    link: link.clone(),
                },
                "reference key for {link:?} must round-trip"
            );
        }
        assert_eq!(
            categorize(&blob_ref_own_path(&digest_a(), &namespace())),
            KeyCategory::BlobRef {
                digest: digest_a(),
                namespace: "org/app".to_string(),
                link: LinkKind::Blob(digest_a()),
            }
        );
    }

    #[test]
    fn tag_entry_and_atime_paths_round_trip() {
        let ns = Namespace::new("org/app").unwrap();
        let tag = Tag::new("v1.0").unwrap();
        let key = tag_entry_path(&ns, &tag, u64::MAX - 1, false, &digest_a());
        assert_eq!(
            categorize(&key),
            KeyCategory::TagEntry {
                namespace: "org/app".to_string(),
                tag: "v1.0".to_string(),
            }
        );
        assert_eq!(
            categorize(&tag_atime_path(&ns, &tag)),
            KeyCategory::TagAccessTime
        );
    }

    #[test]
    fn atime_entry_paths_round_trip() {
        let ns = Namespace::new("org/app").unwrap();
        let tag = Tag::new("v1.0").unwrap();
        let name = atime_entry_name(u64::MAX - 1, &atime_client_suffix("alice"));
        assert_eq!(
            categorize(&format!("{}/{name}", tag_atime_entry_dir(&ns, &tag))),
            KeyCategory::TagAtimeEntry {
                namespace: "org/app".to_string(),
                tag: "v1.0".to_string(),
            }
        );
        assert_eq!(
            categorize(&format!(
                "{}/{name}",
                revision_atime_entry_dir(&ns, &digest_a())
            )),
            KeyCategory::RevisionAtimeEntry {
                namespace: "org/app".to_string(),
                digest: digest_a(),
            }
        );
        assert_eq!(
            categorize(&format!("v2/ns/org/app!atime/rev/sha256/{HASH_A}")),
            KeyCategory::TagAccessTime
        );
        let unknown = [
            format!("v2/ns/org/app!atime/tag/-bad!/{name}"),
            "v2/ns/org/app!atime/tag/v1.0!/junk".to_string(),
            format!("v2/ns/org/app!atime/rev/sha3/{HASH_A}!/{name}"),
            format!("v2/ns/org/app!atime/rev/sha256/{HASH_A}!/junk.entry"),
        ];
        for key in unknown {
            assert_eq!(categorize(&key), KeyCategory::Unknown, "key {key:?}");
        }
    }

    #[test]
    fn tag_hist_paths_round_trip() {
        let ns = Namespace::new("org/app").unwrap();
        let tag = Tag::new("v1.0").unwrap();
        let entry_key = tag_entry_path(&ns, &tag, u64::MAX - 1, false, &digest_a());
        let file = entry_key.rsplit_once('/').unwrap().1;
        assert_eq!(
            categorize(&tag_hist_path(&ns, &tag, file)),
            KeyCategory::TagHistory
        );
        assert_eq!(categorize("v2/ns/org/app!hist/v1.0"), KeyCategory::Unknown);
    }

    #[test]
    fn adversarial_tag_keys_are_unknown() {
        let unknown = [
            "v2/ns/org/app".to_string(),
            "v2/ns/org/app!tag/v1.0".to_string(),
            format!("v2/ns/org/app!tag/-bad!/{:016x}.set.sha256.{HASH_A}", 1),
            format!("v2/ns/org/app!tag/v1!/{:016x}.mov.sha256.{HASH_A}", 1),
            format!("v2/ns/BAD!tag/v1!/{:016x}.set.sha256.{HASH_A}", 1),
            "v2/ns/org/app!atime/tag/-bad".to_string(),
            "v2/ns/org/app!other/x".to_string(),
        ];
        for key in unknown {
            assert_eq!(categorize(&key), KeyCategory::Unknown, "key {key:?}");
        }
    }

    #[test]
    fn adversarial_blob_ref_keys_are_unknown() {
        let unknown = [
            format!("v2/ref/sha256/aa/{HASH_A}/ns!r/unknown"),
            format!("v2/ref/sha256/bb/{HASH_A}/ns!own"),
            format!("v2/ref/sha256/aa/{HASH_A}/ns"),
            format!("v2/ref/sha3/aa/{HASH_A}/ns!own"),
            "v2/ref/sha256/aa".to_string(),
        ];
        for key in unknown {
            assert_eq!(categorize(&key), KeyCategory::Unknown, "key {key:?}");
        }
    }

    #[test]
    fn every_link_kind_round_trips() {
        let cases: Vec<(LinkKind, ParsedLink)> = vec![
            (
                LinkKind::Tag(Tag::new("v1.0").unwrap()),
                ParsedLink::Tag {
                    name: "v1.0".to_string(),
                },
            ),
            (
                LinkKind::Digest(digest_a()),
                ParsedLink::Revision(digest_a()),
            ),
            (LinkKind::Blob(digest_a()), ParsedLink::Blob(digest_a())),
            (LinkKind::Layer(digest_a()), ParsedLink::Layer(digest_a())),
            (LinkKind::Config(digest_a()), ParsedLink::Config(digest_a())),
            (
                LinkKind::Referrer {
                    subject: digest_a(),
                    referrer: digest_b(),
                },
                ParsedLink::Referrer {
                    subject: digest_a(),
                    referrer: digest_b(),
                },
            ),
            (
                LinkKind::Manifest {
                    index: digest_a(),
                    child: digest_b(),
                },
                ParsedLink::ManifestIndex {
                    index: digest_a(),
                    child: digest_b(),
                },
            ),
        ];
        for (kind, expected) in cases {
            assert_eq!(
                categorize(&link_path(&kind, &namespace())),
                KeyCategory::Link {
                    namespace: "org/app".to_string(),
                    link: expected,
                },
                "link kind {kind:?} must round-trip"
            );
        }
    }

    const SESSION: &str = "067e6162-3b6f-4ae2-a171-2470b63dff00";

    fn session() -> UploadSessionId {
        UploadSessionId::from_str(SESSION).unwrap()
    }

    #[test]
    fn upload_artifacts_round_trip() {
        let ns = namespace();
        let cases = [
            (upload_path(&ns, &session()), UploadArtifact::Data),
            (
                upload_session_path(&ns, &session()),
                UploadArtifact::SessionJson,
            ),
            (
                upload_start_date_path(&ns, &session()),
                UploadArtifact::StartedAt,
            ),
            (
                upload_hash_context_path(&ns, &session(), 42),
                UploadArtifact::HashState,
            ),
            (
                format!("v2/repositories/org/app/_uploads/{SESSION}/staged/7"),
                UploadArtifact::Staged,
            ),
        ];
        for (key, expected) in cases {
            assert_eq!(
                categorize(&key),
                KeyCategory::UploadArtifact {
                    namespace: "org/app".to_string(),
                    artifact: expected,
                },
                "upload artifact {key} must round-trip"
            );
        }
    }

    /// A directory angos never opened is not an upload session: it must reach
    /// the unknown-key quarantine instead of being reported as one.
    #[test]
    fn an_upload_directory_that_is_not_a_session_is_unknown() {
        let ns = namespace();
        for name in ["uuid-1", "", "..", "not-a-uuid", "067e6162"] {
            let key = format!("v2/repositories/org/app/_uploads/{name}/data");
            assert_eq!(
                categorize(&key),
                KeyCategory::Unknown,
                "'{name}' must not categorize as an upload session"
            );
        }
        assert_eq!(
            categorize(&upload_path(&ns, &session())),
            KeyCategory::UploadArtifact {
                namespace: "org/app".to_string(),
                artifact: UploadArtifact::Data,
            }
        );
    }

    #[test]
    fn job_paths_round_trip() {
        assert_eq!(
            categorize(&job_pending_path("replication", "0000-id")),
            KeyCategory::JobRecord {
                queue: Queue::Replication,
                state: JobState::Pending,
            }
        );
        assert_eq!(
            categorize(&job_failed_path("cache", "0000-id")),
            KeyCategory::JobRecord {
                queue: Queue::Cache,
                state: JobState::Failed,
            }
        );
        assert_eq!(
            categorize(&job_lock_key_index_path(
                "cache",
                &LockKey::new("a/b:c").expect("lock key")
            )),
            KeyCategory::JobIndex {
                queue: Queue::Cache,
            }
        );
    }

    #[test]
    fn engine_and_reserved_prefixes_are_recognized() {
        assert_eq!(
            categorize(".tx-log/0000-uuid.json"),
            KeyCategory::TxLeftover
        );
        assert_eq!(categorize(".tx-bodies/uuid/0"), KeyCategory::TxLeftover);
        assert_eq!(categorize(".tx-locks/aa/some-key"), KeyCategory::TxLeftover);
        assert_eq!(
            categorize("_lost_and_found/foo/bar"),
            KeyCategory::LostAndFound
        );
        assert_eq!(categorize("_angos_probe_1234"), KeyCategory::Probe);
    }

    #[test]
    fn adversarial_keys_are_unknown() {
        let unknown = [
            // Root garbage and near-miss string prefixes.
            "garbage",
            "v2/blobsx/sha256/aa/file",
            "v2/blobs",
            "v2/repositories",
            // Blob shard-prefix / hash mismatches and truncations.
            &format!("v2/blobs/sha256/bb/{HASH_A}/data"),
            "v2/blobs/sha256/aa/aaaa/data",
            &format!("v2/blobs/sha3/aa/{HASH_A}/data"),
            &format!("v2/blobs/sha256/aa/{HASH_A}/other"),
            &format!("v2/blobs/sha256/aa/{HASH_A}/refs/ns"),
            // Repository keys with no namespace, no marker, or a stray tail.
            "v2/repositories/_manifests/tags/x/current/link",
            "v2/repositories/ns/unmarked/file",
            &format!("v2/repositories/ns/_manifests/revisions/sha256/{HASH_A}/extra"),
            "v2/repositories/ns/_manifests/tags/a/b/current/link",
            "v2/repositories/ns/_uploads/uuid/hashstates/not-a-number",
            "v2/repositories/ns/_uploads/uuid/junkfile",
            // Jobs with an unknown queue or partition, or a non-JSON file.
            "_jobs/pending/futurequeue/0000-id.json",
            "_jobs/leases/replication/0000-id.json",
            "_jobs/pending/replication/0000-id",
            // Probe-like keys below the root.
            "sub/_angos_probe_1234",
            // Degenerate segments.
            "v2//blobs/x",
            "v2/repositories/../escape",
            "",
        ];
        for key in unknown {
            assert_eq!(categorize(key), KeyCategory::Unknown, "key {key:?}");
        }
    }

    #[test]
    fn invalid_tag_name_is_still_a_categorized_tag_link() {
        // A tag directory whose name fails the tag grammar is a known defect
        // handled by validation (deleted), not an unknown key.
        assert_eq!(
            categorize("v2/repositories/ns/_manifests/tags/-bad/current/link"),
            KeyCategory::Link {
                namespace: "ns".to_string(),
                link: ParsedLink::Tag {
                    name: "-bad".to_string(),
                },
            }
        );
    }
    #[test]
    fn gc_markers_are_recognized_and_nested_gc_keys_are_not() {
        assert!(matches!(
            categorize("v2/gc/0f7a2f2e-run"),
            KeyCategory::GcMarker
        ));
        assert!(matches!(
            categorize("v2/gc/nested/key"),
            KeyCategory::Unknown
        ));
    }
}
