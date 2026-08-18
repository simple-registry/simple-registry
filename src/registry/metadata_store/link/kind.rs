use std::fmt::Display;

use serde::{Deserialize, Serialize};

use angos_oci::{Digest, Reference, Tag};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(from = "StoredLinkKind", into = "StoredLinkKind")]
pub enum LinkKind {
    Blob(Digest),
    Tag(Tag),
    Digest(Digest),
    Layer(Digest),
    Config(Digest),
    /// A referrer back-link: the manifest `referrer` names `subject` in its
    /// `subject` field.
    Referrer {
        subject: Digest,
        referrer: Digest,
    },
    /// An index child link: the index `index` lists `child` among its manifests.
    Manifest {
        index: Digest,
        child: Digest,
    },
    /// A per-referrer reference entry: the manifest with this digest
    /// references the blob the entry lives under. Backed while that
    /// manifest's revision still resolves in the namespace.
    ReferencedBy(Digest),
}

/// The shape [`LinkKind`] has always had inside a blob-index shard, where the
/// two-digest kinds are positional arrays. Named fields on the live type would
/// otherwise re-encode those as objects and strand every stored shard.
#[derive(Serialize, Deserialize)]
enum StoredLinkKind {
    Blob(Digest),
    Tag(Tag),
    Digest(Digest),
    Layer(Digest),
    Config(Digest),
    Referrer(Digest, Digest),
    Manifest(Digest, Digest),
    /// Never present in a legacy shard (the kind postdates them); carried so
    /// the conversions stay total.
    ReferencedBy(Digest),
}

impl From<StoredLinkKind> for LinkKind {
    fn from(stored: StoredLinkKind) -> Self {
        match stored {
            StoredLinkKind::Blob(digest) => LinkKind::Blob(digest),
            StoredLinkKind::Tag(tag) => LinkKind::Tag(tag),
            StoredLinkKind::Digest(digest) => LinkKind::Digest(digest),
            StoredLinkKind::Layer(digest) => LinkKind::Layer(digest),
            StoredLinkKind::Config(digest) => LinkKind::Config(digest),
            StoredLinkKind::Referrer(subject, referrer) => LinkKind::Referrer { subject, referrer },
            StoredLinkKind::Manifest(index, child) => LinkKind::Manifest { index, child },
            StoredLinkKind::ReferencedBy(referrer) => LinkKind::ReferencedBy(referrer),
        }
    }
}

impl From<LinkKind> for StoredLinkKind {
    fn from(link: LinkKind) -> Self {
        match link {
            LinkKind::Blob(digest) => StoredLinkKind::Blob(digest),
            LinkKind::Tag(tag) => StoredLinkKind::Tag(tag),
            LinkKind::Digest(digest) => StoredLinkKind::Digest(digest),
            LinkKind::Layer(digest) => StoredLinkKind::Layer(digest),
            LinkKind::Config(digest) => StoredLinkKind::Config(digest),
            LinkKind::Referrer { subject, referrer } => StoredLinkKind::Referrer(subject, referrer),
            LinkKind::Manifest { index, child } => StoredLinkKind::Manifest(index, child),
            LinkKind::ReferencedBy(referrer) => StoredLinkKind::ReferencedBy(referrer),
        }
    }
}

impl LinkKind {
    pub fn is_tracked(&self) -> bool {
        matches!(
            self,
            LinkKind::Layer(_)
                | LinkKind::Config(_)
                | LinkKind::Manifest { .. }
                | LinkKind::ReferencedBy(_)
        )
    }

    pub fn from_reference(reference: &Reference) -> Self {
        match reference {
            Reference::Tag(s) => LinkKind::Tag(s.clone()),
            Reference::Digest(d) => LinkKind::Digest(d.clone()),
        }
    }
}

impl Display for LinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkKind::Blob(d) => write!(f, "blob:{d}"),
            LinkKind::Tag(s) => write!(f, "tag:{s}"),
            LinkKind::Digest(d) => write!(f, "digest:{d}"),
            LinkKind::Layer(d) => write!(f, "layer:{d}"),
            LinkKind::Config(d) => write!(f, "config:{d}"),
            LinkKind::Referrer { subject, referrer } => {
                write!(f, "referrer:{subject}-{referrer}")
            }
            LinkKind::Manifest { index, child } => write!(f, "manifest:{index}-{child}"),
            LinkKind::ReferencedBy(referrer) => write!(f, "referenced-by:{referrer}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use angos_oci::{Reference, Tag};

    use crate::registry::metadata_store::link::kind::*;

    // Valid 64-char lowercase-hex sha256 hashes (the only shape `Digest` accepts).
    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn sha(hash: &str) -> Digest {
        Digest::sha256(hash).unwrap()
    }

    /// The blob-index shards hold this enum, so its JSON is a stored format:
    /// the two-digest kinds are positional arrays and must stay that way now
    /// that the live type names its digests. Both directions, so a shard
    /// written by any earlier angos still reads and still round-trips.
    #[test]
    fn the_stored_form_is_unchanged_by_the_named_fields() {
        let cases = [
            (
                LinkKind::Blob(sha(HASH_A)),
                format!(r#"{{"Blob":"sha256:{HASH_A}"}}"#),
            ),
            (
                LinkKind::Tag(Tag::new("v1").unwrap()),
                r#"{"Tag":"v1"}"#.to_string(),
            ),
            (
                LinkKind::Digest(sha(HASH_A)),
                format!(r#"{{"Digest":"sha256:{HASH_A}"}}"#),
            ),
            (
                LinkKind::Layer(sha(HASH_A)),
                format!(r#"{{"Layer":"sha256:{HASH_A}"}}"#),
            ),
            (
                LinkKind::Config(sha(HASH_A)),
                format!(r#"{{"Config":"sha256:{HASH_A}"}}"#),
            ),
            (
                LinkKind::Referrer {
                    subject: sha(HASH_A),
                    referrer: sha(HASH_B),
                },
                format!(r#"{{"Referrer":["sha256:{HASH_A}","sha256:{HASH_B}"]}}"#),
            ),
            (
                LinkKind::Manifest {
                    index: sha(HASH_A),
                    child: sha(HASH_B),
                },
                format!(r#"{{"Manifest":["sha256:{HASH_A}","sha256:{HASH_B}"]}}"#),
            ),
            (
                LinkKind::ReferencedBy(sha(HASH_A)),
                format!(r#"{{"ReferencedBy":"sha256:{HASH_A}"}}"#),
            ),
        ];

        for (link, stored) in cases {
            assert_eq!(
                serde_json::to_string(&link).unwrap(),
                stored,
                "{link} must serialize to the shape the shards already carry"
            );
            assert_eq!(
                serde_json::from_str::<LinkKind>(&stored).unwrap(),
                link,
                "a stored {link} must read back unchanged"
            );
        }
    }

    /// The order inside a stored pair is load-bearing: the first digest is the
    /// subject, the second the referrer.
    #[test]
    fn a_stored_pair_keeps_its_positions() {
        let stored = format!(r#"{{"Referrer":["sha256:{HASH_A}","sha256:{HASH_B}"]}}"#);
        let LinkKind::Referrer { subject, referrer } =
            serde_json::from_str::<LinkKind>(&stored).unwrap()
        else {
            panic!("a referrer entry must read back as a referrer");
        };
        assert_eq!(subject, sha(HASH_A), "the first digest is the subject");
        assert_eq!(referrer, sha(HASH_B), "the second is the referrer");
    }

    #[test]
    fn test_from_reference() {
        let tag = Reference::Tag(Tag::new("tag").unwrap());
        let tag_link = LinkKind::Tag(Tag::new("tag").unwrap());
        assert_eq!(LinkKind::from_reference(&tag), tag_link);

        let digest = Reference::Digest(sha(HASH_A));
        let digest_link = LinkKind::Digest(sha(HASH_A));
        assert_eq!(LinkKind::from_reference(&digest), digest_link);
    }

    #[test]
    fn is_tracked_returns_true_for_layer() {
        assert!(LinkKind::Layer(sha(HASH_A)).is_tracked());
    }

    #[test]
    fn is_tracked_returns_true_for_config() {
        assert!(LinkKind::Config(sha(HASH_A)).is_tracked());
    }

    #[test]
    fn is_tracked_returns_true_for_manifest() {
        assert!(
            LinkKind::Manifest {
                index: sha(HASH_A),
                child: sha(HASH_B)
            }
            .is_tracked()
        );
    }

    #[test]
    fn is_tracked_returns_true_for_referenced_by() {
        assert!(LinkKind::ReferencedBy(sha(HASH_A)).is_tracked());
    }

    #[test]
    fn is_tracked_returns_false_for_blob() {
        assert!(!LinkKind::Blob(sha(HASH_A)).is_tracked());
    }

    #[test]
    fn is_tracked_returns_false_for_tag() {
        assert!(!LinkKind::Tag(Tag::new("latest").unwrap()).is_tracked());
    }

    #[test]
    fn is_tracked_returns_false_for_digest() {
        assert!(!LinkKind::Digest(sha(HASH_A)).is_tracked());
    }

    #[test]
    fn is_tracked_returns_false_for_referrer() {
        assert!(
            !LinkKind::Referrer {
                subject: sha(HASH_A),
                referrer: sha(HASH_B)
            }
            .is_tracked()
        );
    }

    #[test]
    fn display_renders_expected_string_for_each_variant() {
        let cases = [
            (
                LinkKind::Tag(Tag::new("v1.0.0").unwrap()),
                "tag:v1.0.0".to_string(),
            ),
            (LinkKind::Blob(sha(HASH_A)), format!("blob:sha256:{HASH_A}")),
            (
                LinkKind::Digest(sha(HASH_A)),
                format!("digest:sha256:{HASH_A}"),
            ),
            (
                LinkKind::Layer(sha(HASH_A)),
                format!("layer:sha256:{HASH_A}"),
            ),
            (
                LinkKind::Config(sha(HASH_A)),
                format!("config:sha256:{HASH_A}"),
            ),
            (
                LinkKind::Referrer {
                    subject: sha(HASH_A),
                    referrer: sha(HASH_B),
                },
                format!("referrer:sha256:{HASH_A}-sha256:{HASH_B}"),
            ),
            (
                LinkKind::Manifest {
                    index: sha(HASH_A),
                    child: sha(HASH_B),
                },
                format!("manifest:sha256:{HASH_A}-sha256:{HASH_B}"),
            ),
            (
                LinkKind::ReferencedBy(sha(HASH_A)),
                format!("referenced-by:sha256:{HASH_A}"),
            ),
        ];

        for (link, expected) in cases {
            assert_eq!(link.to_string(), expected);
        }
    }
}
