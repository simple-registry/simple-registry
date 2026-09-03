use std::fmt::Display;

use angos_oci::{Digest, Reference, Tag};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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
    /// references the blob the entry lives under, and is backed while that
    /// manifest's revision still resolves in the namespace.
    ReferencedBy(Digest),
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

    /// The reference-key tail after `<ns>!`. Digest-bearing kinds omit the
    /// blob's own digest and spell out only the foreign one: a referrer entry
    /// names its subject, an index child entry names its index.
    pub fn ref_entry(&self) -> String {
        match self {
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

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn sha(hash: &str) -> Digest {
        Digest::sha256(hash).unwrap()
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
