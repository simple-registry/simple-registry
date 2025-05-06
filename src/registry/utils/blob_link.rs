use crate::registry::oci_types::{Digest, Reference};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum BlobLink {
    Tag(String),
    Digest(Digest),
    Layer(Digest),
    Config(Digest),
    Referrer(Digest, Digest),
}

impl Display for BlobLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobLink::Tag(s) => write!(f, "tag:{s}"),
            BlobLink::Digest(d) => write!(f, "digest:{d}"),
            BlobLink::Layer(d) => write!(f, "layer:{d}"),
            BlobLink::Config(d) => write!(f, "config:{d}"),
            BlobLink::Referrer(l, r) => write!(f, "referrer:{l}-{r}"),
        }
    }
}

impl From<Reference> for BlobLink {
    fn from(r: Reference) -> Self {
        match r {
            Reference::Tag(s) => BlobLink::Tag(s),
            Reference::Digest(d) => BlobLink::Digest(d),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::oci_types::Reference;

    #[test]
    fn test_from_reference() {
        let tag = Reference::Tag("tag".to_string());
        let tag_link = BlobLink::Tag("tag".to_string());
        assert_eq!(BlobLink::from(tag), tag_link);

        let digest = Reference::Digest(Digest::Sha256("digest".to_string()));
        let digest_link = BlobLink::Digest(Digest::Sha256("digest".to_string()));
        assert_eq!(BlobLink::from(digest), digest_link);
    }
}
