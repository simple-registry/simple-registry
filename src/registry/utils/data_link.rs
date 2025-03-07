use crate::registry::oci_types::{Digest, Reference};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum DataLink {
    Tag(String),
    Digest(Digest),
    Layer(Digest),
    Config(Digest),
    Referrer(Digest, Digest),
}

impl Display for DataLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataLink::Tag(s) => write!(f, "tag:{s}"),
            DataLink::Digest(d) => write!(f, "digest:{d}"),
            DataLink::Layer(d) => write!(f, "layer:{d}"),
            DataLink::Config(d) => write!(f, "config:{d}"),
            DataLink::Referrer(l, r) => write!(f, "referrer:{l}-{r}"),
        }
    }
}

impl From<Reference> for DataLink {
    fn from(r: Reference) -> Self {
        match r {
            Reference::Tag(s) => DataLink::Tag(s),
            Reference::Digest(d) => DataLink::Digest(d),
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
        let tag_link = DataLink::Tag("tag".to_string());
        assert_eq!(DataLink::from(tag), tag_link);

        let digest = Reference::Digest(Digest::Sha256("digest".to_string()));
        let digest_link = DataLink::Digest(Digest::Sha256("digest".to_string()));
        assert_eq!(DataLink::from(digest), digest_link);
    }
}
