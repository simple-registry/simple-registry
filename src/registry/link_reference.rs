use crate::oci::{Digest, Reference};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum LinkReference {
    Tag(String),
    Digest(Digest),
    Layer(Digest),
    Config(Digest),
    Referrer(Digest, Digest),
}

impl From<Reference> for LinkReference {
    fn from(r: Reference) -> Self {
        match r {
            Reference::Tag(s) => LinkReference::Tag(s),
            Reference::Digest(d) => LinkReference::Digest(d),
        }
    }
}
