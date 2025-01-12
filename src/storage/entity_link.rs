use crate::oci::{Digest, Reference};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum EntityLink {
    Tag(String),
    Digest(Digest),
    Layer(Digest),
    Config(Digest),
    Referrer(Digest, Digest),
}

impl From<Reference> for EntityLink {
    fn from(r: Reference) -> Self {
        match r {
            Reference::Tag(s) => EntityLink::Tag(s),
            Reference::Digest(d) => EntityLink::Digest(d),
        }
    }
}
