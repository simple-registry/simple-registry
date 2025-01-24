use crate::oci::{Digest, Reference};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum DataLink {
    Tag(String),
    Digest(Digest),
    Layer(Digest),
    Config(Digest),
    Referrer(Digest, Digest),
}

impl From<Reference> for DataLink {
    fn from(r: Reference) -> Self {
        match r {
            Reference::Tag(s) => DataLink::Tag(s),
            Reference::Digest(d) => DataLink::Digest(d),
        }
    }
}
