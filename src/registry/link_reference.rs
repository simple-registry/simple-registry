use crate::oci::{Digest, Reference};

#[derive(Clone, Debug)]
pub enum LinkReference {
    Tag(String),
    Digest(Digest),
    Layer(Digest),
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
