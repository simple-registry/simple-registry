use crate::error::RegistryError;
use crate::oci::digest::Digest;
use lazy_static::lazy_static;
use regex::Regex;
use serde::de::Visitor;
use serde::{de, Deserialize, Deserializer};
use std::fmt;
use std::fmt::{Display, Formatter};

lazy_static! {
    static ref TAG_REGEX: Regex = Regex::new(r"^\w[\w.-]{0,127}$").unwrap();
}

#[derive(Clone, Debug)]
pub enum Reference {
    Tag(String),
    Digest(Digest),
}

impl Reference {
    pub fn from_str(s: &str) -> Result<Self, RegistryError> {
        if s.is_empty() {
            return Err(RegistryError::ManifestBlobUnknown);
        }

        if s.contains(':') {
            Ok(Reference::Digest(Digest::from_str(s)?))
        } else if TAG_REGEX.is_match(s) {
            Ok(Reference::Tag(s.to_string()))
        } else {
            Err(RegistryError::ManifestBlobUnknown)
        }
    }
}

impl Display for Reference {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Reference::Tag(s) => write!(f, "{}", s),
            Reference::Digest(d) => write!(f, "{}", d),
        }
    }
}

impl<'de> Deserialize<'de> for Reference {
    fn deserialize<D>(deserializer: D) -> Result<Reference, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ReferenceVisitor;

        impl Visitor<'_> for ReferenceVisitor {
            type Value = Reference;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a valid reference string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Reference, E>
            where
                E: de::Error,
            {
                Reference::from_str(value).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(ReferenceVisitor)
    }
}
