use crate::registry::oci_types::Digest;
use crate::registry::oci_types::Error;
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
    pub fn from_str(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            return Err(Error::InvalidFormat(
                "Reference cannot be empty".to_string(),
            ));
        }

        if s.contains(':') {
            Ok(Reference::Digest(Digest::try_from(s)?))
        } else if TAG_REGEX.is_match(s) {
            Ok(Reference::Tag(s.to_string()))
        } else {
            Err(Error::InvalidFormat(format!("Invalid reference: '{s}'",)))
        }
    }
}

impl Display for Reference {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Reference::Tag(s) => write!(f, "{s}"),
            Reference::Digest(d) => write!(f, "{d}"),
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_reference_from_str() {
        let tag_str = "latest";
        let digest_str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let Some(Reference::Tag(tag)) = Reference::from_str(tag_str).ok() else {
            panic!("Failed to parse tag");
        };
        assert_eq!(tag, tag_str);

        let Some(Reference::Digest(digest)) = Reference::from_str(digest_str).ok() else {
            panic!("Failed to parse digest");
        };
        assert_eq!(digest.algorithm(), "sha256");
        assert_eq!(
            digest.hash(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_reference_display() {
        let tag = "latest";
        let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        assert_eq!(Reference::Tag(tag.to_string()).to_string(), tag);
        assert_eq!(
            Reference::Digest(digest.try_into().unwrap()).to_string(),
            digest
        );
    }

    #[test]
    fn test_reference_deserialize() {
        let tag_str = r#""latest""#;
        let digest_str =
            r#""sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef""#;

        let Some(Reference::Tag(tag)) = serde_json::from_str(tag_str).ok() else {
            panic!("Failed to parse tag");
        };
        assert_eq!(tag, "latest");

        let Some(Reference::Digest(digest)) = serde_json::from_str(digest_str).ok() else {
            panic!("Failed to parse digest");
        };
        assert_eq!(digest.algorithm(), "sha256");
        assert_eq!(
            digest.hash(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }
}
