use lazy_static::lazy_static;
use regex::Regex;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter};

use crate::error::RegistryError;
use crate::io_helpers::parse_regex;

lazy_static! {
    static ref DIGEST_REGEX: Regex =
        Regex::new(r"^(?P<algorithm>[a-z0-9]+):(?P<hash>[a-f0-9]{64})$").unwrap();
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum Digest {
    Sha256(String),
}

impl Digest {
    pub fn from_str(s: &str) -> Result<Self, RegistryError> {
        #[derive(Deserialize)]
        struct ParsedDigest {
            algorithm: String,
            hash: String,
        }

        let parsed_digest =
            parse_regex::<ParsedDigest>(s, &DIGEST_REGEX).ok_or(RegistryError::DigestInvalid)?;

        match parsed_digest.algorithm.as_str() {
            "sha256" => Ok(Digest::Sha256(parsed_digest.hash)),
            _ => Err(RegistryError::Unsupported),
        }
    }

    pub fn algorithm(&self) -> &str {
        match self {
            Digest::Sha256(_) => "sha256",
        }
    }

    pub fn hash(&self) -> &str {
        match self {
            Digest::Sha256(s) => s,
        }
    }

    pub fn hash_prefix(&self) -> &str {
        match self {
            Digest::Sha256(s) => &s[0..2],
        }
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm(), self.hash())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Digest, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DigestVisitor;

        impl<'de> Visitor<'de> for DigestVisitor {
            type Value = Digest;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a valid digest string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Digest, E>
            where
                E: Error,
            {
                Digest::from_str(value).map_err(Error::custom)
            }
        }

        deserializer.deserialize_str(DigestVisitor)
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
