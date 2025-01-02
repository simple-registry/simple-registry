use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter};

use crate::error::RegistryError;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum Digest {
    Sha256(String),
}

impl Digest {
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

impl TryFrom<&str> for Digest {
    type Error = RegistryError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (algorithm, hash) = s.split_once(':').ok_or_else(|| {
            RegistryError::InternalServerError(Some(format!(
                "Digest must be in the format 'algorithm:hash', got '{}'",
                s
            )))
        })?;

        // Only sha256 is supported at the moment
        if algorithm.to_lowercase() != "sha256" {
            return Err(RegistryError::InternalServerError(Some(format!(
                "Unsupported digest algorithm '{}'",
                algorithm
            ))));
        }

        // Check that hash is a valid sha256 hash (64 bytes representation)
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(RegistryError::InternalServerError(Some(format!(
                "Invalid sha256 hash '{}'",
                hash
            ))));
        }

        Ok(Digest::Sha256(hash.to_string()))
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

        impl Visitor<'_> for DigestVisitor {
            type Value = Digest;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a valid digest string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Digest, E>
            where
                E: Error,
            {
                Digest::try_from(value).map_err(Error::custom)
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
