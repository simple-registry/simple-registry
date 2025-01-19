use crate::registry;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

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

impl FromStr for Digest {
    type Err = registry::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl TryFrom<&str> for Digest {
    type Error = registry::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (algorithm, hash) = s.split_once(':').ok_or_else(|| {
            registry::Error::Internal(Some(format!(
                "Digest must be in the format 'algorithm:hash', got '{s}'"
            )))
        })?;

        // Only sha256 is supported at the moment
        if algorithm.to_lowercase() != "sha256" {
            return Err(registry::Error::Internal(Some(format!(
                "Unsupported digest algorithm '{algorithm}'"
            ))));
        }

        // Check that hash is a valid sha256 hash (64 bytes representation)
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(registry::Error::Internal(Some(format!(
                "Invalid sha256 hash '{hash}'"
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn test_digest_try_from() {
        let digest: Digest =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .try_into()
                .unwrap();

        assert_eq!(digest.algorithm(), "sha256");
        assert_eq!(
            digest.hash(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(digest.hash_prefix(), "01");
    }

    #[test]
    fn test_digest_try_from_invalid() {
        let digest: Result<Digest, registry::Error> = "sha256:invalid".try_into();
        assert!(digest.is_err());
    }

    #[test]
    fn test_digest_display() {
        let digest: Digest = Digest::Sha256(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        );
        assert_eq!(
            digest.to_string(),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_digest_deserialize() {
        let digest: Digest = serde_json::from_str(
            r#""sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef""#,
        )
        .unwrap();
        assert_eq!(
            digest,
            Digest::Sha256(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
            )
        );
    }
}
