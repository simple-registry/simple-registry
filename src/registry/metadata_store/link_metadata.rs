use crate::registry::metadata_store::Error;
use crate::registry::oci::Digest;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkMetadata {
    pub target: Digest,
    pub created_at: Option<DateTime<Utc>>,
    pub accessed_at: Option<DateTime<Utc>>,
}

impl LinkMetadata {
    pub fn from_digest(target: Digest) -> Self {
        Self {
            target,
            created_at: Some(Utc::now()),
            accessed_at: None,
        }
    }

    pub fn from_bytes(s: Vec<u8>) -> Result<Self, Error> {
        // Try to deserialize the data as LinkMetadata, if it fails, it means
        // the link is a simple string (probably coming from "distribution" implementation).
        if let Ok(metadata) = serde_json::from_slice(&s) {
            Ok(metadata)
        } else {
            // If the link is not a valid LinkMetadata, we create a new one
            let target = String::from_utf8(s).map_err(|e| Error::InvalidData(e.to_string()))?;
            let target =
                Digest::try_from(target.as_str()).map_err(|e| Error::InvalidData(e.to_string()))?;

            Ok(LinkMetadata {
                target,
                created_at: Some(Utc::now()),
                accessed_at: None,
            })
        }
    }

    pub fn accessed(mut self) -> Self {
        self.accessed_at = Some(Utc::now());
        self
    }
}
