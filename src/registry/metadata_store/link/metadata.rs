use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};

use angos_oci::{Descriptor, Digest, MediaType};

/// Reads a recorded media type, dropping the parameter section an angos before
/// 1.5.0 copied verbatim out of the pushed `Content-Type`. Refusing such a
/// value would have scrub delete the link as corrupt.
fn stored_media_type<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<MediaType>, D::Error> {
    let Some(recorded) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };

    MediaType::from_content_type(&recorded)
        .map(Some)
        .map_err(DeError::custom)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkMetadata {
    pub target: Digest,
    pub created_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        deserialize_with = "stored_media_type",
        skip_serializing_if = "Option::is_none"
    )]
    pub media_type: Option<MediaType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<Descriptor>,
}

impl LinkMetadata {
    /// Test convenience for `from_digest_at(target, now())`.
    #[cfg(test)]
    pub fn from_digest(target: Digest) -> Self {
        Self::from_digest_at(target, Utc::now())
    }

    /// Construct with an explicit creation time. Replicated writes pass the
    /// originating `source_ts` so the tag's last-writer-wins timestamp tracks
    /// the author's clock, not each receiver's.
    pub fn from_digest_at(target: Digest, created_at: DateTime<Utc>) -> Self {
        Self {
            target,
            created_at: Some(created_at),
            media_type: None,
            descriptor: None,
        }
    }

    /// `Some(created_at)` iff this link supersedes an incoming write authored
    /// at `source_ts`: newer `created_at`, or equal with a target digest
    /// ordering above `incoming_digest`. That tie-break stops equal-timestamp
    /// peers swapping digests forever, and a delete carries no digest so it
    /// keeps plain strictly-greater.
    pub fn supersedes(
        &self,
        source_ts: DateTime<Utc>,
        incoming_digest: Option<&Digest>,
    ) -> Option<DateTime<Utc>> {
        let created_at = self.created_at?;
        if created_at > source_ts {
            return Some(created_at);
        }
        if created_at == source_ts
            && let Some(incoming) = incoming_digest
            && self.target > *incoming
        {
            return Some(created_at);
        }
        None
    }

    pub fn with_media_type(mut self, media_type: Option<MediaType>) -> Self {
        self.media_type = media_type;
        self
    }

    pub fn with_descriptor(mut self, descriptor: Option<Descriptor>) -> Self {
        self.descriptor = descriptor;
        self
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::registry::metadata_store::link::metadata::*;
    use crate::registry::test_utils::media_type;

    const VALID_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn digest() -> Digest {
        Digest::sha256(VALID_HASH).unwrap()
    }

    /// An angos before 1.5.0 recorded the pushed `Content-Type` verbatim,
    /// parameters included; refusing those on read would have scrub delete the
    /// link as corrupt.
    #[test]
    fn a_recorded_media_type_keeps_reading_when_it_carries_parameters() {
        let stored = serde_json::json!({
            "target": format!("sha256:{VALID_HASH}"),
            "created_at": null,
            "media_type": "application/vnd.oci.image.manifest.v1+json; charset=utf-8",
        });

        let metadata: LinkMetadata =
            serde_json::from_value(stored).expect("a legacy link must stay readable");

        assert_eq!(
            metadata.media_type,
            Some(media_type("application/vnd.oci.image.manifest.v1+json"))
        );
    }

    fn minimal_descriptor() -> Descriptor {
        Descriptor {
            media_type: media_type("application/vnd.oci.image.manifest.v1+json"),
            digest: digest(),
            size: 42,
            annotations: HashMap::new(),
            artifact_type: None,
            platform: None,
        }
    }

    #[test]
    fn from_digest_at_uses_explicit_timestamp() {
        let ts = Utc::now() - chrono::Duration::hours(2);
        let meta = LinkMetadata::from_digest_at(digest(), ts);
        assert_eq!(meta.target, digest());
        assert_eq!(meta.created_at, Some(ts));
        assert!(meta.media_type.is_none());
        assert!(meta.descriptor.is_none());
    }

    #[test]
    fn link_metadata_survives_json_round_trip() {
        let meta = LinkMetadata::from_digest(digest())
            .with_media_type(Some(media_type(
                "application/vnd.oci.image.manifest.v1+json",
            )))
            .with_descriptor(Some(minimal_descriptor()));

        let bytes = serde_json::to_vec(&meta).unwrap();
        let parsed: LinkMetadata = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(parsed.target, meta.target);
        assert_eq!(parsed.media_type, meta.media_type);
        assert_eq!(parsed.descriptor, meta.descriptor);
    }

    #[test]
    fn with_media_type_assigns_field() {
        let meta = LinkMetadata::from_digest(digest())
            .with_media_type(Some(media_type("application/vnd.foo")));
        assert_eq!(meta.media_type, Some(media_type("application/vnd.foo")));
    }

    #[test]
    fn with_media_type_none_clears_field() {
        let meta = LinkMetadata::from_digest(digest())
            .with_media_type(Some(media_type("application/vnd.foo")))
            .with_media_type(None);
        assert!(meta.media_type.is_none());
    }

    #[test]
    fn with_descriptor_assigns_field() {
        let desc = minimal_descriptor();
        let meta = LinkMetadata::from_digest(digest()).with_descriptor(Some(desc.clone()));
        assert_eq!(meta.descriptor, Some(desc));
    }
}
