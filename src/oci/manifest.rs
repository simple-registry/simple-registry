use std::{collections::HashMap, mem};

use serde::{Deserialize, Serialize};

use crate::oci::{Descriptor, Digest, Error, MediaType};

/// OCI image-spec manifest `schemaVersion`. Enforced where a manifest enters
/// the store, not on this DTO, so angos keeps reading what it once accepted.
pub const OCI_MANIFEST_SCHEMA_VERSION: i32 = 2;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub schema_version: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<MediaType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Descriptor>,
    /// Always serialized: the image spec requires `layers` on an image
    /// manifest, so omitting it when empty would emit an invalid document.
    #[serde(default)]
    pub layers: Vec<Descriptor>,
    /// Always serialized, for the same reason `manifests` is required on an
    /// index.
    #[serde(default)]
    pub manifests: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Descriptor>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<MediaType>,
}

impl Manifest {
    /// Deserializes leniently, like `media_type` being optional: angos must
    /// keep reading manifests it once accepted. Ingress checks the strict rules.
    pub fn from_slice(s: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice(s)?)
    }

    /// Returns `true` if `artifact_type` equals either the manifest's top-level
    /// `artifactType` field or, per the OCI Referrers API spec, the config's
    /// `mediaType` fallback.
    pub fn has_artifact_type(&self, artifact_type: &str) -> bool {
        self.artifact_type.as_deref() == Some(artifact_type)
            || self
                .config
                .as_ref()
                .is_some_and(|c| c.media_type == artifact_type)
    }

    /// Returns whether this manifest's `artifact_type` (or config `mediaType`
    /// fallback) matches the given filter. A `None` filter matches anything.
    pub fn artifact_type_matches(&self, filter: Option<&String>) -> bool {
        filter.is_none_or(|want| self.has_artifact_type(want))
    }

    /// Builds a `Descriptor` for this manifest, moving the (potentially large)
    /// annotations map out of `self` rather than cloning it. Returns `None`
    /// only when the manifest carries no `media_type`. Filter-mismatch is a
    /// separate concern; callers that need filtering call
    /// `artifact_type_matches` first.
    pub fn take_descriptor(&mut self, digest: Digest, size: u64) -> Option<Descriptor> {
        let media_type = self.media_type.clone()?;
        // Per the OCI Referrers API a referrer's `artifactType` is the manifest's
        // own field, falling back to the config `mediaType` for image manifests
        // without one; an empty value would drop the entry from filtered lists.
        let artifact_type = self
            .artifact_type
            .clone()
            .or_else(|| self.config.as_ref().map(|c| c.media_type.clone()));
        Some(Descriptor {
            media_type,
            annotations: mem::take(&mut self.annotations),
            artifact_type,
            platform: None,
            digest,
            size,
        })
    }
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            schema_version: OCI_MANIFEST_SCHEMA_VERSION,
            media_type: None,
            config: None,
            layers: Vec::new(),
            manifests: Vec::new(),
            subject: None,
            annotations: HashMap::new(),
            artifact_type: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::oci::Digest;

    const VALID_HASH: &str = "99c9d5e2bdc7ef0223f56c845a695ea0f8f11f5b55ea6f74e1f7df0d4f90026c";
    const MEDIA_TYPE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
    const MEDIA_TYPE_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
    const ARTIFACT_TYPE_INDEX: &str = "application/vnd.oci.image.index.v1+json";

    fn valid_digest() -> Digest {
        Digest::sha256(VALID_HASH).unwrap()
    }

    fn media_type(value: &str) -> MediaType {
        MediaType::new(value).unwrap()
    }

    fn demo_manifest() -> Manifest {
        Manifest {
            media_type: Some(media_type(MEDIA_TYPE_MANIFEST)),
            config: Some(Descriptor {
                media_type: media_type(MEDIA_TYPE_CONFIG),
                digest: valid_digest(),
                size: 1234,
                annotations: HashMap::new(),
                artifact_type: None,
                platform: None,
            }),
            layers: vec![Descriptor {
                media_type: media_type("application/vnd.oci.image.layer.v1.tar"),
                digest: valid_digest(),
                size: 5678,
                annotations: HashMap::new(),
                artifact_type: None,
                platform: None,
            }],
            artifact_type: Some(media_type(ARTIFACT_TYPE_INDEX)),
            ..Manifest::default()
        }
    }

    /// A `null` config or subject is not something a client would ever send,
    /// and `layers` is required on an image manifest however empty it is.
    #[test]
    fn serializing_omits_absent_fields_but_keeps_the_required_arrays() {
        let json = serde_json::to_value(Manifest::default()).unwrap();
        let object = json
            .as_object()
            .expect("a manifest serializes to an object");

        assert!(
            !object.values().any(Value::is_null),
            "no field may serialize as null: {json}"
        );
        assert!(
            !object.contains_key("annotations"),
            "an empty annotations map must be omitted: {json}"
        );
        assert!(
            object.contains_key("layers") && object.contains_key("manifests"),
            "the spec-required arrays must survive an empty manifest: {json}"
        );
    }

    #[test]
    fn serializing_keeps_the_fields_that_are_set() {
        let json = serde_json::to_value(demo_manifest()).unwrap();

        assert_eq!(json["mediaType"], MEDIA_TYPE_MANIFEST);
        assert_eq!(json["artifactType"], ARTIFACT_TYPE_INDEX);
        assert_eq!(json["config"]["size"], 1234);
        assert_eq!(json["layers"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn test_has_artifact_type_top_level_field() {
        let manifest = demo_manifest();
        assert!(manifest.has_artifact_type(ARTIFACT_TYPE_INDEX));
    }

    #[test]
    fn test_has_artifact_type_config_media_type_fallback() {
        let manifest = demo_manifest();
        assert!(manifest.has_artifact_type(MEDIA_TYPE_CONFIG));
    }

    #[test]
    fn test_has_artifact_type_no_match() {
        let manifest = demo_manifest();
        assert!(!manifest.has_artifact_type("application/vnd.example.unknown"));
    }

    #[test]
    fn test_has_artifact_type_none_artifact_type_none_config() {
        let manifest = Manifest::default();
        assert!(!manifest.has_artifact_type("application/vnd.anything"));
    }

    // take_descriptor: media_type present → Some(Descriptor)
    #[test]
    fn test_take_descriptor_with_media_type_returns_descriptor() {
        let mut manifest = demo_manifest();
        let digest = valid_digest();
        let descriptor = manifest.take_descriptor(digest.clone(), 999);
        let d = descriptor.expect("expected Some(Descriptor)");
        assert_eq!(d.media_type, MEDIA_TYPE_MANIFEST);
        assert_eq!(d.digest, digest);
        assert_eq!(d.size, 999);
        assert_eq!(d.artifact_type.as_deref(), Some(ARTIFACT_TYPE_INDEX));
    }

    // take_descriptor: an image manifest without its own artifactType advertises
    // the config mediaType (OCI Referrers API fallback), not an empty value.
    #[test]
    fn test_take_descriptor_falls_back_to_config_media_type() {
        let mut manifest = demo_manifest();
        manifest.artifact_type = None;
        let d = manifest
            .take_descriptor(valid_digest(), 1)
            .expect("expected Some(Descriptor)");
        assert_eq!(d.artifact_type.as_deref(), Some(MEDIA_TYPE_CONFIG));
    }

    // take_descriptor: media_type absent → None (only reason to return None now)
    #[test]
    fn test_take_descriptor_no_media_type_returns_none() {
        let mut manifest = Manifest {
            media_type: None,
            ..Manifest::default()
        };
        let descriptor = manifest.take_descriptor(valid_digest(), 0);
        assert!(descriptor.is_none(), "absent media_type must yield None");
    }

    // artifact_type_matches: None filter matches anything
    #[test]
    fn test_artifact_type_matches_none_filter_always_matches() {
        assert!(demo_manifest().artifact_type_matches(None));
        let bare = Manifest::default();
        assert!(bare.artifact_type_matches(None));
    }

    // artifact_type_matches: filter matches the manifest's own artifact_type
    #[test]
    fn test_artifact_type_matches_filter_matches_artifact_type() {
        let manifest = demo_manifest();
        let filter = ARTIFACT_TYPE_INDEX.to_string();
        assert!(manifest.artifact_type_matches(Some(&filter)));
    }

    // artifact_type_matches: filter matches the config media_type
    #[test]
    fn test_artifact_type_matches_filter_matches_config_media_type() {
        let manifest = demo_manifest();
        let filter = MEDIA_TYPE_CONFIG.to_string();
        assert!(manifest.artifact_type_matches(Some(&filter)));
    }

    // artifact_type_matches: filter doesn't match any type
    #[test]
    fn test_artifact_type_matches_filter_no_match() {
        let manifest = demo_manifest();
        let filter = "application/vnd.example.unknown".to_string();
        assert!(!manifest.artifact_type_matches(Some(&filter)));
    }
}
