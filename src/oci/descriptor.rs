use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::oci::Manifest;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
}

impl From<Manifest> for Option<Descriptor> {
    fn from(manifest: Manifest) -> Option<Descriptor> {
        Some(Descriptor {
            media_type: manifest.media_type?,
            annotations: manifest.annotations,
            artifact_type: manifest.artifact_type,
            ..Descriptor::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::manifest::tests::demo_manifest;

    #[test]
    fn test_from_manifest() {
        let manifest = demo_manifest();
        let descriptor: Option<Descriptor> = demo_manifest().into();
        let descriptor = descriptor.expect("Failed to convert manifest to descriptor");

        assert_eq!(descriptor.media_type, manifest.media_type.unwrap());
        assert_eq!(descriptor.annotations, manifest.annotations);
        assert_eq!(descriptor.artifact_type, manifest.artifact_type);
    }
}
