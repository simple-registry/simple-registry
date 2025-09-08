use crate::registry::oci::{Descriptor, Error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub schema_version: i32,
    pub media_type: Option<String>,
    #[serde(default)]
    pub config: Option<Descriptor>,
    #[serde(default)]
    pub layers: Vec<Descriptor>,
    #[serde(default)]
    pub subject: Option<Descriptor>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    #[serde(default)]
    pub artifact_type: Option<String>,
}

impl Manifest {
    pub fn from_slice(s: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice(s)?)
    }

    fn artifact_types(&self) -> Vec<String> {
        let mut types = Vec::new();
        if let Some(artifact_type) = &self.artifact_type {
            types.push(artifact_type.clone());
        }
        if let Some(config) = &self.config {
            types.push(config.media_type.clone());
        }
        types
    }

    pub fn into_referrer_descriptor(self, artifact_type: Option<&String>) -> Option<Descriptor> {
        if let Some(artifact_type) = artifact_type {
            if !self.artifact_types().contains(artifact_type) {
                return None;
            }
        }
        self.into()
    }
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            schema_version: 2,
            media_type: None,
            config: None,
            layers: Vec::new(),
            subject: None,
            annotations: HashMap::new(),
            artifact_type: None,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn demo_manifest() -> Manifest {
        Manifest {
            media_type: Some("application/vnd.oci.image.manifest.v1+json".to_string()),
            config: Some(Descriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_string(),
                digest: "sha256:99c9d5e2bdc7ef0223f56c845a695ea0f8f11f5b55ea6f74e1f7df0d4f90026c"
                    .to_string(),
                size: 1234,
                ..Descriptor::default()
            }),
            layers: vec![Descriptor {
                media_type: "application/vnd.oci.image.layer.v1.tar".to_string(),
                digest: "sha256:99c9d5e2bdc7ef0223f56c845a695ea0f8f11f5b55ea6f74e1f7df0d4f90026c"
                    .to_string(),
                size: 5678,
                ..Descriptor::default()
            }],
            artifact_type: Some("oci.image.index.v1".to_string()),
            ..Manifest::default()
        }
    }

    #[test]
    fn test_from_slice() {
        let manifest = demo_manifest();
        let raw_manifest = serde_json::to_vec(&manifest).expect("Failed to serialize manifest");

        let parsed_manifest =
            Manifest::from_slice(raw_manifest.as_slice()).expect("Failed to parse manifest");
        assert_eq!(manifest, parsed_manifest);
    }

    #[test]
    fn test_artifact_types() {
        let manifest = demo_manifest();
        assert_eq!(
            manifest.artifact_types(),
            vec![
                "oci.image.index.v1".to_string(),
                "application/vnd.oci.image.config.v1+json".to_string(),
            ]
        );
    }

    #[test]
    fn test_into_referrer_descriptor() {
        let manifest = demo_manifest();
        let expected_descriptor = Descriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            digest: String::new(),
            size: 0,
            annotations: HashMap::new(),
            artifact_type: Some("oci.image.index.v1".to_string()),
        };

        let descriptor = manifest.into_referrer_descriptor(None);
        assert_eq!(descriptor, Some(expected_descriptor.clone()));

        let manifest = demo_manifest();
        let descriptor = manifest.into_referrer_descriptor(Some(&"oci.image.index.v1".to_string()));
        assert_eq!(descriptor, Some(expected_descriptor));

        let manifest = demo_manifest();
        let descriptor = manifest
            .into_referrer_descriptor(Some(&"application/vnd.oci.image.layer.v1.tar".to_string()));
        assert_eq!(descriptor, None);
    }
}
