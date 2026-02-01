use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::oci::{Descriptor, Digest, Error};

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
    pub manifests: Vec<Descriptor>,
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

    pub fn to_descriptor(
        &self,
        artifact_type: Option<&String>,
        digest: Digest,
        size: u64,
    ) -> Option<Descriptor> {
        if let Some(artifact_type) = artifact_type
            && !self.artifact_types().contains(artifact_type)
        {
            return None;
        }

        Some(Descriptor {
            media_type: self.media_type.clone()?,
            annotations: self.annotations.clone(),
            artifact_type: self.artifact_type.clone(),
            platform: None,
            digest,
            size,
        })
    }
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            schema_version: 2,
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
pub mod tests {
    use super::*;
    use crate::oci::Digest;

    pub fn demo_manifest() -> Manifest {
        Manifest {
            media_type: Some("application/vnd.oci.image.manifest.v1+json".to_string()),
            config: Some(Descriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_string(),
                digest: Digest::Sha256(
                    "99c9d5e2bdc7ef0223f56c845a695ea0f8f11f5b55ea6f74e1f7df0d4f90026c".into(),
                ),
                size: 1234,
                annotations: HashMap::new(),
                artifact_type: None,
                platform: None,
            }),
            layers: vec![Descriptor {
                media_type: "application/vnd.oci.image.layer.v1.tar".to_string(),
                digest: Digest::Sha256(
                    "99c9d5e2bdc7ef0223f56c845a695ea0f8f11f5b55ea6f74e1f7df0d4f90026c".into(),
                ),
                size: 5678,
                annotations: HashMap::new(),
                artifact_type: None,
                platform: None,
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
}
