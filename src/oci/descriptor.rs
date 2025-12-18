use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::oci::Digest;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(default)]
    #[serde(rename = "os.version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(default)]
    #[serde(rename = "os.features")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_features: Option<Vec<String>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: Digest,
    pub size: u64,
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_serialization() {
        let platform = Platform {
            architecture: "amd64".to_string(),
            os: "linux".to_string(),
            variant: Some("v8".to_string()),
            os_version: Some("10.0.19041".to_string()),
            os_features: Some(vec!["win32k".to_string()]),
            features: Some(vec!["sse4".to_string()]),
        };

        let json = serde_json::to_string(&platform).unwrap();

        assert!(json.contains(r#""os.version":"10.0.19041""#));
        assert!(json.contains(r#""os.features":["win32k"]"#));
        assert!(json.contains(r#""architecture":"amd64""#));
        assert!(json.contains(r#""os":"linux""#));
    }

    #[test]
    fn test_platform_deserialization() {
        let json = r#"{
            "architecture": "arm64",
            "os": "linux",
            "variant": "v8",
            "os.version": "22.04",
            "os.features": ["feature1", "feature2"]
        }"#;

        let platform: Platform = serde_json::from_str(json).unwrap();

        assert_eq!(platform.architecture, "arm64");
        assert_eq!(platform.os, "linux");
        assert_eq!(platform.variant, Some("v8".to_string()));
        assert_eq!(platform.os_version, Some("22.04".to_string()));
        assert_eq!(
            platform.os_features,
            Some(vec!["feature1".to_string(), "feature2".to_string()])
        );
    }
}
