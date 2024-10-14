use serde::{Deserialize, Serialize};
use std::collections::HashMap;

mod digest;
mod reference;

pub use digest::Digest;
pub use reference::Reference;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
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

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ReferrerList {
    pub schema_version: i32,
    pub media_type: String,
    pub manifests: Vec<Descriptor>,
}

impl Default for ReferrerList {
    fn default() -> Self {
        ReferrerList {
            schema_version: 2,
            media_type: "application/vnd.oci.image.index.v1+json".to_string(),
            manifests: Vec::new(),
        }
    }
}
