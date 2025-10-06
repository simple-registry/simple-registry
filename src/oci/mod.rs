use serde::Serialize;

mod descriptor;
mod digest;
mod error;
mod manifest;
mod reference;

pub use descriptor::Descriptor;
pub use digest::Digest;
pub use manifest::Manifest;
pub use reference::Reference;
pub use error::Error;

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
