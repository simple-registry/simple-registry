use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct ManifestImage {
    pub tag: String,
    pub pushed_at: u64,
    pub last_pulled_at: u64,
}
