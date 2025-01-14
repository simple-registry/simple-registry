use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct ManifestImage {
    pub tag: Option<String>,
    pub pushed_at: i64,
    pub last_pulled_at: i64,
}
