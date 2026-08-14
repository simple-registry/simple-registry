//! The path grammar of the distribution API, spelled once. [`crate::client`]
//! builds request URLs from these and [`crate::server`] takes them apart, so
//! neither end can drift from the other.

/// Prefix every endpoint of the API sits under.
pub const API_PREFIX: &str = "/v2/";

pub const MANIFESTS: &str = "/manifests/";
pub const BLOBS: &str = "/blobs/";
/// A blob upload, whose trailing slash the spec includes.
pub const UPLOADS: &str = "/blobs/uploads/";
pub const REFERRERS: &str = "/referrers/";
pub const TAGS_LIST: &str = "/tags/list";
