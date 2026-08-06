//! Accept-header set for downstream manifest probes. The last-writer-wins
//! wire constants live on the transport client (`crate::registry_client`),
//! which speaks them on the wire for every consumer.

use crate::oci::{MediaRange, MediaType};

/// Manifest media types stamped as `Accept` headers on every downstream
/// manifest probe. Without them a content-negotiating registry may return a
/// converted representation whose digest never matches the local one.
#[must_use]
pub fn manifest_accept_types() -> Vec<MediaRange> {
    [
        MediaType::oci_manifest(),
        MediaType::oci_index(),
        MediaType::docker_manifest(),
        MediaType::docker_manifest_list(),
    ]
    .map(MediaRange::from)
    .to_vec()
}
