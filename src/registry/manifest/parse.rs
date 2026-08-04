use tracing::warn;

use crate::{
    oci::{Digest, Manifest, MediaType, OCI_MANIFEST_SCHEMA_VERSION},
    registry::{Error, metadata_store::LinkKind},
};

pub struct ParsedManifestDigests {
    /// The manifest body's declared `mediaType`, surfaced from the single parse
    /// so callers need not re-parse the body just to read it.
    pub media_type: Option<MediaType>,
    /// The manifest body's declared `artifactType`, surfaced from the same parse
    /// so a referrer descriptor can be built without re-parsing the body.
    pub artifact_type: Option<MediaType>,
    pub subject: Option<Digest>,
    pub config: Option<Digest>,
    pub layers: Vec<Digest>,
    pub manifests: Vec<Digest>,
}

impl ParsedManifestDigests {
    pub fn links_for_revision(&self, revision: &Digest) -> Vec<(LinkKind, Digest)> {
        let mut links = self.referenced_links_for_revision(revision);

        if let Some(subject) = &self.subject {
            links.push((
                LinkKind::Referrer(subject.clone(), revision.clone()),
                revision.clone(),
            ));
        }

        links
    }

    pub fn referenced_links_for_revision(&self, revision: &Digest) -> Vec<(LinkKind, Digest)> {
        let config = self
            .config
            .iter()
            .map(|digest| (LinkKind::Config(digest.clone()), digest.clone()));
        let layers = self
            .layers
            .iter()
            .map(|digest| (LinkKind::Layer(digest.clone()), digest.clone()));
        let manifests = self.manifests.iter().map(|digest| {
            (
                LinkKind::Manifest(revision.clone(), digest.clone()),
                digest.clone(),
            )
        });

        config.chain(layers).chain(manifests).collect()
    }
}

fn validate_media_type_match(
    manifest: &Manifest,
    content_type: Option<&MediaType>,
) -> Result<(), Error> {
    if content_type.is_some()
        && manifest.media_type.is_some()
        && manifest.media_type.as_ref() != content_type
    {
        warn!(
            "Manifest media type mismatch: {content_type:?} (expected) != {:?} (found)",
            manifest.media_type
        );
        return Err(Error::ManifestInvalid(
            "Expected manifest media type mismatch".to_string(),
        ));
    }
    Ok(())
}

/// Deserialize a manifest body and verify its declared media type matches the
/// optional `content_type` hint. Centralises the JSON-to-`Manifest` conversion
/// so both `parse_manifest_digests` (digest projection) and `put_manifest`
/// (full-manifest writer) share one error payload.
pub fn parse_and_validate_manifest(
    body: &[u8],
    content_type: Option<&MediaType>,
) -> Result<Manifest, Error> {
    let manifest: Manifest = serde_json::from_slice(body).map_err(|e| {
        warn!("Failed to deserialize manifest: {e}");
        Error::ManifestInvalid(format!("invalid manifest JSON: {e}"))
    })?;
    validate_media_type_match(&manifest, content_type)?;
    Ok(manifest)
}

/// [`parse_and_validate_manifest`] for the ingress paths, additionally pinning
/// `schemaVersion` to the one the image spec defines. Parsing and the check are
/// one step so a write path cannot take the lenient door by accident.
pub fn parse_pushed_manifest(
    body: &[u8],
    content_type: Option<&MediaType>,
) -> Result<Manifest, Error> {
    let manifest = parse_and_validate_manifest(body, content_type)?;
    if manifest.schema_version != OCI_MANIFEST_SCHEMA_VERSION {
        warn!(
            "Rejecting manifest with schemaVersion {}",
            manifest.schema_version
        );
        return Err(Error::ManifestInvalid(format!(
            "unsupported schemaVersion {}, expected {OCI_MANIFEST_SCHEMA_VERSION}",
            manifest.schema_version
        )));
    }
    Ok(manifest)
}

/// Recovers the media type to serve for a stored manifest whose link carries no
/// `media_type` (rebuilt by `angos migrate` from a pre-JSON layout, or filled
/// from an upstream that sent no `Content-Type`). Prefers the body's own
/// `mediaType`, else the OCI index type for a manifest list and the OCI manifest
/// type otherwise, so a served manifest never lacks the `Content-Type` the OCI
/// spec requires and go-containerregistry clients reject when absent.
pub fn recover_media_type(body: &[u8]) -> MediaType {
    let manifest = Manifest::from_slice(body).ok();
    if let Some(media_type) = manifest.as_ref().and_then(|m| m.media_type.clone()) {
        return media_type;
    }
    if manifest.is_some_and(|m| !m.manifests.is_empty()) {
        MediaType::oci_index()
    } else {
        MediaType::oci_manifest()
    }
}

pub fn parse_manifest_digests(
    body: &[u8],
    content_type: Option<&MediaType>,
) -> Result<ParsedManifestDigests, Error> {
    let manifest = parse_and_validate_manifest(body, content_type)?;

    let subject = manifest.subject.map(|subject| subject.digest);

    let config = manifest.config.map(|config| config.digest);

    let layers = manifest
        .layers
        .into_iter()
        .map(|layer| layer.digest)
        .collect::<Vec<_>>();

    let manifests = manifest
        .manifests
        .into_iter()
        .map(|m| m.digest)
        .collect::<Vec<_>>();

    Ok(ParsedManifestDigests {
        media_type: manifest.media_type,
        artifact_type: manifest.artifact_type,
        subject,
        config,
        layers,
        manifests,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{parse_manifest_digests, recover_media_type};
    use crate::oci::MediaType;

    const CHILD_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const MEDIA_TYPE_V2: &str = "application/vnd.docker.distribution.manifest.v2+json";

    #[test]
    fn recover_media_type_prefers_the_body_media_type() {
        let body = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        }))
        .unwrap();
        assert_eq!(
            recover_media_type(&body),
            MediaType::new("application/vnd.docker.distribution.manifest.v2+json").unwrap()
        );
    }

    #[test]
    fn recover_media_type_defaults_a_typeless_image_to_oci_manifest() {
        let body = serde_json::to_vec(&json!({ "schemaVersion": 2 })).unwrap();
        assert_eq!(recover_media_type(&body), MediaType::oci_manifest());
    }

    #[test]
    fn recover_media_type_defaults_a_typeless_list_to_oci_index() {
        let body = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": CHILD_DIGEST,
                "size": 512,
            }],
        }))
        .unwrap();
        assert_eq!(recover_media_type(&body), MediaType::oci_index());
    }

    /// Reads stay lenient so a scrub or a replication push never trips over an
    /// object an older angos accepted; only the write paths reject it.
    #[test]
    fn a_stored_foreign_schema_version_is_still_parsed() {
        let body = serde_json::to_vec(&json!({
            "schemaVersion": 1,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        }))
        .unwrap();
        let parsed = parse_manifest_digests(&body, None)
            .expect("a stored manifest must stay readable whatever its schemaVersion");
        assert_eq!(parsed.media_type.as_deref(), Some(MEDIA_TYPE_V2));
    }

    #[test]
    fn recover_media_type_falls_back_when_the_body_is_unparseable() {
        assert_eq!(
            recover_media_type(b"not a manifest"),
            MediaType::oci_manifest()
        );
    }
}
