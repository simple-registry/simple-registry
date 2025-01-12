use tokio::io::AsyncReadExt;
use tracing::{debug, error, instrument, warn};

use crate::oci::{Digest, Manifest, Reference};
use crate::registry::{Error, Registry};
use crate::storage::EntityLink;

pub struct GetManifestResponse {
    pub media_type: Option<String>,
    pub digest: Digest,
    pub content: Vec<u8>,
}

pub struct HeadManifestResponse {
    pub media_type: Option<String>,
    pub digest: Digest,
    pub size: usize,
}

pub struct PutManifestResponse {
    pub digest: Digest,
    pub subject: Option<Digest>,
}

pub struct ParsedManifestDigests {
    pub subject: Option<Digest>,
    pub config: Option<Digest>,
    pub layers: Vec<Digest>,
}

pub fn parse_manifest_digests(
    body: &[u8],
    content_type: Option<&String>,
) -> Result<ParsedManifestDigests, Error> {
    let manifest: Manifest = serde_json::from_slice(body).map_err(|e| {
        debug!("Failed to deserialize manifest: {}", e);
        Error::ManifestInvalid(Some("Failed to deserialize manifest".to_string()))
    })?;

    if content_type.is_some()
        && manifest.media_type.is_some()
        && manifest.media_type.as_ref() != content_type
    {
        warn!(
            "Manifest media type mismatch: {:?} (expected) != {:?} (found)",
            content_type, manifest.media_type
        );
        return Err(Error::ManifestInvalid(Some(
            "Expected manifest media type mismatch".to_string(),
        )));
    }

    let subject = manifest
        .subject
        .map(|subject| Digest::try_from(subject.digest.as_str()))
        .transpose()?;

    let config = manifest
        .config
        .map(|config| Digest::try_from(config.digest.as_str()))
        .transpose()?;

    let layers = manifest
        .layers
        .iter()
        .map(|layer| Digest::try_from(layer.digest.as_str()))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ParsedManifestDigests {
        subject,
        config,
        layers,
    })
}

impl Registry {
    #[instrument]
    pub async fn head_manifest(
        &self,
        namespace: &str,
        reference: Reference,
    ) -> Result<HeadManifestResponse, Error> {
        self.validate_namespace(namespace)?;

        let link = reference.into();
        let digest = self.storage_engine.read_link(namespace, &link).await?;
        self.storage_engine
            .update_last_pulled(namespace, &link)
            .await?;

        let mut reader = self
            .storage_engine
            .build_blob_reader(&digest, None)
            .await
            .map_err(|e| {
                error!("Failed to build blob reader: {}", e);
                Error::ManifestUnknown
            })?;

        let mut manifest_content = Vec::new();
        reader.read_to_end(&mut manifest_content).await?;

        let manifest = serde_json::from_slice::<Manifest>(&manifest_content)?;
        let size = manifest_content.len();

        Ok(HeadManifestResponse {
            media_type: manifest.media_type,
            digest,
            size,
        })
    }

    #[instrument]
    pub async fn get_manifest(
        &self,
        namespace: &str,
        reference: Reference,
    ) -> Result<GetManifestResponse, Error> {
        self.validate_namespace(namespace)?;

        let link = reference.into();
        let digest = self.storage_engine.read_link(namespace, &link).await?;
        self.storage_engine
            .update_last_pulled(namespace, &link)
            .await?;

        let content = self.storage_engine.read_blob(&digest).await?;

        let manifest = serde_json::from_slice::<Manifest>(&content).map_err(|e| {
            debug!("Failed to deserialize manifest: {}", e);
            Error::ManifestInvalid(Some("Failed to deserialize manifest".to_string()))
        })?;

        Ok(GetManifestResponse {
            media_type: manifest.media_type,
            digest,
            content,
        })
    }

    #[instrument(skip(body))]
    pub async fn put_manifest(
        &self,
        namespace: &str,
        reference: Reference,
        content_type: String,
        body: &[u8],
    ) -> Result<PutManifestResponse, Error> {
        self.validate_namespace(namespace)?;

        let manifest_digests = parse_manifest_digests(body, Some(&content_type))?;

        let digest = match reference {
            Reference::Tag(tag) => {
                let digest = self.storage_engine.create_blob(body).await?;

                let link = EntityLink::Tag(tag);
                self.storage_engine
                    .create_link(namespace, &link, &digest)
                    .await?;
                let link = EntityLink::Digest(digest.clone());
                self.storage_engine
                    .create_link(namespace, &link, &digest)
                    .await?;

                digest
            }
            Reference::Digest(provided_digest) => {
                let digest = self.storage_engine.create_blob(body).await?;

                if provided_digest != digest {
                    warn!(
                        "Provided digest does not match calculated digest: {} != {}",
                        provided_digest, digest
                    );
                    return Err(Error::ManifestInvalid(Some(
                        "Provided digest does not match calculated digest".to_string(),
                    )));
                }
                let link = EntityLink::Digest(digest.clone());
                self.storage_engine
                    .create_link(namespace, &link, &digest)
                    .await?;

                digest
            }
        };

        if let Some(subject) = &manifest_digests.subject {
            let link = EntityLink::Referrer(subject.clone(), digest.clone());
            self.storage_engine
                .create_link(namespace, &link, &digest)
                .await?;
        }

        if let Some(config_digest) = manifest_digests.config {
            let link = EntityLink::Config(config_digest.clone());
            self.storage_engine
                .create_link(namespace, &link, &config_digest)
                .await?;
        }

        for layer_digest in manifest_digests.layers {
            let link = EntityLink::Layer(layer_digest.clone());
            self.storage_engine
                .create_link(namespace, &link, &layer_digest)
                .await?;
        }

        Ok(PutManifestResponse {
            digest,
            subject: manifest_digests.subject,
        })
    }

    #[instrument]
    pub async fn delete_manifest(
        &self,
        namespace: &str,
        reference: Reference,
    ) -> Result<(), Error> {
        self.validate_namespace(namespace)?;

        match reference {
            Reference::Tag(tag) => {
                let link = EntityLink::Tag(tag);
                self.storage_engine.delete_link(namespace, &link).await?;
            }
            Reference::Digest(digest) => {
                let mut marker = None;
                loop {
                    let (tags, next_marker) = self
                        .storage_engine
                        .list_tags(namespace, 100, marker)
                        .await?;

                    for tag in tags {
                        let link_reference = EntityLink::Tag(tag);
                        if self
                            .storage_engine
                            .read_link(namespace, &link_reference)
                            .await?
                            == digest
                        {
                            self.storage_engine
                                .delete_link(namespace, &link_reference)
                                .await?;
                        }
                    }

                    let link = EntityLink::Digest(digest.clone());

                    let digest = self.storage_engine.read_link(namespace, &link).await?;
                    let content = self.storage_engine.read_blob(&digest).await?;
                    let manifest_digests = parse_manifest_digests(&content, None)?;

                    if let Some(subject_digest) = manifest_digests.subject {
                        let link = EntityLink::Referrer(subject_digest, digest);
                        self.storage_engine.delete_link(namespace, &link).await?;
                    }

                    self.storage_engine.delete_link(namespace, &link).await?;

                    if next_marker.is_none() {
                        break;
                    }

                    marker = next_marker;
                }
            }
        }

        Ok(())
    }
}
