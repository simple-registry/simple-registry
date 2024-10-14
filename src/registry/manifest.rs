use tokio::io::AsyncReadExt;
use tracing::{debug, error, instrument, warn};

use crate::error::RegistryError;
use crate::io_helpers::parse_reader;
use crate::oci::{Digest, Manifest, Reference};
use crate::registry::{LinkReference, Registry};

pub struct ManifestData {
    pub media_type: Option<String>,
    pub digest: Digest,
    pub content: Vec<u8>,
}

pub struct ManifestSummary {
    pub media_type: Option<String>,
    pub digest: Digest,
    pub size: usize,
}

pub struct NewManifest {
    pub digest: Digest,
    pub subject: Option<Digest>,
}

struct ManifestDigests {
    subject: Option<Digest>,
    config: Option<Digest>,
    layers: Vec<Digest>,
}

fn parse_manifest_digests(
    body: &[u8],
    expected_content_type: Option<String>,
) -> Result<ManifestDigests, RegistryError> {
    let manifest: Manifest = serde_json::from_slice(body).map_err(|e| {
        debug!("Failed to deserialize manifest: {}", e);
        RegistryError::ManifestInvalid(Some("Failed to deserialize manifest".to_string()))
    })?;

    if let Some(expected_content_type) = expected_content_type {
        if manifest.media_type.is_some()
            && manifest.media_type != Some(expected_content_type.clone())
        {
            warn!(
                "Expected manifest media type mismatch: {} (expected) != {:?} (found)",
                expected_content_type, manifest.media_type
            );
            return Err(RegistryError::ManifestInvalid(Some(
                "Expected manifest media type mismatch".to_string(),
            )));
        }
    }

    let subject = manifest
        .subject
        .map(|subject| Digest::from_str(&subject.digest))
        .transpose()?;

    let config = manifest
        .config
        .map(|config| Digest::from_str(&config.digest))
        .transpose()?;

    let layers = manifest
        .layers
        .iter()
        .map(|layer| Digest::from_str(&layer.digest))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ManifestDigests {
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
        reference: LinkReference,
    ) -> Result<ManifestSummary, RegistryError> {
        self.validate_namespace(namespace)?;

        let digest = self.storage.read_link(namespace, &reference).await?;

        let reader = self
            .storage
            .build_blob_reader(&digest, None)
            .await
            .map_err(|e| {
                error!("Failed to build blob reader: {}", e);
                RegistryError::ManifestUnknown
            })?;
        let (manifest, size) = parse_reader::<Manifest, _>(reader).await.map_err(|e| {
            debug!("Failed to deserialize manifest: {}", e);
            RegistryError::ManifestInvalid(Some("Failed to deserialize manifest".to_string()))
        })?;

        let media_type = manifest.media_type.clone();

        Ok(ManifestSummary {
            media_type,
            digest,
            size,
        })
    }

    #[instrument]
    pub async fn get_manifest(
        &self,
        namespace: &str,
        reference: LinkReference,
    ) -> Result<ManifestData, RegistryError> {
        self.validate_namespace(namespace)?;

        let digest = self.storage.read_link(namespace, &reference).await?;

        let mut reader = self.storage.build_blob_reader(&digest, None).await?;

        let mut content = Vec::new();
        reader.read_to_end(&mut content).await?;

        let manifest = serde_json::from_slice::<Manifest>(&content).map_err(|e| {
            debug!("Failed to deserialize manifest: {}", e);
            RegistryError::ManifestInvalid(Some("Failed to deserialize manifest".to_string()))
        })?;

        let media_type = manifest.media_type.clone();

        Ok(ManifestData {
            media_type,
            digest,
            content,
        })
    }

    #[instrument]
    pub async fn put_manifest(
        &self,
        namespace: &str,
        reference: Reference,
        content_type: String,
        body: &[u8],
    ) -> Result<NewManifest, RegistryError> {
        self.validate_namespace(namespace)?;

        let manifest_digests = parse_manifest_digests(body, Some(content_type))?;

        let digest = self.storage.create_blob(body).await?;

        match reference {
            Reference::Tag(tag) => {
                let link = LinkReference::Tag(tag);
                self.storage.create_link(namespace, &link, &digest).await?;
                let link = LinkReference::Digest(digest.clone());
                self.storage.create_link(namespace, &link, &digest).await?;
            }
            Reference::Digest(provided_digest) => {
                if provided_digest != digest {
                    warn!(
                        "Provided digest does not match calculated digest: {} != {}",
                        provided_digest, digest
                    );
                    return Err(RegistryError::ManifestInvalid(Some(
                        "Provided digest does not match calculated digest".to_string(),
                    )));
                }
                let link = LinkReference::Digest(digest.clone());
                self.storage.create_link(namespace, &link, &digest).await?;
            }
        }

        if let Some(subject) = &manifest_digests.subject {
            let link = LinkReference::Referrer(subject.clone(), digest.clone());
            self.storage.create_link(namespace, &link, &digest).await?;
        }

        if let Some(config_digest) = manifest_digests.config {
            let link = LinkReference::Layer(config_digest.clone());
            self.storage.create_link(namespace, &link, &digest).await?;
        }

        for layer_digest in manifest_digests.layers {
            let link = LinkReference::Layer(layer_digest.clone());
            self.storage.create_link(namespace, &link, &digest).await?;
        }

        Ok(NewManifest {
            digest,
            subject: manifest_digests.subject,
        })
    }

    #[instrument]
    pub async fn delete_manifest(
        &self,
        namespace: &str,
        reference: Reference,
    ) -> Result<(), RegistryError> {
        self.validate_namespace(namespace)?;

        let link = match &reference {
            Reference::Tag(tag) => LinkReference::Tag(tag.clone()),
            Reference::Digest(digest) => LinkReference::Digest(digest.clone()),
        };

        let digest = self.storage.read_link(namespace, &link).await?;
        let content = self.storage.read_blob(&digest).await?;
        let manifest_digests = parse_manifest_digests(&content, None)?;

        if let Some(subject_digest) = manifest_digests.subject {
            let link = LinkReference::Referrer(subject_digest.clone(), digest.clone());
            self.storage.delete_link(namespace, &link).await?;
        }

        if let Some(digest) = manifest_digests.config {
            let link = LinkReference::Layer(digest.clone());
            self.storage.delete_link(namespace, &link).await?;
        }

        for digest in manifest_digests.layers {
            let link = LinkReference::Layer(digest.clone());
            self.storage.delete_link(namespace, &link).await?;
        }

        match reference {
            Reference::Tag(tag) => {
                let link = LinkReference::Tag(tag);

                self.storage.delete_link(namespace, &link).await?;
                self.storage
                    .delete_link(namespace, &LinkReference::Digest(digest))
                    .await?;
            }
            Reference::Digest(digest) => {
                let (tags, _) = self.storage.list_tags(namespace, None).await?;
                for tag in tags {
                    let link_reference = LinkReference::Tag(tag.clone());

                    if self.storage.read_link(namespace, &link_reference).await? == digest {
                        self.storage.delete_link(namespace, &link_reference).await?;
                    }
                }

                let link = LinkReference::Digest(digest.clone());
                self.storage.delete_link(namespace, &link).await?;
            }
        }

        Ok(())
    }
}
