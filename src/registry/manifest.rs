use log::{debug, error, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::error::RegistryError;
use crate::io_helpers::parse_reader;
use crate::oci::{Digest, Manifest, Reference};
use crate::registry::{LinkReference, Registry};

pub struct ManifestData {
    pub media_type: String,
    pub digest: Digest,
    pub content: Vec<u8>,
}

pub struct ManifestSummary {
    pub media_type: String,
    pub digest: Digest,
    pub size: usize,
}

pub struct NewManifest {
    pub digest: Digest,
    pub subject: Option<Digest>,
}

impl Registry {
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

    pub async fn put_manifest(
        &self,
        namespace: &str,
        reference: Reference,
        content_type: String,
        body: &[u8],
    ) -> Result<NewManifest, RegistryError> {
        self.validate_namespace(namespace)?;

        let manifest: Manifest = serde_json::from_slice(body).map_err(|e| {
            debug!("Failed to deserialize manifest: {}", e);
            RegistryError::ManifestInvalid(Some("Failed to deserialize manifest".to_string()))
        })?;

        if manifest.media_type != content_type {
            warn!(
                "Content-Type header does not match manifest media type: {} != {}",
                content_type, manifest.media_type
            );
            return Err(RegistryError::ManifestInvalid(Some(
                "Content-Type header does not match manifest media type".to_string(),
            )));
        }

        let upload_uuid = Uuid::new_v4();
        self.storage.create_upload(namespace, upload_uuid).await?;

        let mut writer = self
            .storage
            .build_upload_writer(namespace, upload_uuid, None)
            .await?;

        writer.write_all(body).await?;
        writer.flush().await?;

        let manifest_digest = self
            .storage
            .complete_upload(namespace, upload_uuid, None)
            .await?;

        let link_reference = reference.clone().into();
        debug!("link_reference: {:?}", link_reference);

        self.storage
            .create_link(namespace, &link_reference, &manifest_digest)
            .await?;

        if let Reference::Tag(_) = reference {
            let link_reference = LinkReference::Digest(manifest_digest.clone());
            self.storage
                .create_link(namespace, &link_reference, &manifest_digest)
                .await?;
        }

        if let Some(config) = manifest.config {
            let digest = Digest::from_str(&config.digest)?;
            let link_reference = LinkReference::Layer(digest.clone());
            self.storage
                .create_link(namespace, &link_reference, &digest)
                .await?;
        }

        for layer in manifest.layers {
            let digest = Digest::from_str(&layer.digest)?;
            let link_reference = LinkReference::Layer(digest.clone());
            self.storage
                .create_link(namespace, &link_reference, &digest)
                .await?;
        }

        let subject;

        if let Some(subject_descriptor) = manifest.subject {
            let digest = Digest::from_str(&subject_descriptor.digest)?;
            let link_reference = LinkReference::Referrer(digest.clone(), manifest_digest.clone());

            self.storage
                .create_link(namespace, &link_reference, &digest)
                .await?;

            subject = Some(digest);
        } else {
            subject = None;
        }

        Ok(NewManifest {
            digest: manifest_digest,
            subject,
        })
    }

    pub async fn delete_manifest(
        &self,
        namespace: &str,
        reference: Reference,
    ) -> Result<(), RegistryError> {
        self.validate_namespace(namespace)?;

        let digest = self
            .storage
            .read_link(namespace, &reference.clone().into())
            .await?;

        let mut reader = self.storage.build_blob_reader(&digest, None).await?;

        let mut content = Vec::new();
        reader.read_to_end(&mut content).await?;

        debug!("Deserializing manifest");
        let manifest = serde_json::from_slice::<Manifest>(&content).map_err(|e| {
            debug!("Failed to deserialize manifest: {}", e);
            RegistryError::ManifestInvalid(Some("Failed to deserialize manifest".to_string()))
        })?;

        debug!("Deleting links for subject");
        if let Some(subject_descriptor) = manifest.subject {
            let subject_digest = Digest::from_str(&subject_descriptor.digest)?;
            let link_reference = LinkReference::Referrer(subject_digest.clone(), digest.clone());
            self.storage.delete_link(namespace, &link_reference).await?;
        }

        debug!("Deleting links for layers");
        for layer in manifest.layers {
            let digest = Digest::from_str(&layer.digest)?;
            let link_reference = LinkReference::Layer(digest.clone());
            let _ = self.storage.delete_link(namespace, &link_reference).await; // TODO: should NOT be ignored
        }

        debug!("Deleting links for config");
        if let Some(config) = manifest.config {
            let digest = Digest::from_str(&config.digest)?;
            let link_reference = LinkReference::Layer(digest.clone());
            self.storage.delete_link(namespace, &link_reference).await?;
        }

        if let Reference::Tag(_) = reference {
            debug!("Deleting links for manifest");

            let link_reference = LinkReference::Digest(digest.clone());
            self.storage.delete_link(namespace, &link_reference).await?;

            // TODO: if not a tag, manifest deletion must also delete all related tags!
        }

        debug!("Deleting link for reference");
        let link_reference = reference.clone().into();
        self.storage.delete_link(namespace, &link_reference).await?;

        Ok(())
    }
}
