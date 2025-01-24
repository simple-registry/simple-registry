use crate::oci::{Digest, Manifest, Reference};
use crate::registry::utils::DataLink;
use crate::registry::{Error, Registry};
use futures_util::StreamExt;
use http_body_util::BodyExt;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::Method;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, instrument, warn};

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
        Error::ManifestInvalid("Failed to deserialize manifest".to_string())
    })?;

    if content_type.is_some()
        && manifest.media_type.is_some()
        && manifest.media_type.as_ref() != content_type
    {
        warn!(
            "Manifest media type mismatch: {:?} (expected) != {:?} (found)",
            content_type, manifest.media_type
        );
        return Err(Error::ManifestInvalid(
            "Expected manifest media type mismatch".to_string(),
        ));
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
        accepted_mime_types: &[String],
        namespace: &str,
        reference: Reference,
    ) -> Result<HeadManifestResponse, Error> {
        let (repository_name, repository) = self.validate_namespace(namespace)?;

        if repository.is_pull_through() {
            if let Ok(response) = self.head_local_manifest(namespace, reference.clone()).await {
                return Ok(response);
            }

            let res = repository
                .query_upstream_manifest(
                    &Method::HEAD,
                    accepted_mime_types,
                    repository_name,
                    namespace,
                    &reference,
                )
                .await?;

            let media_type = Self::get_header(&res, CONTENT_TYPE);
            let digest = Self::parse_header(&res, "docker-content-digest")?;
            let size = Self::parse_header(&res, CONTENT_LENGTH)?;

            // Store locally before returning
            let _ = self
                .get_manifest(accepted_mime_types, namespace, reference.clone())
                .await?;

            return Ok(HeadManifestResponse {
                media_type,
                digest,
                size,
            });
        }

        self.head_local_manifest(namespace, reference).await
    }

    async fn head_local_manifest(
        &self,
        namespace: &str,
        reference: Reference,
    ) -> Result<HeadManifestResponse, Error> {
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
        accepted_mime_types: &[String],
        namespace: &str,
        reference: Reference,
    ) -> Result<GetManifestResponse, Error> {
        let (repository_name, repository) = self.validate_namespace(namespace)?;

        if repository.is_pull_through() {
            if let Ok(response) = self.get_local_manifest(namespace, reference.clone()).await {
                return Ok(response);
            }

            let res = repository
                .query_upstream_manifest(
                    &Method::GET,
                    accepted_mime_types,
                    repository_name,
                    namespace,
                    &reference,
                )
                .await?;

            let media_type = Self::get_header(&res, CONTENT_TYPE);
            let digest = Self::parse_header(&res, "docker-content-digest")?;

            let mut content = Vec::new();
            let mut body = res.into_data_stream();
            while let Some(frame) = body.next().await {
                let frame = frame.map_err(|e| {
                    error!("Data stream error: {}", e);
                    Error::Internal("Data stream error".to_string())
                })?;
                content.extend_from_slice(&frame);
            }

            // NOTE: a side effect of storing the manifest locally at this stage is that blobs indexes
            // are also created locally even though the blob itself may not yet be available locally.
            // This behavior is specific to pull-through repositories.
            self.put_manifest(namespace, reference.clone(), media_type.as_ref(), &content)
                .await?;

            let link = reference.into();
            self.storage_engine
                .update_last_pulled(namespace, &link)
                .await?;

            return Ok(GetManifestResponse {
                media_type,
                digest,
                content,
            });
        }

        self.get_local_manifest(namespace, reference).await
    }

    async fn get_local_manifest(
        &self,
        namespace: &str,
        reference: Reference,
    ) -> Result<GetManifestResponse, Error> {
        let link = reference.into();
        let digest = self.storage_engine.read_link(namespace, &link).await?;
        self.storage_engine
            .update_last_pulled(namespace, &link)
            .await?;

        let content = self.storage_engine.read_blob(&digest).await?;
        let manifest = serde_json::from_slice::<Manifest>(&content).map_err(|e| {
            debug!("Failed to deserialize manifest: {}", e);
            Error::ManifestInvalid("Failed to deserialize manifest".to_string())
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
        content_type: Option<&String>,
        body: &[u8],
    ) -> Result<PutManifestResponse, Error> {
        self.validate_namespace(namespace)?;

        let manifest_digests = parse_manifest_digests(body, content_type)?;

        let digest = match reference {
            Reference::Tag(tag) => {
                let digest = self.storage_engine.create_blob(body).await?;

                let link = DataLink::Tag(tag);
                self.storage_engine
                    .create_link(namespace, &link, &digest)
                    .await?;
                let link = DataLink::Digest(digest.clone());
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
                    return Err(Error::ManifestInvalid(
                        "Provided digest does not match calculated digest".to_string(),
                    ));
                }
                let link = DataLink::Digest(digest.clone());
                self.storage_engine
                    .create_link(namespace, &link, &digest)
                    .await?;

                digest
            }
        };

        if let Some(subject) = &manifest_digests.subject {
            let link = DataLink::Referrer(subject.clone(), digest.clone());
            self.storage_engine
                .create_link(namespace, &link, &digest)
                .await?;
        }

        if let Some(config_digest) = manifest_digests.config {
            let link = DataLink::Config(config_digest.clone());
            self.storage_engine
                .create_link(namespace, &link, &config_digest)
                .await?;
        }

        for layer_digest in manifest_digests.layers {
            let link = DataLink::Layer(layer_digest.clone());
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
                let link = DataLink::Tag(tag);
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
                        let link_reference = DataLink::Tag(tag);
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

                    let link = DataLink::Digest(digest.clone());

                    let digest = self.storage_engine.read_link(namespace, &link).await?;
                    let content = self.storage_engine.read_blob(&digest).await?;
                    let manifest_digests = parse_manifest_digests(&content, None)?;

                    if let Some(subject_digest) = manifest_digests.subject {
                        let link = DataLink::Referrer(subject_digest, digest);
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
