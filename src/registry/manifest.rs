use crate::registry::api::hyper::response_ext::{IntoAsyncRead, ResponseExt};
use crate::registry::api::hyper::DOCKER_CONTENT_DIGEST;
use crate::registry::data_store::DataStore;
use crate::registry::oci_types::{Digest, Manifest, Reference};
use crate::registry::utils::DataLink;
use crate::registry::{Error, Registry, Repository};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::Method;
use tokio::io::AsyncReadExt;
use tracing::{error, instrument, warn};

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
    let manifest: Manifest = serde_json::from_slice(body).unwrap_or_default();

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

impl<D: DataStore> Registry<D> {
    #[instrument(skip(repository))]
    pub async fn head_manifest(
        &self,
        repository: &Repository,
        accepted_mime_types: &[String],
        namespace: &str,
        reference: Reference,
    ) -> Result<HeadManifestResponse, Error> {
        if repository.is_pull_through() {
            if let Ok(response) = self.head_local_manifest(namespace, reference.clone()).await {
                return Ok(response);
            }

            let res = repository
                .query_upstream_manifest(&Method::HEAD, accepted_mime_types, namespace, &reference)
                .await?;

            let media_type = res.get_header(CONTENT_TYPE);
            let digest = res.parse_header(DOCKER_CONTENT_DIGEST)?;
            let size = res.parse_header(CONTENT_LENGTH)?;

            // Store locally before returning
            let _ = self
                .get_manifest(
                    repository,
                    accepted_mime_types,
                    namespace,
                    reference.clone(),
                )
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
        let tag = match link {
            DataLink::Tag(tag) => Some(tag),
            _ => None,
        };

        self.storage_engine
            .update_last_pulled(namespace, tag, &digest)
            .await?;

        let mut reader = self
            .storage_engine
            .build_blob_reader(&digest, None)
            .await
            .map_err(|error| {
                error!("Failed to build blob reader: {error}");
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

    #[instrument(skip(repository))]
    pub async fn get_manifest(
        &self,
        repository: &Repository,
        accepted_mime_types: &[String],
        namespace: &str,
        reference: Reference,
    ) -> Result<GetManifestResponse, Error> {
        if repository.is_pull_through() {
            if let Ok(response) = self.get_local_manifest(namespace, reference.clone()).await {
                return Ok(response);
            }

            let res = repository
                .query_upstream_manifest(&Method::GET, accepted_mime_types, namespace, &reference)
                .await?;

            let media_type = res.get_header(CONTENT_TYPE);
            let digest = res.parse_header(DOCKER_CONTENT_DIGEST)?;

            let mut content = Vec::new();
            res.into_async_read().read_to_end(&mut content).await?;

            // NOTE: a side effect of storing the manifest locally at this stage is that blobs indexes
            // are also created locally even though the blob itself may not yet be available locally.
            // This behavior is specific to pull-through repositories.
            self.put_manifest(namespace, reference.clone(), media_type.as_ref(), &content)
                .await?;

            let tag = match reference {
                Reference::Tag(tag) => Some(tag),
                Reference::Digest(_) => None,
            };

            self.storage_engine
                .update_last_pulled(namespace, tag, &digest)
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
            .update_last_pulled(namespace, None, &digest)
            .await?;

        let content = self.storage_engine.read_blob(&digest).await?;
        let manifest = serde_json::from_slice::<Manifest>(&content).map_err(|error| {
            warn!("Failed to deserialize manifest (2): {error}");
            warn!("Manifest content: {:?}", String::from_utf8_lossy(&content));
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
                    warn!("Provided digest does not match calculated digest: {provided_digest} != {digest}");
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
