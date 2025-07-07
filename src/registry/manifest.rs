use crate::registry::api::hyper::response_ext::{IntoAsyncRead, ResponseExt};
use crate::registry::api::hyper::DOCKER_CONTENT_DIGEST;
use crate::registry::data_store::DataStore;
use crate::registry::oci_types::{Digest, Manifest, Reference};
use crate::registry::utils::BlobLink;
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
        let local_manifest = self.head_local_manifest(namespace, reference.clone()).await;

        if let Ok(response) = local_manifest {
            return Ok(response);
        } else if !repository.is_pull_through() {
            error!("Failed to head local manifest: {namespace}:{reference}");
            return Err(Error::ManifestUnknown);
        }

        let res = repository
            .query_upstream_manifest(
                &self.auth_token_cache,
                &Method::HEAD,
                accepted_mime_types,
                namespace,
                &reference,
            )
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

        Ok(HeadManifestResponse {
            media_type,
            digest,
            size,
        })
    }

    async fn head_local_manifest(
        &self,
        namespace: &str,
        reference: Reference,
    ) -> Result<HeadManifestResponse, Error> {
        let blob_link = reference.into();
        let link = self.read_link(namespace, &blob_link).await?;

        let mut reader = self
            .store
            .build_blob_reader(&link.target, None)
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
            digest: link.target,
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
        let local_manifest = self.get_local_manifest(namespace, &reference).await;

        if let Ok(response) = local_manifest {
            return Ok(response);
        } else if !repository.is_pull_through() {
            error!("Failed to get local manifest: {namespace}:{reference}");
            return Err(Error::ManifestUnknown);
        }

        // TODO: test if upstream manifest has changed or not (if reference is a Reference::Tag)
        let res = repository
            .query_upstream_manifest(
                &self.auth_token_cache,
                &Method::GET,
                accepted_mime_types,
                namespace,
                &reference,
            )
            .await?;

        let media_type = res.get_header(CONTENT_TYPE);
        let digest = res.parse_header(DOCKER_CONTENT_DIGEST)?;

        let mut content = Vec::new();
        res.into_async_read().read_to_end(&mut content).await?;

        self.put_manifest(namespace, reference.clone(), media_type.as_ref(), &content)
            .await?;

        Ok(GetManifestResponse {
            media_type,
            digest,
            content,
        })
    }

    async fn get_local_manifest(
        &self,
        namespace: &str,
        reference: &Reference,
    ) -> Result<GetManifestResponse, Error> {
        let blob_link = reference.clone().into();
        let link = self.read_link(namespace, &blob_link).await?;

        let content = self.store.read_blob(&link.target).await?;
        let manifest = serde_json::from_slice::<Manifest>(&content).map_err(|error| {
            warn!("Failed to deserialize manifest: {error}");
            Error::ManifestInvalid("Failed to deserialize manifest".to_string())
        })?;

        Ok(GetManifestResponse {
            media_type: manifest.media_type,
            digest: link.target,
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
                let digest = self.store.create_blob(body).await?;

                let link = BlobLink::Tag(tag);
                self.create_link(namespace, &link, &digest).await?;

                let link = BlobLink::Digest(digest.clone());
                self.create_link(namespace, &link, &digest).await?;

                digest
            }
            Reference::Digest(provided_digest) => {
                let digest = self.store.create_blob(body).await?;

                if provided_digest != digest {
                    warn!("Provided digest does not match calculated digest: {provided_digest} != {digest}");
                    return Err(Error::ManifestInvalid(
                        "Provided digest does not match calculated digest".to_string(),
                    ));
                }

                let link = BlobLink::Digest(digest.clone());
                self.create_link(namespace, &link, &digest).await?;

                digest
            }
        };

        if let Some(subject) = &manifest_digests.subject {
            let link = BlobLink::Referrer(subject.clone(), digest.clone());
            self.create_link(namespace, &link, &digest).await?;
        }

        if let Some(config_digest) = manifest_digests.config {
            let link = BlobLink::Config(config_digest.clone());
            self.create_link(namespace, &link, &config_digest).await?;
        }

        for layer_digest in manifest_digests.layers {
            let link = BlobLink::Layer(layer_digest.clone());
            self.create_link(namespace, &link, &layer_digest).await?;
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
                let link = BlobLink::Tag(tag);
                self.delete_link(namespace, &link).await?;
            }
            Reference::Digest(digest) => {
                let mut marker = None;
                loop {
                    let (tags, next_marker) = self.store.list_tags(namespace, 100, marker).await?;

                    for tag in tags {
                        let link_reference = BlobLink::Tag(tag);
                        let link = self.read_link(namespace, &link_reference).await?;

                        if link.target == digest {
                            self.delete_link(namespace, &link_reference).await?;
                        }
                    }

                    let blob_link = BlobLink::Digest(digest.clone());
                    let link = self.read_link(namespace, &blob_link).await?;

                    let content = self.store.read_blob(&link.target).await?;
                    let manifest_digests = parse_manifest_digests(&content, None)?;

                    if let Some(subject_digest) = manifest_digests.subject {
                        let link = BlobLink::Referrer(subject_digest, link.target);
                        self.delete_link(namespace, &link).await?;
                    }

                    self.delete_link(namespace, &blob_link).await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::test_utils::{create_test_fs_backend, create_test_s3_backend};
    use serde_json::json;

    fn create_test_manifest() -> (Vec<u8>, String) {
        let manifest = json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "size": 1234
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    "size": 5678
                }
            ]
        });

        let content = serde_json::to_vec(&manifest).unwrap();
        let media_type = "application/vnd.docker.distribution.manifest.v2+json".to_string();
        (content, media_type)
    }

    fn create_test_manifest_with_subject() -> (Vec<u8>, String) {
        let manifest = json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "subject": {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "digest": "sha256:9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
                "size": 1234
            },
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "size": 1234
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    "size": 5678
                }
            ]
        });

        let content = serde_json::to_vec(&manifest).unwrap();
        let media_type = "application/vnd.docker.distribution.manifest.v2+json".to_string();
        (content, media_type)
    }

    async fn test_put_manifest_impl<D: DataStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Test put manifest with tag
        let response = registry
            .put_manifest(
                namespace,
                Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        // Verify manifest was stored
        let stored_manifest = registry
            .get_manifest(
                registry.validate_namespace(namespace).unwrap(),
                &[media_type.clone()],
                namespace,
                Reference::Tag(tag.to_string()),
            )
            .await
            .unwrap();

        assert_eq!(stored_manifest.content, content);
        assert_eq!(stored_manifest.media_type.unwrap(), media_type);
        assert_eq!(stored_manifest.digest, response.digest);

        // Test put manifest with digest
        let digest = response.digest.clone();
        let response = registry
            .put_manifest(
                namespace,
                Reference::Digest(digest.clone()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        assert_eq!(response.digest, digest);
    }

    #[tokio::test]
    async fn test_put_manifest_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_put_manifest_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_put_manifest_s3() {
        let registry = create_test_s3_backend().await;
        test_put_manifest_impl(&registry).await;
    }

    async fn test_get_manifest_impl<D: DataStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let response = registry
            .put_manifest(
                namespace,
                Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        // Test get manifest by tag
        let manifest = registry
            .get_manifest(
                registry.validate_namespace(namespace).unwrap(),
                &[media_type.clone()],
                namespace,
                Reference::Tag(tag.to_string()),
            )
            .await
            .unwrap();

        assert_eq!(manifest.content, content);
        assert_eq!(manifest.media_type.unwrap(), media_type);
        assert_eq!(manifest.digest, response.digest);

        // Test get manifest by digest
        let manifest = registry
            .get_manifest(
                registry.validate_namespace(namespace).unwrap(),
                &[media_type.clone()],
                namespace,
                Reference::Digest(response.digest.clone()),
            )
            .await
            .unwrap();

        assert_eq!(manifest.content, content);
        assert_eq!(manifest.media_type.unwrap(), media_type);
        assert_eq!(manifest.digest, response.digest);
    }

    #[tokio::test]
    async fn test_get_manifest_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_get_manifest_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_get_manifest_s3() {
        let registry = create_test_s3_backend().await;
        test_get_manifest_impl(&registry).await;
    }

    async fn test_head_manifest_impl<D: DataStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let response = registry
            .put_manifest(
                namespace,
                Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        // Test head manifest by tag
        let manifest = registry
            .head_manifest(
                registry.validate_namespace(namespace).unwrap(),
                &[media_type.clone()],
                namespace,
                Reference::Tag(tag.to_string()),
            )
            .await
            .unwrap();

        assert_eq!(manifest.media_type.unwrap(), media_type);
        assert_eq!(manifest.digest, response.digest);
        assert_eq!(manifest.size, content.len());

        // Test head manifest by digest
        let manifest = registry
            .head_manifest(
                registry.validate_namespace(namespace).unwrap(),
                &[media_type.clone()],
                namespace,
                Reference::Digest(response.digest.clone()),
            )
            .await
            .unwrap();

        assert_eq!(manifest.media_type.unwrap(), media_type);
        assert_eq!(manifest.digest, response.digest);
        assert_eq!(manifest.size, content.len());
    }

    #[tokio::test]
    async fn test_head_manifest_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_head_manifest_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_head_manifest_s3() {
        let registry = create_test_s3_backend().await;
        test_head_manifest_impl(&registry).await;
    }

    async fn test_delete_manifest_impl<D: DataStore + 'static>(registry: &Registry<D>) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let response = registry
            .put_manifest(
                namespace,
                Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        // Test delete manifest by tag
        registry
            .delete_manifest(namespace, Reference::Tag(tag.to_string()))
            .await
            .unwrap();

        // Verify tag is deleted
        assert!(registry
            .get_manifest(
                registry.validate_namespace(namespace).unwrap(),
                &[media_type.clone()],
                namespace,
                Reference::Tag(tag.to_string()),
            )
            .await
            .is_err());

        // Test delete manifest by digest
        registry
            .delete_manifest(namespace, Reference::Digest(response.digest.clone()))
            .await
            .unwrap();

        // Verify digest is deleted
        assert!(registry
            .get_manifest(
                registry.validate_namespace(namespace).unwrap(),
                &[media_type.clone()],
                namespace,
                Reference::Digest(response.digest),
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_delete_manifest_fs() {
        let (registry, _temp_dir) = create_test_fs_backend().await;
        test_delete_manifest_impl(&registry).await;
    }

    #[tokio::test]
    async fn test_delete_manifest_s3() {
        let registry = create_test_s3_backend().await;
        test_delete_manifest_impl(&registry).await;
    }

    #[test]
    fn test_parse_manifest_digests() {
        // Test regular manifest
        let (content, media_type) = create_test_manifest();
        let digests = parse_manifest_digests(&content, Some(&media_type)).unwrap();

        assert!(digests.subject.is_none());
        assert_eq!(
            digests.config.unwrap().to_string(),
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert_eq!(
            digests.layers[0].to_string(),
            "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );

        // Test manifest with subject
        let (content, media_type) = create_test_manifest_with_subject();
        let digests = parse_manifest_digests(&content, Some(&media_type)).unwrap();

        assert_eq!(
            digests.subject.unwrap().to_string(),
            "sha256:9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"
        );
        assert_eq!(
            digests.config.unwrap().to_string(),
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert_eq!(
            digests.layers[0].to_string(),
            "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );

        // Test media type mismatch
        let wrong_media_type = "application/wrong.media.type".to_string();
        assert!(parse_manifest_digests(&content, Some(&wrong_media_type)).is_err());
    }
}
