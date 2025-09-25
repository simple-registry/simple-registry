use crate::registry::metadata_store::link_kind::LinkKind;
use crate::registry::oci::{Digest, Manifest, Reference};
use crate::registry::server::response_ext::{IntoAsyncRead, ResponseExt};
use crate::registry::{Error, Registry, Repository, ResponseBody};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use hyper::{Method, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{error, instrument, warn};

pub const OCI_SUBJECT: &str = "OCI-Subject";
pub const DOCKER_CONTENT_DIGEST: &str = "Docker-Content-Digest";

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

impl Registry {
    #[instrument(skip(repository))]
    pub async fn head_manifest(
        &self,
        repository: &Repository,
        accepted_mime_types: &[String],
        namespace: &str,
        reference: Reference,
    ) -> Result<HeadManifestResponse, Error> {
        let local_manifest = self.head_local_manifest(namespace, &reference).await;

        if let Ok(response) = local_manifest {
            return Ok(response);
        } else if !repository.is_pull_through() {
            error!("Failed to head local manifest: {namespace}:{reference}");
            return Err(Error::ManifestUnknown);
        }

        let res = repository
            .query_manifest(&Method::HEAD, accepted_mime_types, namespace, &reference)
            .await?;

        let media_type = res.get_header(CONTENT_TYPE);
        let digest = res.parse_header(DOCKER_CONTENT_DIGEST)?;
        let size = res.parse_header(CONTENT_LENGTH)?;

        // Store locally before returning
        let _ = self
            .get_manifest(repository, accepted_mime_types, namespace, reference)
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
        reference: &Reference,
    ) -> Result<HeadManifestResponse, Error> {
        let blob_link = reference.clone().into();
        let link = self
            .metadata_store
            .read_link(namespace, &blob_link, self.update_pull_time)
            .await?;

        let mut reader = self
            .blob_store
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
            .query_manifest(&Method::GET, accepted_mime_types, namespace, &reference)
            .await?;

        let media_type = res.get_header(CONTENT_TYPE);
        let digest = res.parse_header(DOCKER_CONTENT_DIGEST)?;

        let mut content = Vec::new();
        res.into_async_read().read_to_end(&mut content).await?;

        self.put_manifest(namespace, &reference, media_type.as_ref(), &content)
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
        let link = self
            .metadata_store
            .read_link(namespace, &blob_link, self.update_pull_time)
            .await?;

        let content = self.blob_store.read_blob(&link.target).await?;
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
        reference: &Reference,
        content_type: Option<&String>,
        body: &[u8],
    ) -> Result<PutManifestResponse, Error> {
        let manifest_digests = parse_manifest_digests(body, content_type)?;

        let digest = match reference {
            Reference::Tag(tag) => {
                let digest = self.blob_store.create_blob(body).await?;

                let link = LinkKind::Tag(tag.clone());
                self.metadata_store
                    .create_link(namespace, &link, &digest)
                    .await?;

                let link = LinkKind::Digest(digest.clone());
                self.metadata_store
                    .create_link(namespace, &link, &digest)
                    .await?;

                digest
            }
            Reference::Digest(provided_digest) => {
                let digest = self.blob_store.create_blob(body).await?;

                if *provided_digest != digest {
                    warn!("Provided digest does not match calculated digest: {provided_digest} != {digest}");
                    return Err(Error::ManifestInvalid(
                        "Provided digest does not match calculated digest".to_string(),
                    ));
                }

                let link = LinkKind::Digest(digest.clone());
                self.metadata_store
                    .create_link(namespace, &link, &digest)
                    .await?;

                digest
            }
        };

        if let Some(subject) = &manifest_digests.subject {
            let link = LinkKind::Referrer(subject.clone(), digest.clone());
            self.metadata_store
                .create_link(namespace, &link, &digest)
                .await?;
        }

        if let Some(config_digest) = manifest_digests.config {
            let link = LinkKind::Config(config_digest.clone());
            self.metadata_store
                .create_link(namespace, &link, &config_digest)
                .await?;
        }

        for layer_digest in manifest_digests.layers {
            let link = LinkKind::Layer(layer_digest.clone());
            self.metadata_store
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
        reference: &Reference,
    ) -> Result<(), Error> {
        match reference {
            Reference::Tag(tag) => {
                let link = LinkKind::Tag(tag.clone());
                self.metadata_store.delete_link(namespace, &link).await?;
            }
            Reference::Digest(digest) => {
                let mut marker = None;
                loop {
                    let (tags, next_marker) = self
                        .metadata_store
                        .list_tags(namespace, 100, marker)
                        .await?;

                    for tag in tags {
                        let link_reference = LinkKind::Tag(tag);
                        let link = match self
                            .metadata_store
                            .read_link(namespace, &link_reference, self.update_pull_time)
                            .await
                        {
                            Ok(link) => link,
                            Err(crate::registry::metadata_store::Error::ReferenceNotFound) => {
                                // Tag doesn't exist, skip it
                                continue;
                            }
                            Err(e) => return Err(e.into()),
                        };

                        if link.target == *digest {
                            self.metadata_store
                                .delete_link(namespace, &link_reference)
                                .await?;
                        }
                    }

                    // Try to read the manifest by digest to check for referrers
                    let blob_link = LinkKind::Digest(digest.clone());
                    let link = match self
                        .metadata_store
                        .read_link(namespace, &blob_link, self.update_pull_time)
                        .await
                    {
                        Ok(link) => link,
                        Err(crate::registry::metadata_store::Error::ReferenceNotFound) => {
                            // Manifest doesn't exist, but still try to delete the link
                            // (delete_link is idempotent and returns Ok if not found)
                            self.metadata_store
                                .delete_link(namespace, &blob_link)
                                .await?;
                            break;
                        }
                        Err(e) => return Err(e.into()),
                    };

                    let content = self.blob_store.read_blob(&link.target).await?;
                    let manifest_digests = parse_manifest_digests(&content, None)?;

                    if let Some(subject_digest) = manifest_digests.subject {
                        let link = LinkKind::Referrer(subject_digest, link.target);
                        self.metadata_store.delete_link(namespace, &link).await?;
                    }

                    self.metadata_store
                        .delete_link(namespace, &blob_link)
                        .await?;

                    if next_marker.is_none() {
                        break;
                    }

                    marker = next_marker;
                }
            }
        }

        Ok(())
    }

    // API Handlers
    #[instrument(skip(self))]
    pub async fn handle_head_manifest(
        &self,
        namespace: &str,
        reference: Reference,
        mime_types: &[String],
    ) -> Result<Response<ResponseBody>, Error> {
        let repository = self.get_repository_for_namespace(namespace)?;

        let manifest = self
            .head_manifest(repository, mime_types, namespace, reference)
            .await?;

        let res = if let Some(media_type) = manifest.media_type {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, media_type)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .header(CONTENT_LENGTH, manifest.size)
                .body(ResponseBody::empty())?
        } else {
            Response::builder()
                .status(StatusCode::OK)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .header(CONTENT_LENGTH, manifest.size)
                .body(ResponseBody::empty())?
        };

        Ok(res)
    }

    #[instrument(skip(self))]
    pub async fn handle_get_manifest(
        &self,
        namespace: &str,
        reference: Reference,
        mime_types: &[String],
    ) -> Result<Response<ResponseBody>, Error> {
        let repository = self.get_repository_for_namespace(namespace)?;

        let manifest = self
            .get_manifest(repository, mime_types, namespace, reference)
            .await?;

        let res = if let Some(content_type) = manifest.media_type {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, content_type)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .body(ResponseBody::fixed(manifest.content))?
        } else {
            Response::builder()
                .status(StatusCode::OK)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .body(ResponseBody::fixed(manifest.content))?
        };

        Ok(res)
    }

    #[instrument(skip(self, body_stream))]
    pub async fn handle_put_manifest<S>(
        &self,
        namespace: &str,
        reference: Reference,
        mime_type: String,
        mut body_stream: S,
    ) -> Result<Response<ResponseBody>, Error>
    where
        S: AsyncRead + Unpin + Send,
    {
        let mut request_body = String::new();

        body_stream
            .read_to_string(&mut request_body)
            .await
            .map_err(|_| {
                Error::ManifestInvalid("Unable to retrieve manifest from client query".to_string())
            })?;
        let request_body = request_body.into_bytes();

        let location = format!("/v2/{namespace}/manifests/{reference}");

        let manifest = self
            .put_manifest(namespace, &reference, Some(&mime_type), &request_body)
            .await?;

        let res = match manifest.subject {
            Some(subject) => Response::builder()
                .status(StatusCode::CREATED)
                .header(LOCATION, location)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .header(OCI_SUBJECT, subject.to_string())
                .body(ResponseBody::empty())?,
            None => Response::builder()
                .status(StatusCode::CREATED)
                .header(LOCATION, location)
                .header(DOCKER_CONTENT_DIGEST, manifest.digest.to_string())
                .body(ResponseBody::empty())?,
        };

        Ok(res)
    }

    #[instrument(skip(self))]
    pub async fn handle_delete_manifest(
        &self,
        namespace: &str,
        reference: Reference,
    ) -> Result<Response<ResponseBody>, Error> {
        self.delete_manifest(namespace, &reference).await?;

        let res = Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(ResponseBody::empty())?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::server::response_ext::IntoAsyncRead;
    use crate::registry::tests::{FSRegistryTestCase, S3RegistryTestCase};
    use serde_json::json;
    use std::io::Cursor;
    use std::slice;
    use tokio::io::AsyncReadExt;

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

    async fn test_put_manifest_impl(registry: &Registry) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Test put manifest with tag
        let response = registry
            .put_manifest(
                namespace,
                &Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        // Verify manifest was stored
        let stored_manifest = registry
            .get_manifest(
                registry.get_repository_for_namespace(namespace).unwrap(),
                slice::from_ref(&media_type),
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
                &Reference::Digest(digest.clone()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        assert_eq!(response.digest, digest);
    }

    #[tokio::test]
    async fn test_put_manifest_fs() {
        let t = FSRegistryTestCase::new();
        test_put_manifest_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_put_manifest_s3() {
        let t = S3RegistryTestCase::new();
        test_put_manifest_impl(t.registry()).await;
    }

    async fn test_get_manifest_impl(registry: &Registry) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let response = registry
            .put_manifest(
                namespace,
                &Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        // Test get manifest by tag
        let manifest = registry
            .get_manifest(
                registry.get_repository_for_namespace(namespace).unwrap(),
                slice::from_ref(&media_type),
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
                registry.get_repository_for_namespace(namespace).unwrap(),
                slice::from_ref(&media_type),
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
        let t = FSRegistryTestCase::new();
        test_get_manifest_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_get_manifest_s3() {
        let t = S3RegistryTestCase::new();
        test_get_manifest_impl(t.registry()).await;
    }

    async fn test_head_manifest_impl(registry: &Registry) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let response = registry
            .put_manifest(
                namespace,
                &Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        // Test head manifest by tag
        let manifest = registry
            .head_manifest(
                registry.get_repository_for_namespace(namespace).unwrap(),
                slice::from_ref(&media_type),
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
                registry.get_repository_for_namespace(namespace).unwrap(),
                slice::from_ref(&media_type),
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
        let t = FSRegistryTestCase::new();
        test_head_manifest_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_head_manifest_s3() {
        let t = S3RegistryTestCase::new();
        test_head_manifest_impl(t.registry()).await;
    }

    async fn test_delete_manifest_impl(registry: &Registry) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let response = registry
            .put_manifest(
                namespace,
                &Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        // Test delete manifest by tag
        registry
            .delete_manifest(namespace, &Reference::Tag(tag.to_string()))
            .await
            .unwrap();

        // Verify tag is deleted
        assert!(registry
            .get_manifest(
                registry.get_repository_for_namespace(namespace).unwrap(),
                slice::from_ref(&media_type),
                namespace,
                Reference::Tag(tag.to_string()),
            )
            .await
            .is_err());

        // Test delete manifest by digest
        registry
            .delete_manifest(namespace, &Reference::Digest(response.digest.clone()))
            .await
            .unwrap();

        // Verify digest is deleted
        assert!(registry
            .get_manifest(
                registry.get_repository_for_namespace(namespace).unwrap(),
                slice::from_ref(&media_type),
                namespace,
                Reference::Digest(response.digest),
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_delete_manifest_fs() {
        let t = FSRegistryTestCase::new();
        test_delete_manifest_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_delete_manifest_s3() {
        let t = S3RegistryTestCase::new();
        test_delete_manifest_impl(t.registry()).await;
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

    // API Handler Tests
    async fn test_handle_head_manifest_impl(registry: &Registry) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let put_response = registry
            .put_manifest(
                namespace,
                &Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        let mime_types = Vec::new();

        let reference = Reference::Tag(tag.to_string());

        let response = registry
            .handle_head_manifest(namespace, reference, &mime_types)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.get_header(DOCKER_CONTENT_DIGEST),
            Some(put_response.digest.to_string())
        );
        assert_eq!(
            response.get_header(CONTENT_LENGTH),
            Some(content.len().to_string())
        );
        assert_eq!(response.get_header(CONTENT_TYPE), Some(media_type));
    }

    #[tokio::test]
    async fn test_handle_head_manifest_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_head_manifest_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_head_manifest_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_head_manifest_impl(t.registry()).await;
    }

    async fn test_handle_get_manifest_impl(registry: &Registry) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let put_response = registry
            .put_manifest(
                namespace,
                &Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        let reference = Reference::Tag(tag.to_string());
        let accepted_mime_types = Vec::new();

        let response = registry
            .handle_get_manifest(namespace, reference, &accepted_mime_types)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.get_header(DOCKER_CONTENT_DIGEST),
            Some(put_response.digest.to_string())
        );
        assert_eq!(response.get_header(CONTENT_TYPE), Some(media_type));

        // Read response body
        let mut reader = response.into_async_read();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, content);
    }

    #[tokio::test]
    async fn test_handle_get_manifest_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_get_manifest_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_get_manifest_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_get_manifest_impl(t.registry()).await;
    }

    async fn test_handle_put_manifest_impl(registry: &Registry) -> Result<(), Error> {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        let reference = Reference::Tag(tag.to_string());

        let manifest_stream = Cursor::new(content.clone());

        let response = registry
            .handle_put_manifest(namespace, reference, media_type.clone(), manifest_stream)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let digest = response.get_header(DOCKER_CONTENT_DIGEST).unwrap();

        assert_eq!(
            response.get_header(LOCATION),
            Some(format!("/v2/{namespace}/manifests/{tag}"))
        );

        // Verify manifest was stored
        let stored_manifest = registry
            .get_manifest(
                registry.get_repository_for_namespace(namespace).unwrap(),
                slice::from_ref(&media_type),
                namespace,
                Reference::Tag(tag.to_string()),
            )
            .await
            .unwrap();

        assert_eq!(stored_manifest.content, content);
        assert_eq!(stored_manifest.media_type.unwrap(), media_type);
        assert_eq!(stored_manifest.digest.to_string(), digest);

        Ok(())
    }

    #[tokio::test]
    async fn test_handle_put_manifest_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_put_manifest_impl(t.registry()).await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_put_manifest_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_put_manifest_impl(t.registry()).await.unwrap();
    }

    async fn test_handle_delete_manifest_impl(registry: &Registry) {
        let namespace = "test-repo";
        let tag = "latest";
        let (content, media_type) = create_test_manifest();

        // Put manifest first
        let _put_response = registry
            .put_manifest(
                namespace,
                &Reference::Tag(tag.to_string()),
                Some(&media_type),
                &content,
            )
            .await
            .unwrap();

        let reference = Reference::Tag(tag.to_string());

        let response = registry
            .handle_delete_manifest(namespace, reference)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        // Verify manifest is deleted
        assert!(registry
            .get_manifest(
                registry.get_repository_for_namespace(namespace).unwrap(),
                slice::from_ref(&media_type),
                namespace,
                Reference::Tag(tag.to_string()),
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_handle_delete_manifest_fs() {
        let t = FSRegistryTestCase::new();
        test_handle_delete_manifest_impl(t.registry()).await;
    }

    #[tokio::test]
    async fn test_handle_delete_manifest_s3() {
        let t = S3RegistryTestCase::new();
        test_handle_delete_manifest_impl(t.registry()).await;
    }
}
