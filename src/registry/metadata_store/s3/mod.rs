#[cfg(test)]
pub mod tests;

use crate::registry::data_store;
use crate::registry::metadata_store::lock::{self, LockBackend, MemoryBackend};
use crate::registry::metadata_store::Error;
use crate::registry::metadata_store::{LinkMetadata, LockConfig, MetadataStore};
use crate::registry::oci_types::{Descriptor, Digest, Manifest};
use crate::registry::utils::{path_builder, BlobMetadata};
use crate::registry::BlobLink;
use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, instrument};

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct BackendConfig {
    pub access_key_id: String,
    pub secret_key: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub key_prefix: String,
    #[serde(default)]
    pub redis: Option<LockConfig>,
}

impl From<BackendConfig> for data_store::s3::BackendConfig {
    fn from(config: BackendConfig) -> Self {
        Self {
            access_key_id: config.access_key_id,
            secret_key: config.secret_key,
            endpoint: config.endpoint,
            bucket: config.bucket,
            region: config.region,
            key_prefix: config.key_prefix,
            ..Default::default()
        }
    }
}

#[derive(Clone)]
pub struct Backend {
    pub store: data_store::s3::Backend,
    lock_store: Arc<dyn LockBackend<Guard = Box<dyn Send>> + Send + Sync>,
}

impl Backend {
    pub fn new(config: BackendConfig) -> Result<Self, crate::configuration::Error> {
        let store = data_store::s3::Backend::new(data_store::s3::BackendConfig {
            access_key_id: config.access_key_id,
            secret_key: config.secret_key,
            endpoint: config.endpoint,
            bucket: config.bucket,
            region: config.region,
            key_prefix: config.key_prefix,
            ..Default::default()
        });

        let lock_store: Arc<dyn LockBackend<Guard = Box<dyn Send>> + Send + Sync> =
            if let Some(redis_config) = config.redis {
                let backend = lock::RedisBackend::new(redis_config).map_err(|e| {
                    crate::configuration::Error::MetadataStore(format!(
                        "Failed to initialize Redis lock store: {e}"
                    ))
                })?;
                Arc::new(backend)
            } else {
                Arc::new(MemoryBackend::new())
            };

        Ok(Self { store, lock_store })
    }
}

#[async_trait]
impl MetadataStore for Backend {
    #[instrument(skip(self))]
    async fn list_namespaces(
        &self,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        debug!("Fetching {n} namespace(s) with continuation token: {last:?}");

        // List all objects under the repository directory
        let repo_dir = path_builder::repository_dir();

        let mut namespaces = Vec::new();
        let mut continuation_token = None;

        // List all objects recursively to find all namespaces
        loop {
            let (objects, next_token) = self
                .store
                .list_objects(&repo_dir, 1000, continuation_token)
                .await?;

            for key in objects {
                // The path is relative to v2/repositories, like:
                // namespace/_manifests/... or
                // namespace/nested/_manifests/...

                // Look for special directories that indicate a namespace
                for marker in &["/_manifests/", "/_layers/", "/_uploads/", "/_config/"] {
                    if let Some(idx) = key.find(marker) {
                        let namespace = key[..idx].to_string();
                        if !namespaces.contains(&namespace) {
                            namespaces.push(namespace);
                        }
                        break; // Found a namespace, no need to check other markers
                    }
                }
            }

            continuation_token = next_token;
            if continuation_token.is_none() {
                break;
            }
        }

        // Sort namespaces for consistent pagination
        namespaces.sort();

        let start_idx = if let Some(last_item) = &last {
            namespaces
                .iter()
                .position(|ns| ns > last_item)
                .unwrap_or(namespaces.len())
        } else {
            0
        };

        let end_idx = std::cmp::min(start_idx + usize::from(n), namespaces.len());
        let result_namespaces = namespaces[start_idx..end_idx].to_vec();

        let next_token = if end_idx < namespaces.len() {
            result_namespaces.last().cloned()
        } else {
            None
        };

        Ok((result_namespaces, next_token))
    }

    #[instrument(skip(self))]
    async fn list_tags(
        &self,
        namespace: &str,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        debug!("Listing {n} tag(s) for namespace '{namespace}' starting with continuation_token '{last:?}'");
        let tags_dir = path_builder::manifest_tags_dir(namespace);

        let mut all_tags = Vec::new();
        let mut continuation_token = None;

        loop {
            let (prefixes, _, next_token) = self
                .store
                .list_prefixes(&tags_dir, "/", 1000, continuation_token)
                .await?;

            for tag in prefixes {
                all_tags.push(tag);
            }

            continuation_token = next_token;
            if continuation_token.is_none() {
                break;
            }
        }

        let start_idx = if let Some(last_tag) = &last {
            all_tags
                .iter()
                .position(|tag| tag > last_tag)
                .unwrap_or(all_tags.len())
        } else {
            0
        };

        let end_idx = std::cmp::min(start_idx + usize::from(n), all_tags.len());
        let result_tags = all_tags[start_idx..end_idx].to_vec();

        let next_token = if end_idx < all_tags.len() {
            result_tags.last().cloned()
        } else {
            None
        };

        Ok((result_tags, next_token))
    }

    #[instrument(skip(self))]
    async fn list_referrers(
        &self,
        namespace: &str,
        digest: &Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, Error> {
        let referrers_dir = path_builder::manifest_referrers_dir(namespace, digest);

        let mut referrers = Vec::new();
        let mut continuation_token = None;

        loop {
            let (objects, next_token) = self
                .store
                .list_objects(&referrers_dir, 100, continuation_token)
                .await?;

            for key in objects {
                // The key is a relative path like "sha256/<digest>/link"
                let parts: Vec<&str> = key.split('/').collect();
                if parts.len() < 2 || parts[0] != "sha256" {
                    continue;
                }

                let manifest_digest = Digest::Sha256(parts[1].to_string());
                let blob_path = path_builder::blob_path(&manifest_digest);

                let manifest = match self.store.read(&blob_path).await {
                    Ok(data) => data,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Err(Error::ReferenceNotFound)
                    }
                    Err(e) => return Err(e.into()),
                };
                let manifest_len = manifest.len();

                let manifest = Manifest::from_slice(&manifest)?;
                let Some(descriptor) = manifest.into_referrer_descriptor(artifact_type.as_ref())
                else {
                    continue;
                };

                referrers.push(Descriptor {
                    digest: manifest_digest.to_string(),
                    size: manifest_len as u64,
                    ..descriptor
                });
            }

            continuation_token = next_token;
            if continuation_token.is_none() {
                break;
            }
        }

        Ok(referrers)
    }

    async fn list_revisions(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error> {
        debug!("Fetching {n} revision(s) for namespace '{namespace}' with continuation token: {continuation_token:?}");
        let revisions_dir = path_builder::manifest_revisions_link_root_dir(namespace, "sha256");

        let (prefixes, _, next_last) = self
            .store
            .list_prefixes(&revisions_dir, "/", i32::from(n), continuation_token)
            .await?;

        let mut revisions = Vec::new();
        for key in prefixes {
            revisions.push(Digest::Sha256(key));
        }

        Ok((revisions, next_last))
    }

    #[instrument(skip(self))]
    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobMetadata, Error> {
        let path = path_builder::blob_index_path(digest);

        let data = match self.store.read(&path).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::ReferenceNotFound)
            }
            Err(e) => return Err(e.into()),
        };
        let index = serde_json::from_slice(&data)?;

        Ok(index)
    }

    #[instrument(skip(self, operation))]
    async fn update_blob_index<O>(
        &self,
        namespace: &str,
        digest: &Digest,
        operation: O,
    ) -> Result<(), Error>
    where
        O: FnOnce(&mut HashSet<BlobLink>) + Send,
    {
        let path = path_builder::blob_index_path(digest);

        let res = self.store.read(&path).await;

        let mut reference_index = match res {
            Ok(data) => serde_json::from_slice::<BlobMetadata>(&data)?,
            Err(_) => BlobMetadata::default(),
        };

        let index = reference_index
            .namespace
            .entry(namespace.to_string())
            .or_insert_with(HashSet::new);

        operation(index);
        if index.is_empty() {
            reference_index.namespace.remove(namespace);
        }

        if reference_index.namespace.is_empty() {
            let path = path_builder::blob_container_dir(digest);
            self.store.delete_prefix(&path).await?;
        } else {
            let content = Bytes::from(serde_json::to_vec(&reference_index)?);
            self.store.put_object(&path, content).await?;
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn create_link(
        &self,
        namespace: &str,
        link: &BlobLink,
        digest: &Digest,
    ) -> Result<LinkMetadata, Error> {
        let _guard = self
            .lock_store
            .acquire_lock(&link.to_string())
            .await
            .map_err(|e| Error::StorageBackend(e.to_string()))?;
        let link_data = self.read_link_reference(namespace, link).await;

        if let Ok(link_data) = link_data {
            if &link_data.target != digest {
                let _blob_guard = self
                    .lock_store
                    .acquire_lock(link_data.target.as_str())
                    .await
                    .map_err(|e| Error::StorageBackend(e.to_string()))?;
                self.update_blob_index(namespace, &link_data.target, |index| {
                    index.remove(link);
                })
                .await?;

                let _blob_guard = self
                    .lock_store
                    .acquire_lock(digest.as_str())
                    .await
                    .map_err(|e| Error::StorageBackend(e.to_string()))?;
                self.update_blob_index(namespace, digest, |index| {
                    index.insert(link.clone());
                })
                .await?;
            }
        } else {
            let _blob_guard = self
                .lock_store
                .acquire_lock(digest.as_str())
                .await
                .map_err(|e| Error::StorageBackend(e.to_string()))?;
            self.update_blob_index(namespace, digest, |index| {
                index.insert(link.clone());
            })
            .await?;
        }

        let metadata = LinkMetadata::from_digest(digest.clone());
        self.write_link_reference(namespace, link, &metadata)
            .await?;
        Ok(metadata)
    }

    #[instrument(skip(self))]
    async fn read_link(
        &self,
        namespace: &str,
        link: &BlobLink,
        update_access_time: bool,
    ) -> Result<LinkMetadata, Error> {
        let _guard = self
            .lock_store
            .acquire_lock(&link.to_string())
            .await
            .map_err(|e| Error::StorageBackend(e.to_string()))?;

        if update_access_time {
            let link_data = self.read_link_reference(namespace, link).await?.accessed();
            self.write_link_reference(namespace, link, &link_data)
                .await?;
            Ok(link_data)
        } else {
            self.read_link_reference(namespace, link).await
        }
    }

    #[instrument(skip(self))]
    async fn delete_link(&self, namespace: &str, link: &BlobLink) -> Result<(), Error> {
        let _guard = self
            .lock_store
            .acquire_lock(&link.to_string())
            .await
            .map_err(|e| Error::StorageBackend(e.to_string()))?;
        let metadata = self.read_link_reference(namespace, link).await;

        let digest = match metadata {
            Ok(link_data) => link_data.target,
            Err(Error::ReferenceNotFound) => return Ok(()),
            Err(e) => return Err(e),
        };

        let _blob_guard = self
            .lock_store
            .acquire_lock(digest.as_str())
            .await
            .map_err(|e| Error::StorageBackend(e.to_string()))?;
        self.delete_link_reference(namespace, link).await?;
        self.update_blob_index(namespace, &digest, |index| {
            index.remove(link);
        })
        .await?;

        Ok(())
    }
}

impl Backend {
    async fn read_link_reference(
        &self,
        namespace: &str,
        link: &BlobLink,
    ) -> Result<LinkMetadata, Error> {
        let link_path = path_builder::get_link_path(link, namespace);
        match self.store.read(&link_path).await {
            Ok(data) => LinkMetadata::from_bytes(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::ReferenceNotFound),
            Err(e) => Err(e.into()),
        }
    }

    async fn write_link_reference(
        &self,
        namespace: &str,
        link: &BlobLink,
        metadata: &LinkMetadata,
    ) -> Result<(), Error> {
        let link_path = path_builder::get_link_path(link, namespace);
        let serialized_link_data = Bytes::from(serde_json::to_vec(metadata)?);
        self.store
            .put_object(&link_path, serialized_link_data)
            .await?;
        Ok(())
    }

    async fn delete_link_reference(&self, namespace: &str, link: &BlobLink) -> Result<(), Error> {
        let link_path = path_builder::get_link_path(link, namespace);
        self.store.delete(&link_path).await?;
        Ok(())
    }
}
