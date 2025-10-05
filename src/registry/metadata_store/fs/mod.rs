#[cfg(test)]
mod tests;

use crate::registry::metadata_store::link_kind::LinkKind;
use crate::registry::metadata_store::lock::{self, LockBackend, MemoryBackend};
use crate::registry::metadata_store::{
    BlobIndex, BlobIndexOperation, Error, LinkMetadata, LockConfig, MetadataStore,
};
use crate::registry::oci::{Descriptor, Digest, Manifest};
use crate::registry::{data_store, path_builder};
use async_trait::async_trait;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, instrument};

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct BackendConfig {
    pub root_dir: String,
    #[serde(default)]
    pub redis: Option<LockConfig>,
    #[serde(default)]
    pub sync_to_disk: bool,
}

impl From<BackendConfig> for data_store::fs::BackendConfig {
    fn from(config: BackendConfig) -> Self {
        Self {
            root_dir: config.root_dir,
            sync_to_disk: config.sync_to_disk,
        }
    }
}

#[derive(Clone)]
pub struct Backend {
    store: data_store::fs::Backend,
    lock: Arc<dyn LockBackend<Guard = Box<dyn Send>> + Send + Sync>,
}

impl Backend {
    pub fn new(config: &BackendConfig) -> Result<Self, Error> {
        info!("Using filesystem metadata-store backend");
        let store = data_store::fs::Backend::new(&data_store::fs::BackendConfig {
            root_dir: config.root_dir.clone(),
            sync_to_disk: config.sync_to_disk,
        });

        let lock: Arc<dyn LockBackend<Guard = Box<dyn Send>> + Send + Sync> =
            if let Some(redis_config) = &config.redis {
                info!("Using Redis lock store for filesystem metadata-store");
                let backend = lock::RedisBackend::new(redis_config).map_err(|e| {
                    Error::Lock(format!("Failed to initialize Redis lock store: {e}"))
                })?;
                Arc::new(backend)
            } else {
                info!("Using in-memory lock store for filesystem metadata-store");
                Arc::new(MemoryBackend::new())
            };

        Ok(Self { store, lock })
    }

    pub fn paginate<T>(
        items: &[T],
        n: u16,
        continuation_token: Option<String>,
    ) -> (Vec<T>, Option<String>)
    where
        T: Clone + ToString + Ord,
    {
        let start = match continuation_token {
            Some(token) => match items.iter().position(|item| item.to_string() == token) {
                Some(pos) => pos + 1,
                None => 0,
            },
            None => 0,
        };

        let end = (start + n as usize).min(items.len());
        let result = items[start..end].to_vec();

        let next_token = if !result.is_empty() && end < items.len() {
            Some(result.last().unwrap().to_string())
        } else {
            None
        };

        (result, next_token)
    }

    //

    #[instrument(skip(self))]
    async fn collect_repositories(&self, base_path: &str) -> Vec<String> {
        let mut path_stack: Vec<String> = vec![base_path.to_string()];
        let mut repositories = Vec::new();

        while let Some(current_path) = path_stack.pop() {
            if let Ok(entries) = self.store.list_dir(&current_path).await {
                for entry in entries {
                    let path = if current_path.ends_with('/') {
                        format!("{current_path}{entry}")
                    } else if current_path.is_empty() {
                        entry.clone()
                    } else {
                        format!("{current_path}/{entry}")
                    };

                    // check entries starting with a "_": it means it's a repository
                    // add entries not starting with a "_" as paths to explore
                    if entry.starts_with('_') {
                        // Extract the repository name from the parent path
                        if let Some(repo_name) = PathBuf::from(&current_path)
                            .strip_prefix(base_path)
                            .ok()
                            .and_then(|p| p.to_str())
                        {
                            if !repo_name.is_empty() {
                                debug!("Found repository: {repo_name}");
                                repositories.push(repo_name.to_string());
                            }
                        }
                    } else {
                        debug!("Exploring path: {}", path);
                        path_stack.push(path);
                    }
                }
            }
        }

        repositories.sort();
        repositories
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
        let base_path = path_builder::repository_dir();

        let mut repositories = self.collect_repositories(&base_path).await;
        repositories.dedup();

        Ok(Self::paginate(&repositories, n, last))
    }

    #[instrument(skip(self))]
    async fn list_tags(
        &self,
        namespace: &str,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        let path = path_builder::manifest_tags_dir(namespace);
        debug!("Listing tags in path: {path}");
        let mut tags = self.store.list_dir(&path).await?;
        tags.sort();

        Ok(Self::paginate(&tags, n, last))
    }

    #[instrument(skip(self))]
    async fn list_referrers(
        &self,
        namespace: &str,
        digest: &Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, Error> {
        let path = format!(
            "{}/sha256",
            path_builder::manifest_referrers_dir(namespace, digest)
        );
        let all_manifest = self.store.list_dir(&path).await?;
        let mut referrers = Vec::new();

        for manifest_digest in all_manifest {
            let manifest_digest = Digest::Sha256(manifest_digest);
            let blob_path = path_builder::blob_path(&manifest_digest);

            let manifest = self.store.read(&blob_path).await?;
            let manifest_len = manifest.len();

            let manifest = Manifest::from_slice(&manifest)?;
            let Some(descriptor) = manifest.into_referrer_descriptor(artifact_type.as_ref()) else {
                continue;
            };

            referrers.push(Descriptor {
                digest: manifest_digest.to_string(),
                size: manifest_len as u64,
                ..descriptor
            });
        }

        Ok(referrers)
    }

    async fn list_revisions(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error> {
        let path = path_builder::manifest_revisions_link_root_dir(namespace, "sha256"); // HACK: hardcoded sha256

        let all_revisions = self.store.list_dir(&path).await?;
        let mut revisions = Vec::new();

        for revision in all_revisions {
            revisions.push(Digest::Sha256(revision));
        }

        Ok(Self::paginate(&revisions, n, continuation_token))
    }

    #[instrument(skip(self))]
    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobIndex, Error> {
        let path = path_builder::blob_index_path(digest);
        let content = self.store.read_to_string(&path).await?;

        let index = serde_json::from_str(&content)?;
        Ok(index)
    }

    async fn update_blob_index(
        &self,
        namespace: &str,
        digest: &Digest,
        operation: BlobIndexOperation,
    ) -> Result<(), Error> {
        debug!("Ensuring container directory for digest: {digest}");

        debug!("Updating reference count for digest: {digest}");
        let path = path_builder::blob_index_path(digest);

        let mut reference_index = match self.store.read_to_string(&path).await.map_err(Error::from)
        {
            Ok(content) => serde_json::from_str::<BlobIndex>(&content)?,
            Err(Error::ReferenceNotFound) => BlobIndex::default(),
            Err(e) => Err(e)?,
        };

        debug!("Updating reference index");
        let mut index = reference_index
            .namespace
            .remove(namespace)
            .unwrap_or_default();
        match operation {
            BlobIndexOperation::Insert(link) => {
                index.insert(link);
            }
            BlobIndexOperation::Remove(link) => {
                index.remove(&link);
            }
        }
        if !index.is_empty() {
            reference_index
                .namespace
                .insert(namespace.to_string(), index);
        }

        if reference_index.namespace.is_empty() {
            debug!("Deleting no longer referenced Blob: {digest}");
            let path = path_builder::blob_container_dir(digest);
            self.store.delete_dir(&path).await?;
            let _ = self.store.delete_empty_parent_dirs(&path).await;
        } else {
            debug!("Writing reference count to path: {path}");
            let content = serde_json::to_string(&reference_index)?;
            self.store.write(&path, content.as_bytes()).await?;
            debug!("Reference index for {digest} updated");
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn create_link(
        &self,
        namespace: &str,
        link: &LinkKind,
        digest: &Digest,
    ) -> Result<LinkMetadata, Error> {
        let _guard = self.lock.acquire(&link.to_string()).await?;
        let link_data = self.read_link_reference(namespace, link).await;

        // Overwriting an existing link!
        if let Ok(link_data) = link_data {
            if &link_data.target != digest {
                let _blob_guard = self.lock.acquire(link_data.target.as_str()).await?;
                self.update_blob_index(
                    namespace,
                    &link_data.target,
                    BlobIndexOperation::Remove(link.clone()),
                )
                .await?;

                let _blob_guard = self.lock.acquire(digest.as_str()).await?;
                self.update_blob_index(namespace, digest, BlobIndexOperation::Insert(link.clone()))
                    .await?;
            }
        } else {
            let _blob_guard = self.lock.acquire(digest.as_str()).await?;
            self.update_blob_index(namespace, digest, BlobIndexOperation::Insert(link.clone()))
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
        link: &LinkKind,
        update_access_time: bool,
    ) -> Result<LinkMetadata, Error> {
        let _guard = self.lock.acquire(&link.to_string()).await?;

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
    async fn delete_link(&self, namespace: &str, link: &LinkKind) -> Result<(), Error> {
        let _guard = self.lock.acquire(&link.to_string()).await?;
        let metadata = self.read_link_reference(namespace, link).await;

        let digest = match metadata {
            Ok(link_data) => link_data.target,
            Err(Error::ReferenceNotFound) => return Ok(()),
            Err(e) => return Err(e),
        };

        let _blob_guard = self.lock.acquire(digest.as_str()).await?;
        self.delete_link_reference(namespace, link).await?;
        self.update_blob_index(namespace, &digest, BlobIndexOperation::Remove(link.clone()))
            .await?;

        Ok(())
    }
}

impl Backend {
    async fn read_link_reference(
        &self,
        namespace: &str,
        link: &LinkKind,
    ) -> Result<LinkMetadata, Error> {
        let link_path = path_builder::get_link_path(link, namespace);

        let link = self.store.read(&link_path).await?;
        LinkMetadata::from_bytes(link)
    }

    async fn write_link_reference(
        &self,
        namespace: &str,
        link: &LinkKind,
        metadata: &LinkMetadata,
    ) -> Result<(), Error> {
        let link_path = path_builder::get_link_path(link, namespace);
        let serialized_link_data = serde_json::to_vec(metadata)?;
        self.store.write(&link_path, &serialized_link_data).await?;
        Ok(())
    }

    async fn delete_link_reference(&self, namespace: &str, link: &LinkKind) -> Result<(), Error> {
        let path = path_builder::get_link_container_path(link, namespace);
        debug!("Deleting link at path: {path}");

        self.store.delete_dir(&path).await?;
        let _ = self.store.delete_empty_parent_dirs(&path).await;

        Ok(())
    }
}
