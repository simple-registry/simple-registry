use crate::configuration::StorageFSConfig;
use crate::lock_manager::LockManager;
use crate::oci::{Descriptor, Digest, Manifest};
use crate::registry::Error;
use crate::storage::entity_link::EntityLink;
use crate::storage::entity_path_builder::EntityPathBuilder;
use crate::storage::{
    deserialize_hash_state, serialize_hash_empty_state, serialize_hash_state, BlobEntityLinkIndex,
    GenericStorageEngine, Reader, ReferenceInfo, UploadSummary,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sha2::{Digest as ShaDigestTrait, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::io::{ErrorKind, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{self, File};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tracing::{debug, error, instrument, warn};

#[derive(Clone)]
pub struct StorageEngine {
    lock_manager: LockManager,
    pub tree: Arc<EntityPathBuilder>,
}

impl Debug for StorageEngine {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSystemStorageEngine").finish()
    }
}

impl StorageEngine {
    pub fn new(fs_config: StorageFSConfig, lock_manager: LockManager) -> Self {
        Self {
            tree: Arc::new(EntityPathBuilder::new(fs_config.root_dir)),
            lock_manager,
        }
    }

    #[instrument]
    pub async fn get_file_size(&self, path: &str) -> Result<Option<u64>, Error> {
        match fs::metadata(&path).await {
            Ok(metadata) => Ok(Some(metadata.len())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    #[instrument]
    async fn collect_repositories(&self, base_path: &Path) -> Vec<String> {
        let mut path_stack: Vec<PathBuf> = vec![base_path.to_path_buf()];
        let mut repositories = Vec::new();

        while let Some(current_path) = path_stack.pop() {
            if let Ok(mut entries) = fs::read_dir(&current_path).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();

                    if path.is_dir() {
                        debug!("checking path: {}", path.display());
                        // check entries starting with a "_": it means it's a repository
                        // add entries not starting with a "_" as paths to explore
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if name.starts_with('_') {
                                if let Some(name) =
                                    path.parent().and_then(|p| p.strip_prefix(base_path).ok())
                                {
                                    if let Some(name) = name.to_str() {
                                        debug!("Found repository: {}", name);
                                        repositories.push(name.to_string());
                                    }
                                }
                            } else {
                                debug!("Exploring path: {}", path.display());
                                path_stack.push(path);
                            }
                        }
                    }
                }
            }
        }

        repositories.sort();
        repositories
    }

    #[instrument]
    pub async fn collect_directory_entries(&self, path: &str) -> Result<Vec<String>, Error> {
        let mut entries = Vec::new();
        let mut read_dir = match fs::read_dir(&path).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(entries),
            Err(e) => return Err(e.into()),
        };

        while let Some(entry) = read_dir.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                entries.push(name.to_string());
            }
        }

        Ok(entries)
    }

    #[instrument]
    pub async fn delete_empty_parent_dirs(&self, path: &str) -> Result<(), Error> {
        let path = PathBuf::from(path);
        let root_dir = Path::new(&self.tree.prefix);

        let _ = fs::remove_dir_all(&path).await;

        let mut parent = path.parent();
        while let Some(parent_path) = parent {
            if parent_path == root_dir {
                break;
            }

            let Ok(mut entries) = fs::read_dir(&parent_path).await else {
                break;
            };

            if entries.next_entry().await?.is_some() {
                break;
            }

            debug!("Deleting empty parent dir: {}", parent_path.display());
            fs::remove_dir(parent_path).await?;

            parent = parent_path.parent();
        }

        Ok(())
    }

    pub async fn blob_link_index_update<O>(
        &self,
        namespace: &str,
        digest: &Digest,
        operation: O,
    ) -> Result<bool, Error>
    where
        O: FnOnce(&mut HashSet<EntityLink>),
    {
        debug!("Ensuring container directory for digest: {}", digest);
        let path = self.tree.blob_container_dir(digest);
        fs::create_dir_all(&path).await?;

        debug!("Updating reference count for digest: {}", digest);
        let path = self.tree.blob_index_path(digest);

        let mut reference_index = match fs::read_to_string(&path).await {
            Ok(content) => serde_json::from_str::<BlobEntityLinkIndex>(&content),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(BlobEntityLinkIndex::default()),
            Err(e) => return Err(e.into()),
        }?;

        debug!("Updating reference count");
        let mut index = reference_index.namespace.get_mut(namespace);
        if index.is_none() {
            reference_index
                .namespace
                .insert(namespace.to_string(), HashSet::new());
            index = reference_index.namespace.get_mut(namespace);
        };

        let Some(index) = index else {
            // Not supposed to happen as we just inserted it
            warn!("Unable to reliably create reference index for {}", digest);
            return Err(Error::NameUnknown);
        };

        operation(index);
        if index.is_empty() {
            reference_index.namespace.remove(namespace);
        }

        let is_referenced = !reference_index.namespace.is_empty();

        debug!("Writing reference count to path: {}", path);
        let content = serde_json::to_string(&reference_index)?;
        fs::write(&path, content).await?;

        debug!("Reference index for {} updated", digest);

        Ok(is_referenced)
    }

    pub fn paginate<T>(
        items: &[T],
        n: u16,
        continuation_token: Option<String>,
    ) -> (Vec<T>, Option<String>)
    where
        T: Clone + ToString,
    {
        let start = match continuation_token {
            Some(continuation_token) => {
                // search for the index of element lexicographically immediately after the continuation token
                items
                    .iter()
                    .position(|r| r.to_string() > continuation_token)
                    .unwrap_or(items.len())
            }
            None => 0,
        };

        let end = (start + n as usize).min(items.len());

        let items = items[start..end].to_vec();
        if end < items.len() {
            let next = items[end].to_string();
            (items, Some(next))
        } else {
            (items, None)
        }
    }
}

#[async_trait]
impl GenericStorageEngine for StorageEngine {
    #[instrument(skip(self))]
    async fn list_namespaces(
        &self,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        let base_path = self.tree.repository_dir();
        let base_path = Path::new(&base_path);

        let mut repositories = self.collect_repositories(base_path).await;
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
        let path = self.tree.manifest_tags_dir(namespace);
        debug!("Listing tags in path: {}", path);
        let mut tags = self.collect_directory_entries(&path).await?;
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
        let _guard = self.lock_manager.read_lock(digest.to_string()).await;
        let path = self.tree.manifest_referrers_dir(namespace, digest);
        let all_manifest = self.collect_directory_entries(&path).await?;
        let mut referrers = Vec::new();

        for manifest_digest in all_manifest {
            let manifest_digest = Digest::try_from(manifest_digest.as_str())?;
            let blob_path = self.tree.blob_path(&manifest_digest);

            let manifest = fs::read(&blob_path).await?;
            let manifest_len = manifest.len();
            let manifest: Manifest = serde_json::from_slice(&manifest)?;

            let Some(media_type) = manifest.media_type else {
                continue;
            };

            if let Some(artifact_type) = artifact_type.as_ref() {
                if let Some(manifest_artifact_type) = manifest.artifact_type.as_ref() {
                    if manifest_artifact_type != artifact_type {
                        continue;
                    }
                } else if let Some(manifest_config) = manifest.config {
                    if &manifest_config.media_type != artifact_type {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            referrers.push(Descriptor {
                media_type,
                digest: manifest_digest.to_string(),
                size: manifest_len as u64,
                annotations: manifest.annotations,
                artifact_type: manifest.artifact_type,
            });
        }

        Ok(referrers)
    }

    #[instrument(skip(self))]
    async fn list_uploads(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        let path = self.tree.uploads_root_dir(namespace);

        let mut uploads = Vec::new();
        for upload in self.collect_directory_entries(&path).await? {
            uploads.push(upload);
        }

        Ok(Self::paginate(&uploads, n, continuation_token))
    }

    #[instrument(skip(self))]
    async fn list_blobs(
        &self,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error> {
        let path = PathBuf::new()
            .join(self.tree.blobs_root_dir())
            .join("sha256")
            .to_string_lossy()
            .to_string();

        let all_prefixes = self.collect_directory_entries(&path).await?;

        let mut digests = Vec::new();

        for prefix in all_prefixes {
            let blob_path = PathBuf::from(&path)
                .join(&prefix)
                .to_string_lossy()
                .to_string();

            let all_digests = self.collect_directory_entries(&blob_path).await?;

            for digest in all_digests {
                digests.push(Digest::Sha256(digest));
            }
        }

        Ok(Self::paginate(&digests, n, continuation_token))
    }

    async fn list_revisions(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error> {
        let path = self
            .tree
            .manifest_revisions_link_root_dir(namespace, "sha256"); // HACK: hardcoded sha256

        let all_revisions = self.collect_directory_entries(&path).await?;
        let mut revisions = Vec::new();

        for revision in all_revisions {
            revisions.push(Digest::Sha256(revision));
        }

        Ok(Self::paginate(&revisions, n, continuation_token))
    }

    #[instrument(skip(self))]
    async fn create_upload(&self, name: &str, uuid: &str) -> Result<String, Error> {
        let _guard = self
            .lock_manager
            .write_lock("dir-management".to_string())
            .await;
        let container_dir = self.tree.upload_container_path(name, uuid);
        fs::create_dir_all(&container_dir).await?;

        let content_path = self.tree.upload_path(name, uuid);
        fs::write(content_path, "").await?;

        let container_dir = self.tree.upload_start_date_container_dir(name, uuid);
        fs::create_dir_all(&container_dir).await?;

        let date_path = self.tree.upload_start_date_path(name, uuid);
        fs::write(date_path, Utc::now().to_rfc3339()).await?;

        let container_dir = self
            .tree
            .upload_hash_context_container_path(name, uuid, "sha256");
        fs::create_dir_all(&container_dir).await?;

        let path = self.tree.upload_hash_context_path(name, uuid, "sha256", 0);
        let state = serialize_hash_empty_state().await?;
        fs::write(&path, state).await?;

        Ok(uuid.to_string())
    }

    #[instrument(skip(self, source))]
    async fn write_upload(
        &self,
        name: &str,
        uuid: &str,
        source: &[u8],
        append: bool,
    ) -> Result<(), Error> {
        let start_offset = if append {
            let summary = self.read_upload_summary(name, uuid).await?;
            summary.size
        } else {
            0
        };

        let file_path = self.tree.upload_path(name, uuid);
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .append(false)
            .write(true)
            .open(&file_path)
            .await
            .map_err(|e| {
                error!("Error opening upload file {:}: {}", file_path, e);
                if e.kind() == ErrorKind::NotFound {
                    Error::BlobUploadUnknown
                } else {
                    Error::Internal(Some("Error opening upload file".to_string()))
                }
            })?;

        file.seek(SeekFrom::Start(start_offset)).await?;

        let path = self
            .tree
            .upload_hash_context_path(name, uuid, "sha256", start_offset);
        let state = fs::read(&path).await?;
        let mut hasher = deserialize_hash_state(state).await?;

        file.seek(SeekFrom::Start(start_offset)).await?;

        let mut total_bytes_written = 0u64;

        file.write_all(source).await?;
        hasher.update(source);
        total_bytes_written += source.len() as u64;

        let offset = start_offset + total_bytes_written;
        let path = self
            .tree
            .upload_hash_context_path(name, uuid, "sha256", offset);
        let state = serialize_hash_state(&hasher).await?;
        fs::write(&path, &state).await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn read_upload_summary(&self, name: &str, uuid: &str) -> Result<UploadSummary, Error> {
        let file_path = self.tree.upload_path(name, uuid);
        let size = self
            .get_file_size(&file_path)
            .await?
            .ok_or(Error::BlobUnknown)?;

        let path = self
            .tree
            .upload_hash_context_path(name, uuid, "sha256", size);
        let state = fs::read(&path).await?;

        let hasher = deserialize_hash_state(state).await?;
        let digest = hasher.finalize();
        let digest = Digest::Sha256(hex::encode(digest));

        let date = self.tree.upload_start_date_path(name, uuid);
        let start_date = fs::read_to_string(&date)
            .await
            .ok()
            .and_then(|date| DateTime::parse_from_rfc3339(&date).ok())
            .unwrap_or_default() // Fallbacks to epoch
            .with_timezone(&Utc);

        Ok(UploadSummary {
            digest,
            size,
            start_date,
        })
    }

    #[instrument(skip(self))]
    async fn complete_upload(
        &self,
        name: &str,
        uuid: &str,
        digest: Option<Digest>,
    ) -> Result<Digest, Error> {
        let upload_path = self.tree.upload_path(name, uuid);
        let Some(size) = self.get_file_size(&upload_path).await? else {
            return Err(Error::BlobUnknown);
        };

        let digest = if let Some(digest) = digest {
            digest
        } else {
            let path = self
                .tree
                .upload_hash_context_path(name, uuid, "sha256", size);
            let state = fs::read(&path).await?;
            let hasher = deserialize_hash_state(state).await?;
            let digest = hasher.finalize();
            Digest::Sha256(hex::encode(digest))
        };

        let _guard = self.lock_manager.write_lock(digest.to_string()).await;

        let _guard = self
            .lock_manager
            .write_lock("dir-management".to_string())
            .await;
        let blob_root = self.tree.blob_container_dir(&digest);
        fs::create_dir_all(&blob_root).await?;

        let blob_path = self.tree.blob_path(&digest);
        fs::rename(&upload_path, &blob_path).await?;

        let _ = self
            .blob_link_index_update(name, &digest, |_| { /* NO-OP */ })
            .await?;

        let path = self.tree.upload_container_path(name, uuid);
        let _ = self.delete_empty_parent_dirs(&path).await;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn delete_upload(&self, name: &str, uuid: &str) -> Result<(), Error> {
        let _guard = self
            .lock_manager
            .write_lock("dir-management".to_string())
            .await;

        let path = self.tree.upload_container_path(name, uuid);
        let _ = self.delete_empty_parent_dirs(&path).await;

        Ok(())
    }

    #[instrument(skip(self, content))]
    async fn create_blob(&self, content: &[u8]) -> Result<Digest, Error> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher.finalize();
        let digest = Digest::Sha256(hex::encode(digest));

        let _guard = self.lock_manager.write_lock(digest.to_string()).await;

        let _guard = self
            .lock_manager
            .write_lock("dir-management".to_string())
            .await;

        let blob_root = self.tree.blob_container_dir(&digest);
        fs::create_dir_all(&blob_root).await?;

        let blob_path = self.tree.blob_path(&digest);
        fs::write(blob_path, content).await?;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, Error> {
        let _guard = self.lock_manager.read_lock(digest.to_string()).await;
        let path = self.tree.blob_path(digest);
        Ok(fs::read(path).await?)
    }

    #[instrument(skip(self))]
    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobEntityLinkIndex, Error> {
        let _guard = self.lock_manager.read_lock(digest.to_string()).await;
        let path = self.tree.blob_index_path(digest);
        let content = fs::read_to_string(&path).await?;

        let index = serde_json::from_str(&content)?;
        Ok(index)
    }

    #[instrument(skip(self))]
    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, Error> {
        let _guard = self.lock_manager.read_lock(digest.to_string()).await;
        let path = self.tree.blob_path(digest);
        self.get_file_size(&path).await?.ok_or(Error::BlobUnknown)
    }

    #[instrument(skip(self))]
    async fn read_reference_info(
        &self,
        name: &str,
        reference: &EntityLink,
    ) -> Result<ReferenceInfo, Error> {
        let key = match reference {
            EntityLink::Tag(_) | EntityLink::Digest(_) => self.tree.get_link_path(reference, name),
            _ => return Err(Error::NotFound),
        };

        let metadata = fs::metadata(&key).await?;

        let created_at = metadata.created()?;
        let created_at = DateTime::<Utc>::from(created_at).with_timezone(&Utc);

        let accessed_at = metadata.accessed()?;
        let accessed_at = DateTime::<Utc>::from(accessed_at).with_timezone(&Utc);

        Ok(ReferenceInfo {
            created_at,
            accessed_at,
        })
    }

    #[instrument(skip(self))]
    async fn build_blob_reader(
        &self,
        digest: &Digest,
        start_offset: Option<u64>,
    ) -> Result<Box<dyn Reader>, Error> {
        let _guard = self.lock_manager.read_lock(digest.to_string()).await;

        let path = self.tree.blob_path(digest);
        let mut file = match File::open(&path).await {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(Error::BlobUnknown),
            Err(e) => return Err(e.into()),
        };

        if let Some(offset) = start_offset {
            file.seek(SeekFrom::Start(offset)).await?;
        }

        Ok(Box::new(file))
    }

    #[instrument(skip(self))]
    async fn delete_blob(&self, digest: &Digest) -> Result<(), Error> {
        let _guard = self.lock_manager.write_lock(digest.to_string()).await;
        let _guard = self
            .lock_manager
            .write_lock("dir-management".to_string())
            .await;

        let path = self.tree.blob_container_dir(digest);
        let _ = self.delete_empty_parent_dirs(&path).await;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn update_last_pulled(&self, name: &str, reference: &EntityLink) -> Result<(), Error> {
        match reference {
            EntityLink::Tag(_) => {
                let path = self.tree.get_link_path(reference, name);
                let _ = fs::metadata(&path).await?;

                let digest = self.read_link(name, reference).await?;
                let link = EntityLink::Digest(digest);
                let path = self.tree.get_link_path(&link, name);
                let _ = fs::metadata(&path).await?;
            }
            EntityLink::Digest(_) => {
                let path = self.tree.get_link_path(reference, name);
                let _ = fs::metadata(&path).await?;
            }
            _ => {
                return Ok(()); // No-op
            }
        };

        Ok(())
    }

    #[instrument(skip(self))]
    async fn read_link(&self, name: &str, reference: &EntityLink) -> Result<Digest, Error> {
        debug!(
            "Reading link for namespace: {}, reference: {:?}",
            name, reference
        );
        let path = self.tree.get_link_path(reference, name);
        debug!("Reading link at path: {}", path);

        let link = fs::read_to_string(path).await?;
        debug!("Link content: {}", link);

        Ok(Digest::try_from(link.as_str())?)
    }

    #[instrument(skip(self))]
    async fn create_link(
        &self,
        namespace: &str,
        reference: &EntityLink,
        digest: &Digest,
    ) -> Result<(), Error> {
        debug!(
            "Creating link for namespace: {}, reference: {:?}",
            namespace, reference
        );

        match self.read_link(namespace, reference).await.ok() {
            Some(existing_digest) if &existing_digest == digest => return Ok(()),
            Some(existing_digest) if &existing_digest != digest => {
                // NOTE: no locks here, the delete_link will take care of it
                self.delete_link(namespace, reference).await?;
            }
            _ => {}
        }

        let _guard = self.lock_manager.write_lock(digest.to_string()).await;
        let _guard = self
            .lock_manager
            .write_lock("dir-management".to_string())
            .await;

        let path = self.tree.get_link_parent_path(reference, namespace);
        debug!("Creating link container dir at path: {}", path);
        fs::create_dir_all(&path).await?;

        let link_path = self.tree.get_link_path(reference, namespace);
        debug!("Creating link at path: {}", link_path);
        fs::write(&link_path, digest.to_string()).await?;

        debug!("Increasing reference count for digest: {}", digest);

        let _ = self
            .blob_link_index_update(namespace, digest, |index| {
                index.insert(reference.clone());
            })
            .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_link(&self, namespace: &str, reference: &EntityLink) -> Result<(), Error> {
        debug!(
            "Deleting link for namespace: {}, reference: {:?}",
            namespace, reference
        );
        let digest = match self.read_link(namespace, reference).await {
            Ok(digest) => digest,
            Err(Error::NameUnknown) => return Ok(()),
            Err(e) => return Err(e),
        };

        let link_path = self.tree.get_link_path(reference, namespace);
        if fs::metadata(&link_path).await.is_err() {
            return Ok(());
        }

        let path = self.tree.get_link_container_path(reference, namespace);
        debug!("Deleting link at path: {}", path);

        let _guard = self.lock_manager.write_lock(digest.to_string()).await;
        let _guard = self
            .lock_manager
            .write_lock("dir-management".to_string())
            .await;

        let _ = self.delete_empty_parent_dirs(&path).await;

        debug!("Unregistering reference: {:?}", reference);

        let is_referenced = self
            .blob_link_index_update(namespace, &digest, |index| {
                index.remove(reference);
            })
            .await?;

        if !is_referenced {
            debug!("Deleting no longer referenced Blob: {}", digest);
            let path = self.tree.blob_container_dir(&digest);
            let _ = self.delete_empty_parent_dirs(&path).await;
        }

        Ok(())
    }
}
