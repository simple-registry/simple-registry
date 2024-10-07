use async_trait::async_trait;
use chrono::Utc;
use log::{debug, error, warn};
use sha2::digest::crypto_common::hazmat::SerializableState;
use sha2::{Digest as ShaDigestTrait, Sha256};
use std::io::{ErrorKind, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{self, File};
use tokio::io::AsyncSeekExt;
use uuid::Uuid;

use crate::error::RegistryError;
use crate::oci::{Descriptor, Digest, LinkReference, Manifest};
use crate::storage::disk_engine::upload_writer::DiskUploadWriter;
use crate::storage::tree_manager::TreeManager;
use crate::storage::{StorageEngine, UploadSummary};

mod upload_writer;

pub struct DiskStorageEngine {
    pub tree: Arc<TreeManager>,
}

impl DiskStorageEngine {
    pub fn new(root_dir: String) -> Self {
        Self {
            tree: Arc::new(TreeManager { root_dir }),
        }
    }

    pub async fn get_file_size(&self, path: &String) -> Result<Option<u64>, RegistryError> {
        match fs::metadata(&path).await {
            Ok(metadata) => Ok(Some(metadata.len())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => {
                error!("Error accessing file metadata {}: {}", path, e);
                Err(RegistryError::InternalServerError)
            }
        }
    }

    // TODO: cleanup

    pub async fn collect_directory_entries(
        &self,
        path: &String,
    ) -> Result<Vec<String>, RegistryError> {
        let mut entries = Vec::new();
        let mut read_dir = match fs::read_dir(&path).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(entries),
            Err(e) => {
                error!("Error reading directory {}: {}", path, e);
                return Err(RegistryError::InternalServerError);
            }
        };

        while let Some(entry) = read_dir.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                entries.push(name.to_string());
            }
        }

        Ok(entries)
    }

    pub fn paginate(
        &self,
        items: &[String],
        n: u32,
        last: String,
    ) -> (Vec<String>, Option<String>) {
        let start = if last.is_empty() {
            0
        } else {
            items.iter().position(|x| x == &last).map_or(0, |i| i + 1)
        };

        let end = usize::min(start + n as usize, items.len());
        let next = if end < items.len() {
            Some(items[end - 1].clone())
        } else {
            None
        };

        (items[start..end].to_vec(), next)
    }

    pub async fn delete_empty_parent_dirs(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), RegistryError> {
        let path = PathBuf::from(path.as_ref());

        let mut parent = path.parent();
        while let Some(parent_path) = parent {
            if parent_path == Path::new(&self.tree.root_dir) {
                break;
            }

            let Ok(mut entries) = fs::read_dir(&parent_path).await else {
                break;
            };

            if entries.next_entry().await?.is_some() {
                break;
            }

            error!("Deleting empty parent dir: {}", parent_path.display());
            fs::remove_dir(parent_path).await?;
            parent = parent_path.parent();
        }

        Ok(())
    }

    // TODO: /cleanup

    pub async fn blob_rc_update<O>(
        &self,
        digest: &Digest,
        operation: O,
    ) -> Result<u32, RegistryError>
    where
        O: FnOnce(u32) -> u32,
    {
        debug!("Ensuring container directory for digest: {}", digest);
        let path = self.tree.blob_container_dir(digest);
        fs::create_dir_all(&path).await?;

        debug!("Updating reference count for digest: {}", digest);
        let path = self.tree.blob_ref_path(digest);

        debug!("Reading reference count from path: {}", path);
        let count = match fs::read_to_string(&path).await {
            Ok(content) => content.parse::<u32>(),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(0),
            Err(_) => return Err(RegistryError::InternalServerError),
        };

        debug!("Updating reference count");
        let count = count.map_err(|_| RegistryError::InternalServerError)?;
        let count = operation(count);

        debug!("Writing reference count to path: {}", path);
        fs::write(&path, count.to_string()).await?;

        debug!("Reference count for {} updated to {}", digest, count);
        Ok(count)
    }

    pub async fn blob_rc_init(&self, digest: &Digest) -> Result<(), RegistryError> {
        debug!("Initializing reference count for digest: {}", digest);
        let _ = self.blob_rc_update(digest, |_| 0).await?;
        Ok(())
    }

    pub async fn blob_rc_increase(&self, digest: &Digest) -> Result<(), RegistryError> {
        debug!("Increasing reference count for digest: {}", digest);
        let _ = self.blob_rc_update(digest, |count| count + 1).await?;

        Ok(())
    }

    pub async fn blob_rc_decrease(&self, digest: &Digest) -> Result<(), RegistryError> {
        debug!("Decreasing reference count for digest: {}", digest);
        if self.blob_rc_update(digest, |count| if count > 0 {
            count - 1
        } else {
            warn!("Reference count for digest {} is already 0, reference counting is maybe inconsistent", digest);
            0
        }).await? == 0 {
            debug!("Deleting blob with digest since RC = 0: {}", digest);
            self.delete_blob(digest).await?;
        }

        Ok(())
    }
}

#[async_trait]
impl StorageEngine for DiskStorageEngine {
    type Reader = File;
    type Writer = DiskUploadWriter;

    async fn read_catalog(
        &self,
        n: u32,
        last: String,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        let repository_dir = self.tree.repository_dir();
        // FIXME: detect repositories with "/" in the name! or adopt a declarative approach to define valid repositories

        let mut all_repos = self.collect_directory_entries(&repository_dir).await?;
        all_repos.sort();
        Ok(self.paginate(&all_repos, n, last))
    }

    async fn list_tags(
        &self,
        name: &str,
        n: u32,
        last: String,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        let path = self.tree.manifest_tags_dir(name);
        debug!("Listing tags in path: {}", path);
        let mut all_tags = self.collect_directory_entries(&path).await?;
        all_tags.sort();
        Ok(self.paginate(&all_tags, n, last))
    }

    async fn list_referrers(
        &self,
        name: &str,
        digest: &Digest,
    ) -> Result<Vec<Descriptor>, RegistryError> {
        let path = self.tree.manifest_referrers_dir(name, digest);
        let all_manifest = self.collect_directory_entries(&path).await?;
        let mut referrers = Vec::new();
        // FIXME: instead of having the digest in the filename, we could have it in file content!
        for manifest_digest in all_manifest {
            let manifest_digest = Digest::from_str(&manifest_digest)?;
            let blob_path = self.tree.blob_path(&manifest_digest);

            let raw_manifest = fs::read(&blob_path).await?;
            let manifest: Manifest = serde_json::from_slice(&raw_manifest)?;

            referrers.push(Descriptor {
                media_type: manifest.media_type,
                digest: manifest_digest.to_string(),
                size: raw_manifest.len() as u64,
                annotations: manifest.annotations,
                artifact_type: manifest.artifact_type,
            });
        }
        Ok(referrers)
    }

    async fn create_upload(&self, name: &str, uuid: Uuid) -> Result<String, RegistryError> {
        let container_dir = self.tree.upload_container_path(name, &uuid);
        fs::create_dir_all(&container_dir).await?;

        let content_path = self.tree.upload_path(name, &uuid);
        fs::write(content_path, "").await?;

        let container_dir = self.tree.upload_start_date_container_dir(name, &uuid);
        fs::create_dir_all(&container_dir).await?;

        let date_path = self.tree.upload_start_date_path(name, &uuid);
        fs::write(date_path, Utc::now().to_rfc3339()).await?;

        // TODO: rework to have a one-liner
        let container_dir = self
            .tree
            .upload_hash_context_container_path(name, &uuid, "sha256");
        fs::create_dir_all(&container_dir).await?;

        // TODO: cleanup
        let hasher = Sha256::new();
        let hasher_state = hasher.clone();
        let hasher_state = hasher_state.serialize();
        let hasher_state = hasher_state.as_slice().to_vec();

        self.tree
            .save_hashstate(name, &uuid, "sha256", 0, &hasher_state)
            .await?;

        Ok(uuid.to_string())
    }

    async fn build_upload_writer(
        &self,
        name: &str,
        uuid: Uuid,
        start_offset: Option<u64>,
    ) -> Result<Self::Writer, RegistryError> {
        DiskUploadWriter::new(self.tree.clone(), name, uuid, start_offset.unwrap_or(0)).await
    }

    async fn read_upload_summary(
        &self,
        name: &str,
        uuid: Uuid,
    ) -> Result<UploadSummary, RegistryError> {
        let file_path = self.tree.upload_path(name, &uuid);
        let size = self
            .get_file_size(&file_path)
            .await?
            .ok_or(RegistryError::BlobUnknown)?;

        let offsets = self.tree.list_hashstates(name, &uuid, "sha256").await?;

        // TODO: cleanup the syntax
        if let Some(&last_offset) = offsets.last() {
            if last_offset == size {
                let state_bytes = self
                    .tree
                    .load_hashstate(name, &uuid, "sha256", last_offset)
                    .await?;
                let state_array = state_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| RegistryError::InternalServerError)?;
                let hasher_state = Sha256::deserialize(state_array)?;
                let hasher = Sha256::from(hasher_state);
                let hash = hasher.finalize();
                let digest = hex::encode(hash);
                let digest = Digest::Sha256(digest);
                Ok(UploadSummary { digest, size })
            } else {
                Err(RegistryError::InternalServerError)
            }
        } else {
            Err(RegistryError::InternalServerError)
        }
    }

    async fn complete_upload(
        &self,
        name: &str,
        uuid: Uuid,
        digest: Option<Digest>,
    ) -> Result<Digest, RegistryError> {
        let upload_path = self.tree.upload_path(name, &uuid);
        let Some(size) = self.get_file_size(&upload_path).await? else {
            return Err(RegistryError::BlobUnknown);
        };

        let digest = match digest {
            Some(digest) => digest,
            None => {
                let offsets = self.tree.list_hashstates(name, &uuid, "sha256").await?;
                let Some(&last_offset) = offsets.last() else {
                    return Err(RegistryError::InternalServerError);
                };
                if last_offset != size {
                    return Err(RegistryError::InternalServerError);
                }

                let state_bytes = self
                    .tree
                    .load_hashstate(name, &uuid, "sha256", last_offset)
                    .await?;
                let state_array = state_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| RegistryError::InternalServerError)?;
                let hasher_state = Sha256::deserialize(state_array)?;
                let hasher = Sha256::from(hasher_state);
                let hash = hasher.finalize();
                let digest = hex::encode(hash);
                Digest::Sha256(digest)
            }
        };

        let blob_root = self.tree.blob_container_dir(&digest);
        fs::create_dir_all(&blob_root).await?;

        let blob_path = self.tree.blob_path(&digest);
        fs::rename(&upload_path, &blob_path).await?;

        self.blob_rc_init(&digest).await?;

        self.delete_upload(name, uuid).await?;

        Ok(digest)
    }

    async fn delete_upload(&self, name: &str, uuid: Uuid) -> Result<(), RegistryError> {
        // TODO: implement a mechanism to ensure data integrity (operation-queue, scrub?)
        let path = self.tree.upload_container_path(name, &uuid);
        let _ = fs::remove_dir_all(&path).await;
        self.delete_empty_parent_dirs(&path).await
    }

    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, RegistryError> {
        let path = self.tree.blob_path(digest);
        self.get_file_size(&path)
            .await?
            .ok_or(RegistryError::BlobUnknown)
    }

    async fn build_blob_reader(
        &self,
        digest: &Digest,
        start_offset: Option<u64>,
    ) -> Result<Self::Reader, RegistryError> {
        let path = self.tree.blob_path(digest);
        let mut file = match File::open(&path).await {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(RegistryError::BlobUnknown),
            Err(e) => {
                error!("Error opening blob file {}: {}", path, e);
                return Err(RegistryError::InternalServerError);
            }
        };

        if let Some(offset) = start_offset {
            file.seek(SeekFrom::Start(offset)).await?;
        }

        Ok(file)
    }

    async fn delete_blob(&self, digest: &Digest) -> Result<(), RegistryError> {
        // TODO: implement a mechanism to ensure data integrity (operation-queue, scrub?)
        let path = self.tree.blob_container_dir(digest);
        fs::remove_dir_all(&path).await?;
        self.delete_empty_parent_dirs(&path).await
    }

    async fn read_link(
        &self,
        name: &str,
        reference: &LinkReference,
    ) -> Result<Digest, RegistryError> {
        debug!(
            "Reading link for namespace: {}, reference: {:?}",
            name, reference
        );
        let path = self.tree.get_link_path(reference, name);
        debug!("Reading link at path: {}", path);

        let link = fs::read_to_string(path).await?;
        Digest::from_str(&link)
    }

    async fn create_link(
        &self,
        namespace: &str,
        reference: &LinkReference,
        digest: &Digest,
    ) -> Result<(), RegistryError> {
        debug!(
            "Creating link for namespace: {}, reference: {:?}",
            namespace, reference
        );

        let path = self.tree.get_link_parent_path(reference, namespace);
        debug!("Creating link container dir at path: {}", path);
        fs::create_dir_all(&path).await?;

        // TODO: implement a mechanism to ensure data integrity (operation-queue, scrub?)
        let link_path = self.tree.get_link_path(reference, namespace);
        debug!("Creating link at path: {}", link_path);
        fs::write(&link_path, digest.to_string()).await?;

        debug!("Increasing reference count for digest: {}", digest);
        self.blob_rc_increase(digest).await
    }

    async fn delete_link(
        &self,
        name: &str,
        reference: &LinkReference,
    ) -> Result<(), RegistryError> {
        debug!(
            "Deleting link for namespace: {}, reference: {:?}",
            name, reference
        );
        let digest = self.read_link(name, reference).await?;

        // TODO: implement a mechanism to ensure data integrity (operation-queue, scrub?)
        let path = self.tree.get_link_container_path(reference, name);
        debug!("Deleting link at path: {}", path);
        let _ = fs::remove_dir_all(&path).await;
        self.delete_empty_parent_dirs(&path).await?;

        self.blob_rc_decrease(&digest).await
    }
}
