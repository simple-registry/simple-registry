use async_trait::async_trait;
use chrono::Utc;
use log::{debug, error, warn};
use sha2::digest::crypto_common::hazmat::SerializableState;
use sha2::{Digest as ShaDigestTrait, Sha256};
use std::collections::HashSet;
use std::io::{ErrorKind, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{self, File};
use tokio::io::AsyncSeekExt;
use uuid::Uuid;

use crate::error::RegistryError;
use crate::oci::{Descriptor, Digest, Manifest};
use crate::registry::LinkReference;
use crate::storage::disk_engine::upload_writer::DiskUploadWriter;
use crate::storage::tree_manager::TreeManager;
use crate::storage::{
    paginate, StorageEngine, StorageEngineReader, StorageEngineWriter, UploadSummary,
};

mod upload_writer;

pub async fn save_hash_state(
    tree_manager: &TreeManager,
    sha256: &Sha256,
    name: &str,
    uuid: &Uuid,
    algorithm: &str,
    offset: u64,
) -> Result<(), RegistryError> {
    let path = tree_manager.upload_hash_context_path(name, uuid, algorithm, offset);

    let state = sha256.serialize();
    let state = state.as_slice().to_vec();

    fs::write(&path, state).await?;
    Ok(())
}

pub async fn load_hash_state(
    tree_manager: &TreeManager,
    name: &str,
    uuid: &Uuid,
    algorithm: &str,
    offset: u64,
) -> Result<Sha256, RegistryError> {
    let path = tree_manager.upload_hash_context_path(name, uuid, algorithm, offset);
    let state = fs::read(&path).await?;

    let state = state
        .as_slice()
        .try_into()
        .map_err(|_| RegistryError::InternalServerError(None))?;
    let state = Sha256::deserialize(state)?;
    let hasher = Sha256::from(state);

    Ok(hasher)
}

#[derive(Clone)]
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
            Err(e) => Err(e.into()),
        }
    }

    async fn collect_repositories(&self, base_path: &Path, repositories: &mut HashSet<String>) {
        let mut path_stack: Vec<PathBuf> = vec![base_path.to_path_buf()];

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
                                        repositories.insert(name.to_string());
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
    }

    pub async fn collect_directory_entries(
        &self,
        path: &String,
    ) -> Result<Vec<String>, RegistryError> {
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

    pub async fn delete_empty_parent_dirs(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), RegistryError> {
        let path = PathBuf::from(path.as_ref());
        let root_dir = Path::new(&self.tree.root_dir);

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
            Err(e) => return Err(e.into()),
        };

        debug!("Updating reference count");
        let count = count.map_err(|err| {
            error!("Error parsing reference count: {}", err);
            RegistryError::InternalServerError(None)
        })?;
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
    async fn read_catalog(
        &self,
        n: u32,
        last: String,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        let base_path = self.tree.repository_dir();
        let base_path = Path::new(&base_path);
        let mut repositories = HashSet::new();
        self.collect_repositories(base_path, &mut repositories)
            .await;

        let mut repositories: Vec<String> = repositories.into_iter().collect();
        repositories.sort();
        Ok(paginate(&repositories, n, last))
    }

    async fn list_tags(
        &self,
        name: &str,
        n: u32,
        last: String,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        let path = self.tree.manifest_tags_dir(name);
        debug!("Listing tags in path: {}", path);
        let mut tags = self.collect_directory_entries(&path).await?;
        tags.sort();
        Ok(paginate(&tags, n, last))
    }

    async fn list_referrers(
        &self,
        name: &str,
        digest: &Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, RegistryError> {
        let path = self.tree.manifest_referrers_dir(name, digest);
        let all_manifest = self.collect_directory_entries(&path).await?;
        let mut referrers = Vec::new();

        // TODO: instead of having the digest in the filename, we could have it in file content!

        for manifest_digest in all_manifest {
            let manifest_digest = Digest::from_str(&manifest_digest)?;
            let blob_path = self.tree.blob_path(&manifest_digest);

            let raw_manifest = fs::read(&blob_path).await?;
            let manifest: Manifest = serde_json::from_slice(&raw_manifest)?;

            if let Some(artifact_type) = artifact_type.clone() {
                if let Some(manifest_artifact_type) = manifest.artifact_type.clone() {
                    if manifest_artifact_type != artifact_type {
                        continue;
                    }
                } else if let Some(manifest_config) = manifest.config {
                    if manifest_config.media_type != artifact_type {
                        continue;
                    }
                } else {
                    continue;
                }
            }

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

        let container_dir = self
            .tree
            .upload_hash_context_container_path(name, &uuid, "sha256");
        fs::create_dir_all(&container_dir).await?;

        let hasher = Sha256::new();
        save_hash_state(&self.tree, &hasher, name, &uuid, "sha256", 0).await?;

        Ok(uuid.to_string())
    }

    async fn build_upload_writer(
        &self,
        name: &str,
        uuid: Uuid,
        start_offset: Option<u64>,
    ) -> Result<Box<dyn StorageEngineWriter>, RegistryError> {
        Ok(Box::new(
            DiskUploadWriter::new(self.tree.clone(), name, uuid, start_offset.unwrap_or(0)).await?,
        ))
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

        let hasher = load_hash_state(&self.tree, name, &uuid, "sha256", size).await?;
        let hash = hasher.finalize();

        let digest = Digest::Sha256(hex::encode(hash));
        Ok(UploadSummary { digest, size })
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
                let hasher = load_hash_state(&self.tree, name, &uuid, "sha256", size).await?;
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
    ) -> Result<Box<dyn StorageEngineReader>, RegistryError> {
        let path = self.tree.blob_path(digest);
        let mut file = match File::open(&path).await {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(RegistryError::BlobUnknown),
            Err(e) => return Err(e.into()),
        };

        if let Some(offset) = start_offset {
            file.seek(SeekFrom::Start(offset)).await?;
        }

        Ok(Box::new(file))
    }

    async fn delete_blob(&self, digest: &Digest) -> Result<(), RegistryError> {
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

        let path = self.tree.get_link_container_path(reference, name);
        debug!("Deleting link at path: {}", path);
        let _ = fs::remove_dir_all(&path).await;
        self.delete_empty_parent_dirs(&path).await?;

        self.blob_rc_decrease(&digest).await
    }
}
