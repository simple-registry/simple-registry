use async_trait::async_trait;
use chrono::Utc;
use lazy_static::lazy_static;
use sha2::digest::crypto_common::hazmat::SerializableState;
use sha2::{Digest as ShaDigestTrait, Sha256};
use std::collections::HashSet;
use std::io::{ErrorKind, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{self, File};
use tokio::io::AsyncSeekExt;
use tokio::sync::Mutex;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

use crate::error::RegistryError;
use crate::oci::{Descriptor, Digest, Manifest};
use crate::registry::LinkReference;
use crate::storage::filesystem::upload_writer::DiskUploadWriter;
use crate::storage::tree_manager::TreeManager;
use crate::storage::{
    paginate, BlobReferenceIndex, StorageEngine, StorageEngineReader, StorageEngineWriter,
    UploadSummary,
};

mod upload_writer;

lazy_static! {
    // TODO: lock at the filesystem level instead!
    static ref RC_LOCK: Mutex<()> = Mutex::new(());
}

#[instrument]
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

#[instrument]
pub async fn load_hash_state(
    tree_manager: &TreeManager,
    name: &str,
    uuid: &Uuid,
    algorithm: &str,
    offset: u64,
) -> Result<Sha256, RegistryError> {
    let path = tree_manager.upload_hash_context_path(name, uuid, algorithm, offset);
    let state = fs::read(&path).await?;

    let state = state.as_slice().try_into().map_err(|_| {
        RegistryError::InternalServerError(Some("Unable to resume hash state".to_string()))
    })?;
    let state = Sha256::deserialize(state)?;
    let hasher = Sha256::from(state);

    Ok(hasher)
}

#[derive(Clone, Debug)]
pub struct FileSystemStorageEngine {
    pub tree: Arc<TreeManager>,
}

impl FileSystemStorageEngine {
    pub fn new(root_dir: String) -> Self {
        Self {
            tree: Arc::new(TreeManager { root_dir }),
        }
    }

    #[instrument]
    pub async fn get_file_size(&self, path: &String) -> Result<Option<u64>, RegistryError> {
        match fs::metadata(&path).await {
            Ok(metadata) => Ok(Some(metadata.len())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    #[instrument]
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

    #[instrument]
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

    #[instrument]
    pub async fn delete_empty_parent_dirs(&self, path: &str) -> Result<(), RegistryError> {
        let path = PathBuf::from(path);
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

    pub async fn blob_link_index_update<O>(
        &self,
        namespace: &str,
        digest: &Digest,
        operation: O,
    ) -> Result<HashSet<LinkReference>, RegistryError>
    where
        O: FnOnce(&mut HashSet<LinkReference>),
    {
        debug!("Ensuring container directory for digest: {}", digest);
        let path = self.tree.blob_container_dir(digest);
        fs::create_dir_all(&path).await?;

        debug!("Updating reference count for digest: {}", digest);
        let path = self.tree.blob_ref_path(digest);

        let mut reference_index = match fs::read_to_string(&path).await {
            Ok(content) => serde_json::from_str::<BlobReferenceIndex>(&content),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(BlobReferenceIndex::default()),
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
            return Err(RegistryError::NameUnknown);
        };

        operation(index);
        let res = index.clone();

        debug!("Writing reference count to path: {}", path);
        let content = serde_json::to_string(&reference_index)?;
        fs::write(&path, content).await?;

        debug!("Reference index for {} updated", digest);
        Ok(res)
    }

    #[instrument]
    pub async fn blob_link_index_init(
        &self,
        namespace: &str,
        digest: &Digest,
    ) -> Result<(), RegistryError> {
        let _ = RC_LOCK.lock().await;
        let _ = self
            .blob_link_index_update(namespace, digest, |_| { /* NO-OP */ })
            .await?;
        Ok(())
    }

    #[instrument]
    pub async fn blob_link_index_add(
        &self,
        namespace: &str,
        reference: &LinkReference,
        digest: &Digest,
    ) -> Result<(), RegistryError> {
        let _ = RC_LOCK.lock().await;

        debug!("Registering reference: {:?}", reference);

        let _ = self
            .blob_link_index_update(namespace, digest, |index| {
                index.insert(reference.clone());
            })
            .await?;

        Ok(())
    }

    #[instrument]
    pub async fn blob_link_index_remove(
        &self,
        namespace: &str,
        reference: &LinkReference,
        digest: &Digest,
    ) -> Result<(), RegistryError> {
        let _ = RC_LOCK.lock().await;

        debug!("Unregistering reference: {:?}", reference);

        let references = self
            .blob_link_index_update(namespace, digest, |index| {
                index.remove(reference);
            })
            .await?;

        if references.is_empty() {
            debug!("Deleting empty reference index for digest: {}", digest);
            self.delete_blob(digest).await?;
        }

        Ok(())
    }

    #[instrument]
    pub async fn get_all_tags(&self, name: &str) -> Result<Vec<String>, RegistryError> {
        let path = self.tree.manifest_tags_dir(name);
        debug!("Listing tags in path: {}", path);
        let mut tags = self.collect_directory_entries(&path).await?;
        tags.sort();

        Ok(tags)
    }
}

#[async_trait]
impl StorageEngine for FileSystemStorageEngine {
    #[instrument]
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

    #[instrument]
    async fn list_tags(
        &self,
        name: &str,
        pagination: Option<(u32, String)>,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        let tags = self.get_all_tags(name).await?;

        if let Some((n, last)) = pagination {
            return Ok(paginate(&tags, n, last));
        }

        Ok((tags, None))
    }

    #[instrument]
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

            let Some(media_type) = manifest.media_type else {
                continue;
            };

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
                media_type,
                digest: manifest_digest.to_string(),
                size: raw_manifest.len() as u64,
                annotations: manifest.annotations,
                artifact_type: manifest.artifact_type,
            });
        }

        Ok(referrers)
    }

    #[instrument]
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

    #[instrument]
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

    #[instrument]
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
        let digest = hasher.finalize();
        let digest = Digest::Sha256(hex::encode(digest));

        Ok(UploadSummary { digest, size })
    }

    #[instrument]
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
                let digest = hasher.finalize();
                Digest::Sha256(hex::encode(digest))
            }
        };

        let blob_root = self.tree.blob_container_dir(&digest);
        fs::create_dir_all(&blob_root).await?;

        let blob_path = self.tree.blob_path(&digest);
        fs::rename(&upload_path, &blob_path).await?;
        self.blob_link_index_init(name, &digest).await?;

        self.delete_upload(name, uuid).await?;

        Ok(digest)
    }

    #[instrument]
    async fn delete_upload(&self, name: &str, uuid: Uuid) -> Result<(), RegistryError> {
        let path = self.tree.upload_container_path(name, &uuid);
        let _ = fs::remove_dir_all(&path).await;
        self.delete_empty_parent_dirs(&path).await
    }

    #[instrument]
    async fn create_blob(&self, content: &[u8]) -> Result<Digest, RegistryError> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher.finalize();
        let digest = Digest::Sha256(hex::encode(digest));

        let blob_root = self.tree.blob_container_dir(&digest);
        fs::create_dir_all(&blob_root).await?;

        let blob_path = self.tree.blob_path(&digest);
        fs::write(blob_path, content).await?;

        Ok(digest)
    }

    #[instrument]
    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, RegistryError> {
        let path = self.tree.blob_path(digest);
        fs::read(path).await.map_err(|e| e.into())
    }

    #[instrument]
    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, RegistryError> {
        let path = self.tree.blob_path(digest);
        self.get_file_size(&path)
            .await?
            .ok_or(RegistryError::BlobUnknown)
    }

    #[instrument]
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

    #[instrument]
    async fn delete_blob(&self, digest: &Digest) -> Result<(), RegistryError> {
        let path = self.tree.blob_container_dir(digest);
        fs::remove_dir_all(&path).await?;
        self.delete_empty_parent_dirs(&path).await
    }

    #[instrument]
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

    #[instrument]
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
        if fs::metadata(&link_path).await.is_err() {
            debug!("Creating link at path: {}", link_path);
            fs::write(&link_path, digest.to_string()).await?;

            debug!("Increasing reference count for digest: {}", digest);
            self.blob_link_index_add(namespace, reference, digest)
                .await?;
        }

        Ok(())
    }

    #[instrument]
    async fn delete_link(
        &self,
        namespace: &str,
        reference: &LinkReference,
    ) -> Result<(), RegistryError> {
        debug!(
            "Deleting link for namespace: {}, reference: {:?}",
            namespace, reference
        );
        let digest = match self.read_link(namespace, reference).await {
            Ok(digest) => digest,
            Err(RegistryError::NameUnknown) => return Ok(()),
            Err(e) => return Err(e),
        };

        let link_path = self.tree.get_link_path(reference, namespace);
        if fs::metadata(&link_path).await.is_err() {
            return Ok(());
        }

        let path = self.tree.get_link_container_path(reference, namespace);
        debug!("Deleting link at path: {}", path);
        let _ = fs::remove_dir_all(&path).await;
        self.delete_empty_parent_dirs(&path).await?;

        self.blob_link_index_remove(namespace, reference, &digest)
            .await
    }
}
