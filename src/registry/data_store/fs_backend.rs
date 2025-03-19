use crate::configuration::StorageFSConfig;
use crate::registry::data_store::{BlobEntityLinkIndex, DataStore, Error, Reader, ReferenceInfo};
use crate::registry::lock_store::LockStore;
use crate::registry::oci_types::{Descriptor, Digest, Manifest};
use crate::registry::utils::sha256_ext::Sha256Ext;
use crate::registry::utils::{DataLink, DataPathBuilder};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use fs4::fs_std::FileExt;
use sha2::{Digest as Sha256Digest, Sha256};
use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::fs::{File, OpenOptions};
use std::io::Seek;
use std::io::Write;
use std::io::{ErrorKind, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fmt, fs};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_io_compat::CompatHelperTrait;
use tracing::{debug, error, instrument};

// NOTE: since async FS operations perform very poorly on most platforms, we choose to use standard
// synchronous IO operations as much as possible (while keeping reasonable complexity).

#[derive(Clone)]
pub struct FSBackend {
    lock_store: Arc<LockStore>,
    pub tree: Arc<DataPathBuilder>,
}

impl Debug for FSBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSystemStorageEngine").finish()
    }
}

const DIR_MANAGEMENT_LOCK_KEY: &str = "dir_management";

impl FSBackend {
    pub fn new(config: StorageFSConfig, lock_store: LockStore) -> Self {
        Self {
            tree: Arc::new(DataPathBuilder::new(config.root_dir)),
            lock_store: Arc::new(lock_store),
        }
    }

    #[instrument]
    pub async fn get_file_size(&self, path: &str, not_found_error: Error) -> Result<u64, Error> {
        match fs::metadata(path) {
            Ok(metadata) => Ok(metadata.len()),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(not_found_error),
            Err(e) => Err(e.into()),
        }
    }

    #[instrument]
    async fn collect_repositories(&self, base_path: &Path) -> Vec<String> {
        let mut path_stack: Vec<PathBuf> = vec![base_path.to_path_buf()];
        let mut repositories = Vec::new();

        while let Some(current_path) = path_stack.pop() {
            if let Ok(mut entries) = fs::read_dir(&current_path) {
                while let Some(Ok(entry)) = entries.next() {
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
                                        debug!("Found repository: {name}");
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
        let read_dir = match fs::read_dir(path) {
            Ok(rd) => rd,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(entries),
            Err(e) => return Err(e.into()),
        };

        for entry in read_dir {
            if let Some(name) = entry?.file_name().to_str() {
                entries.push(name.to_string());
            }
        }

        Ok(entries)
    }

    #[instrument]
    pub async fn delete_empty_parent_dirs(&self, path: &str) -> Result<(), Error> {
        let path = PathBuf::from(path);
        let root_dir = Path::new(&self.tree.prefix);

        let _ = fs::remove_dir_all(&path);

        let mut parent = path.parent();
        while let Some(parent_path) = parent {
            if parent_path == root_dir {
                break;
            }

            let Ok(mut entries) = fs::read_dir(parent_path) else {
                break;
            };

            if let Some(entry) = entries.next() {
                if entry.is_ok() {
                    break;
                }
            }

            debug!("Deleting empty parent dir: {}", parent_path.display());
            fs::remove_dir(parent_path)?;

            parent = parent_path.parent();
        }

        Ok(())
    }

    pub async fn blob_link_index_update<O>(
        &self,
        namespace: &str,
        digest: &Digest,
        operation: O,
    ) -> Result<(), Error>
    where
        O: FnOnce(&mut HashSet<DataLink>),
    {
        debug!("Ensuring container directory for digest: {digest}");
        let path = self.tree.blob_container_dir(digest);
        fs::create_dir_all(&path)?;

        debug!("Updating reference count for digest: {digest}");
        let path = self.tree.blob_index_path(digest);

        let mut reference_index = match Self::read_string(&path) {
            Ok(content) => serde_json::from_str::<BlobEntityLinkIndex>(&content)?,
            Err(Error::ReferenceNotFound) => BlobEntityLinkIndex::default(),
            Err(e) => Err(e)?,
        };

        debug!("Updating reference index");
        if let Some(index) = reference_index.namespace.get_mut(namespace) {
            operation(index);
            if index.is_empty() {
                reference_index.namespace.remove(namespace);
            }
        } else {
            let mut index = HashSet::new();
            operation(&mut index);
            if !index.is_empty() {
                reference_index
                    .namespace
                    .insert(namespace.to_string(), index);
            }
        };

        if reference_index.namespace.is_empty() {
            debug!("Deleting no longer referenced Blob: {digest}");
            let path = self.tree.blob_container_dir(digest);
            let _ = self.delete_empty_parent_dirs(&path).await;
        } else {
            debug!("Writing reference count to path: {path}");
            let content = serde_json::to_string(&reference_index)?;
            Self::write_file(&path, content.as_bytes())?;
            debug!("Reference index for {digest} updated");
        }

        Ok(())
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

    fn write_file<P>(path: P, contents: &[u8]) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = File::create(&path)?;
        file.lock_exclusive()?;

        let result = file.write_all(contents);

        #[allow(unstable_name_collisions)]
        let unlock_result = file.unlock();

        result.and(unlock_result)?;

        Ok(())
    }

    fn read_file<P>(path: P) -> Result<Vec<u8>, Error>
    where
        P: AsRef<Path>,
    {
        let file = File::open(&path)?;
        #[allow(unstable_name_collisions)]
        file.lock_shared()?;

        let result = fs::read(&path);

        #[allow(unstable_name_collisions)]
        let unlock_result = file.unlock();

        match result {
            Ok(content) => {
                unlock_result?;
                Ok(content)
            }
            Err(e) => {
                let _ = unlock_result;
                Err(e.into())
            }
        }
    }

    fn read_string<P>(path: P) -> Result<String, Error>
    where
        P: AsRef<Path>,
    {
        let file = File::open(&path)?;
        #[allow(unstable_name_collisions)]
        file.lock_shared()?;

        let result = fs::read_to_string(&path);

        #[allow(unstable_name_collisions)]
        let unlock_result = file.unlock();

        match result {
            Ok(content) => {
                unlock_result?;
                Ok(content)
            }
            Err(e) => {
                let _ = unlock_result;
                Err(e.into())
            }
        }
    }
}

#[async_trait]
impl DataStore for FSBackend {
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
        debug!("Listing tags in path: {path}");
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
        let path = format!(
            "{}/sha256",
            self.tree.manifest_referrers_dir(namespace, digest)
        );
        let all_manifest = self.collect_directory_entries(&path).await?;
        let mut referrers = Vec::new();

        for manifest_digest in all_manifest {
            let manifest_digest = Digest::Sha256(manifest_digest);
            let blob_path = self.tree.blob_path(&manifest_digest);

            let manifest = fs::read(&blob_path)?;
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

    #[instrument(skip(self))]
    async fn list_uploads(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        let path = self.tree.uploads_root_dir(namespace);
        let uploads: Vec<_> = self
            .collect_directory_entries(&path)
            .await?
            .into_iter()
            .collect();

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
            .lock_store
            .acquire_write_lock(DIR_MANAGEMENT_LOCK_KEY)
            .await;
        let content_path = self.tree.upload_path(name, uuid);
        Self::write_file(&content_path, &[])?;

        let date_path = self.tree.upload_start_date_path(name, uuid);
        Self::write_file(&date_path, Utc::now().to_rfc3339().as_bytes())?;

        let path = self.tree.upload_hash_context_path(name, uuid, "sha256", 0);
        Self::write_file(&path, &Sha256::serialized_empty_state())?;

        Ok(uuid.to_string())
    }

    #[instrument(skip(self, stream))]
    async fn write_upload<S: AsyncRead + Unpin + Send + Sync>(
        &self,
        name: &str,
        uuid: &str,
        mut stream: S,
        append: bool,
    ) -> Result<(), Error> {
        let upload_size = if append {
            let path = self.tree.upload_path(name, uuid);
            self.get_file_size(&path, Error::UploadNotFound).await?
        } else {
            0
        };

        let file_path = self.tree.upload_path(name, uuid);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .append(false)
            .write(true)
            .open(&file_path)
            .map_err(|error| {
                error!("Error opening upload file {file_path:}: {error}");
                match error.kind() {
                    ErrorKind::NotFound => Error::UploadNotFound,
                    _ => error.into(),
                }
            })?;

        file.lock_exclusive()?;
        file.seek(SeekFrom::Start(upload_size))?;

        let path = self
            .tree
            .upload_hash_context_path(name, uuid, "sha256", upload_size);
        let hash_state = Self::read_file(&path)?;
        let mut hash = Sha256::deserialize_state(&hash_state)?;

        // poll the stream asynchronously and synchronously write to the file
        let mut buffer = vec![0; 8192];
        let mut wrote_size = 0;

        let result = async {
            while let Ok(size) = stream.read(&mut buffer).await {
                if size == 0 {
                    break;
                }
                file.write_all(&buffer[..size])?;
                hash.update(&buffer[..size]);
                wrote_size += size as u64;
            }
            Ok::<_, Error>(())
        }
        .await;

        #[allow(unstable_name_collisions)]
        let unlock_result = file.unlock();

        result?;
        unlock_result?;

        let path =
            self.tree
                .upload_hash_context_path(name, uuid, "sha256", upload_size + wrote_size);
        Self::write_file(&path, &hash.serialize_state())?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn read_upload_summary(
        &self,
        name: &str,
        uuid: &str,
    ) -> Result<(Digest, u64, DateTime<Utc>), Error> {
        let path = self.tree.upload_path(name, uuid);
        let size = self.get_file_size(&path, Error::UploadNotFound).await?;

        let path = self
            .tree
            .upload_hash_context_path(name, uuid, "sha256", size);
        let state = Self::read_file(&path)?;

        let hasher = Sha256::deserialize_state(&state)?;
        let digest = hasher.to_digest();

        let date = self.tree.upload_start_date_path(name, uuid);
        let date_str = Self::read_string(&date).unwrap_or_default();
        let start_date = DateTime::parse_from_rfc3339(&date_str)
            .ok()
            .unwrap_or_default() // Fallbacks to epoch
            .with_timezone(&Utc);

        Ok((digest, size, start_date))
    }

    #[instrument(skip(self))]
    async fn complete_upload(
        &self,
        name: &str,
        uuid: &str,
        digest: Option<Digest>,
    ) -> Result<Digest, Error> {
        let path = self.tree.upload_path(name, uuid);
        let size = self.get_file_size(&path, Error::UploadNotFound).await?;

        let digest = if let Some(digest) = digest {
            digest
        } else {
            let path = self
                .tree
                .upload_hash_context_path(name, uuid, "sha256", size);
            let state = Self::read_file(&path)?;
            let hasher = Sha256::deserialize_state(&state)?;
            hasher.to_digest()
        };

        let _digest_guard = self
            .lock_store
            .acquire_write_lock(&digest.to_string())
            .await;

        let _guard = self
            .lock_store
            .acquire_write_lock(DIR_MANAGEMENT_LOCK_KEY)
            .await;
        let blob_root = self.tree.blob_container_dir(&digest);
        fs::create_dir_all(&blob_root)?;

        let upload_path = self.tree.upload_path(name, uuid);
        let blob_path = self.tree.blob_path(&digest);
        fs::rename(&upload_path, &blob_path)?;

        let path = self.tree.upload_container_path(name, uuid);
        let _ = self.delete_empty_parent_dirs(&path).await;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn delete_upload(&self, name: &str, uuid: &str) -> Result<(), Error> {
        let _guard = self
            .lock_store
            .acquire_write_lock(DIR_MANAGEMENT_LOCK_KEY)
            .await;

        let path = self.tree.upload_container_path(name, uuid);
        let _ = self.delete_empty_parent_dirs(&path).await;

        Ok(())
    }

    #[instrument(skip(self, content))]
    async fn create_blob(&self, content: &[u8]) -> Result<Digest, Error> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher.to_digest();

        let _digest_guard = self
            .lock_store
            .acquire_write_lock(&digest.to_string())
            .await;

        let _guard = self
            .lock_store
            .acquire_write_lock(DIR_MANAGEMENT_LOCK_KEY)
            .await;

        let blob_path = self.tree.blob_path(&digest);
        Self::write_file(blob_path, content)?;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, Error> {
        let path = self.tree.blob_path(digest);
        Self::read_file(path)
    }

    #[instrument(skip(self))]
    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobEntityLinkIndex, Error> {
        let path = self.tree.blob_index_path(digest);
        let content = Self::read_string(&path)?;

        let index = serde_json::from_str(&content)?;
        Ok(index)
    }

    #[instrument(skip(self))]
    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, Error> {
        let path = self.tree.blob_path(digest);
        self.get_file_size(&path, Error::BlobNotFound).await
    }

    #[instrument(skip(self))]
    async fn read_reference_info(
        &self,
        name: &str,
        reference: &DataLink,
    ) -> Result<ReferenceInfo, Error> {
        let key = match reference {
            DataLink::Tag(_) | DataLink::Digest(_) => self.tree.get_link_path(reference, name),
            _ => return Err(Error::ReferenceNotFound),
        };

        let metadata = fs::metadata(&key)?;

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
        let path = self.tree.blob_path(digest);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(Error::BlobNotFound),
            Err(e) => return Err(e.into()),
        };

        if let Some(offset) = start_offset {
            file.seek(SeekFrom::Start(offset))?;
        }

        Ok(Box::new(file.tokio_io()))
    }

    #[instrument(skip(self))]
    async fn delete_blob(&self, digest: &Digest) -> Result<(), Error> {
        let _digest_guard = self
            .lock_store
            .acquire_write_lock(&digest.to_string())
            .await;
        let _guard = self
            .lock_store
            .acquire_write_lock(DIR_MANAGEMENT_LOCK_KEY)
            .await;

        let path = self.tree.blob_container_dir(digest);
        let _ = self.delete_empty_parent_dirs(&path).await;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn update_last_pulled(
        &self,
        name: &str,
        tag: Option<String>,
        digest: &Digest,
    ) -> Result<(), Error> {
        if let Some(tag) = tag {
            let path = self.tree.get_link_path(&DataLink::Tag(tag), name);
            let _ = fs::metadata(&path)?;
        }

        let path = self
            .tree
            .get_link_path(&DataLink::Digest(digest.clone()), name);
        let _ = fs::metadata(&path)?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn read_link(&self, name: &str, reference: &DataLink) -> Result<Digest, Error> {
        debug!("Reading link for namespace: {name}, reference: {reference}");
        let path = self.tree.get_link_path(reference, name);
        debug!("Reading link at path: {path}");

        let link = Self::read_string(path)?;
        debug!("Link content: {link}");

        Ok(Digest::try_from(link.as_str())?)
    }

    #[instrument(skip(self))]
    async fn create_link(
        &self,
        namespace: &str,
        reference: &DataLink,
        digest: &Digest,
    ) -> Result<(), Error> {
        debug!("Creating or updating link for namespace: {namespace}, reference: {reference}");

        let _digest_guard = self
            .lock_store
            .acquire_write_lock(&digest.to_string())
            .await;
        let _guard = self
            .lock_store
            .acquire_write_lock(DIR_MANAGEMENT_LOCK_KEY)
            .await;

        let link_path = self.tree.get_link_path(reference, namespace);

        match self.read_link(namespace, reference).await.ok() {
            Some(existing_digest) if &existing_digest == digest => return Ok(()),
            Some(existing_digest) if &existing_digest != digest => {
                let _existing_digest_guard = self
                    .lock_store
                    .acquire_write_lock(&existing_digest.to_string())
                    .await;

                self.blob_link_index_update(namespace, digest, |index| {
                    index.remove(reference);
                })
                .await?;
            }
            _ => {}
        }

        debug!("Creating link at path: {link_path}");
        Self::write_file(&link_path, digest.to_string().as_bytes())?;

        debug!("Increasing reference count for digest: {digest}");

        self.blob_link_index_update(namespace, digest, |index| {
            index.insert(reference.clone());
        })
        .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_link(&self, namespace: &str, reference: &DataLink) -> Result<(), Error> {
        debug!("Deleting link for namespace: {namespace}, reference: {reference}");

        let digest = match self.read_link(namespace, reference).await {
            Ok(digest) => digest,
            Err(Error::ReferenceNotFound) => return Ok(()),
            Err(e) => return Err(e),
        };

        let _digest_guard = self
            .lock_store
            .acquire_write_lock(&digest.to_string())
            .await;
        let _guard = self
            .lock_store
            .acquire_write_lock(DIR_MANAGEMENT_LOCK_KEY)
            .await;

        let link_path = self.tree.get_link_path(reference, namespace);
        if fs::metadata(&link_path).is_err() {
            return Ok(());
        }

        let path = self.tree.get_link_container_path(reference, namespace);
        debug!("Deleting link at path: {path}");

        let _ = self.delete_empty_parent_dirs(&path).await;

        debug!("Unregistering reference: {reference}");
        self.blob_link_index_update(namespace, &digest, |index| {
            index.remove(reference);
        })
        .await?;

        Ok(())
    }
}
