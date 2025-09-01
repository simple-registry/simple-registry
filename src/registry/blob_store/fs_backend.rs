use crate::configuration::StorageFSConfig;
use crate::registry::blob_store::{BlobStore, Error, LinkMetadata, Reader};
use crate::registry::oci_types::{Descriptor, Digest, Manifest};
use crate::registry::reader::HashingReader;
use crate::registry::utils::sha256_ext::Sha256Ext;
use crate::registry::utils::{BlobLink, BlobMetadata, DataPathBuilder};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sha2::{Digest as Sha256Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::io::{ErrorKind, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncRead, AsyncSeekExt, AsyncWriteExt};
use tracing::{debug, error, instrument};

#[derive(Clone)]
pub struct FSBackend {
    pub tree: Arc<DataPathBuilder>,
}

impl Debug for FSBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSystemStorageEngine").finish()
    }
}

impl FSBackend {
    pub fn new(config: StorageFSConfig) -> Self {
        Self {
            tree: Arc::new(DataPathBuilder::new(config.root_dir)),
        }
    }

    #[instrument]
    pub async fn get_file_size(&self, path: &str, not_found_error: Error) -> Result<u64, Error> {
        match fs::metadata(path).await {
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
        let mut read_dir = match fs::read_dir(path).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(entries),
            Err(e) => return Err(e.into()),
        };

        while let Ok(Some(entry)) = read_dir.next_entry().await {
            entries.push(entry.file_name().to_string_lossy().to_string());
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

            let mut entries = match fs::read_dir(parent_path).await {
                Ok(entries) => entries,
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e.into()),
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

    async fn write_file<P>(path: P, contents: &[u8]) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut file = File::create(&path).await?;
        file.write_all(contents).await?;
        file.sync_all().await?;

        Ok(())
    }

    async fn save_hasher(
        &self,
        name: &str,
        uuid: &str,
        offset: u64,
        state: Vec<u8>,
    ) -> Result<(), Error> {
        let hash_state_path = self
            .tree
            .upload_hash_context_path(name, uuid, "sha256", offset);

        Self::write_file(&hash_state_path, &state).await
    }

    async fn load_hasher(&self, name: &str, uuid: &str, offset: u64) -> Result<Sha256, Error> {
        let hash_state_path = self
            .tree
            .upload_hash_context_path(name, uuid, "sha256", offset);

        let state = fs::read(&hash_state_path).await?;
        Sha256::from_state(&state)
    }
}

#[async_trait]
impl BlobStore for FSBackend {
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

            let manifest = fs::read(&blob_path).await?;
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
        let content_path = self.tree.upload_path(name, uuid);
        Self::write_file(&content_path, &[]).await?;

        let date_path = self.tree.upload_start_date_path(name, uuid);
        Self::write_file(&date_path, Utc::now().to_rfc3339().as_bytes()).await?;

        let state = Sha256::new().serialized_state();
        self.save_hasher(name, uuid, 0, state).await?;

        Ok(uuid.to_string())
    }

    #[instrument(skip(self, stream))]
    async fn write_upload<S: AsyncRead + Unpin + Send + Sync>(
        &self,
        name: &str,
        uuid: &str,
        stream: S,
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
            .append(append)
            .write(true)
            .open(&file_path)
            .await
            .map_err(|error| {
                error!("Error opening upload file {file_path:}: {error}");
                match error.kind() {
                    ErrorKind::NotFound => Error::UploadNotFound,
                    _ => error.into(),
                }
            })?;
        file.seek(SeekFrom::Start(upload_size)).await?;

        let hasher = self.load_hasher(name, uuid, upload_size).await?;
        let mut reader = HashingReader::with_hasher(stream, hasher);

        let written = tokio::io::copy(&mut reader, &mut file).await?;

        self.save_hasher(name, uuid, upload_size + written, reader.serialized_state())
            .await?;

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

        let digest = self.load_hasher(name, uuid, size).await?.digest();

        let date = self.tree.upload_start_date_path(name, uuid);
        let date_str = fs::read_to_string(&date).await.unwrap_or_default();
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
            self.load_hasher(name, uuid, size).await?.digest()
        };

        let blob_root = self.tree.blob_container_dir(&digest);
        fs::create_dir_all(&blob_root).await?;

        let upload_path = self.tree.upload_path(name, uuid);
        let blob_path = self.tree.blob_path(&digest);
        fs::rename(&upload_path, &blob_path).await?;

        let path = self.tree.upload_container_path(name, uuid);
        let _ = self.delete_empty_parent_dirs(&path).await;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn delete_upload(&self, name: &str, uuid: &str) -> Result<(), Error> {
        let path = self.tree.upload_container_path(name, uuid);
        let _ = self.delete_empty_parent_dirs(&path).await;

        Ok(())
    }

    #[instrument(skip(self, content))]
    async fn create_blob(&self, content: &[u8]) -> Result<Digest, Error> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher.digest();

        let blob_path = self.tree.blob_path(&digest);
        Self::write_file(blob_path, content).await?;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, Error> {
        let path = self.tree.blob_path(digest);
        Ok(fs::read(&path).await?)
    }

    #[instrument(skip(self))]
    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobMetadata, Error> {
        let path = self.tree.blob_index_path(digest);
        let content = fs::read_to_string(&path).await?;

        let index = serde_json::from_str(&content)?;
        Ok(index)
    }

    async fn update_blob_index<O>(
        &self,
        namespace: &str,
        digest: &Digest,
        operation: O,
    ) -> Result<(), Error>
    where
        O: FnOnce(&mut HashSet<BlobLink>) + Send,
    {
        debug!("Ensuring container directory for digest: {digest}");
        let path = self.tree.blob_container_dir(digest);
        fs::create_dir_all(&path).await?;

        debug!("Updating reference count for digest: {digest}");
        let path = self.tree.blob_index_path(digest);

        let mut reference_index = match fs::read_to_string(&path).await.map_err(Error::from) {
            Ok(content) => serde_json::from_str::<BlobMetadata>(&content)?,
            Err(Error::ReferenceNotFound) => BlobMetadata::default(),
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
        }

        if reference_index.namespace.is_empty() {
            debug!("Deleting no longer referenced Blob: {digest}");
            let path = self.tree.blob_container_dir(digest);
            let _ = self.delete_empty_parent_dirs(&path).await;
        } else {
            debug!("Writing reference count to path: {path}");
            let content = serde_json::to_string(&reference_index)?;
            Self::write_file(&path, content.as_bytes()).await?;
            debug!("Reference index for {digest} updated");
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, Error> {
        let path = self.tree.blob_path(digest);
        self.get_file_size(&path, Error::BlobNotFound).await
    }

    #[instrument(skip(self))]
    async fn build_blob_reader(
        &self,
        digest: &Digest,
        start_offset: Option<u64>,
    ) -> Result<Box<dyn Reader>, Error> {
        let path = self.tree.blob_path(digest);
        let mut file = match File::open(&path).await {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(Error::BlobNotFound),
            Err(e) => return Err(e.into()),
        };

        if let Some(offset) = start_offset {
            file.seek(SeekFrom::Start(offset)).await?;
        }

        Ok(Box::new(file))
    }

    async fn read_link(&self, namespace: &str, link: &BlobLink) -> Result<LinkMetadata, Error> {
        let link_path = self.tree.get_link_path(link, namespace);

        let link = fs::read(&link_path).await?;
        Ok(LinkMetadata::from_bytes(link)?)
    }

    async fn write_link(
        &self,
        namespace: &str,
        link: &BlobLink,
        metadata: &LinkMetadata,
    ) -> Result<(), Error> {
        let link_path = self.tree.get_link_path(link, namespace);
        let serialized_link_data = serde_json::to_vec(metadata)?;
        Self::write_file(&link_path, &serialized_link_data).await
    }

    async fn delete_link(&self, namespace: &str, link: &BlobLink) -> Result<(), Error> {
        let path = self.tree.get_link_container_path(link, namespace);
        debug!("Deleting link at path: {path}");

        let _ = self.delete_empty_parent_dirs(&path).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::StorageFSConfig;
    use crate::registry::blob_store::tests::{
        test_datastore_blob_operations, test_datastore_link_operations, test_datastore_list_blobs,
        test_datastore_list_namespaces, test_datastore_list_referrers,
        test_datastore_list_revisions, test_datastore_list_tags, test_datastore_list_uploads,
        test_datastore_upload_operations,
    };
    use tempfile::TempDir;

    fn create_test_backend() -> (FSBackend, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let root_dir = temp_dir.path().to_str().unwrap().to_string();

        let config = StorageFSConfig { root_dir };

        let backend = FSBackend::new(config);

        (backend, temp_dir)
    }

    // Implementation-specific tests
    #[test]
    fn test_paginate() {
        let items: Vec<String> = vec![];
        let (result, token) = FSBackend::paginate(&items, 10, None);
        assert!(result.is_empty());
        assert!(token.is_none());

        let items: Vec<String> = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        let (result, token) = FSBackend::paginate(&items, 10, None);
        assert_eq!(result, items);
        assert!(token.is_none());

        let (page1, token1) = FSBackend::paginate(&items, 2, None);
        assert_eq!(page1, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(token1, Some("b".to_string()));

        let (page2, token2) = FSBackend::paginate(&items, 2, token1);
        assert_eq!(page2, vec!["c".to_string(), "d".to_string()]);
        assert_eq!(token2, None);

        let (page1, token1) = FSBackend::paginate(&items, 1, None);
        assert_eq!(page1, vec!["a".to_string()]);
        assert_eq!(token1, Some("a".to_string()));

        let (page2, token2) = FSBackend::paginate(&items, 1, token1);
        assert_eq!(page2, vec!["b".to_string()]);
        assert_eq!(token2, Some("b".to_string()));

        let (page3, token3) = FSBackend::paginate(&items, 1, token2);
        assert_eq!(page3, vec!["c".to_string()]);
        assert_eq!(token3, Some("c".to_string()));

        let (page4, token4) = FSBackend::paginate(&items, 1, token3);
        assert_eq!(page4, vec!["d".to_string()]);
        assert_eq!(token4, None);
    }

    #[tokio::test]
    async fn test_write_and_read_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path().join("test_file.txt");
        let test_content = b"Hello, world!";

        FSBackend::write_file(&test_path, test_content)
            .await
            .unwrap();
        assert!(test_path.exists());

        let content = fs::read(&test_path).await.unwrap();
        assert_eq!(content, test_content);

        let test_string = "Hello world!";
        FSBackend::write_file(&test_path, test_string.as_bytes())
            .await
            .unwrap();
        let string_content = fs::read_to_string(&test_path).await.unwrap();
        assert_eq!(string_content, test_string);
    }

    #[tokio::test]
    async fn test_collect_directory_entries() {
        let (backend, _) = create_test_backend();
        let namespace = "test-repo";

        let digest1 = backend.create_blob(b"content1").await.unwrap();
        let digest2 = backend.create_blob(b"content2").await.unwrap();

        backend
            .write_link(
                namespace,
                &BlobLink::Tag("file1.txt".to_string()),
                &LinkMetadata {
                    target: digest1,
                    ..LinkMetadata::default()
                },
            )
            .await
            .unwrap();
        backend
            .write_link(
                namespace,
                &BlobLink::Tag("file2.txt".to_string()),
                &LinkMetadata {
                    target: digest2,
                    ..LinkMetadata::default()
                },
            )
            .await
            .unwrap();

        let tags_dir = backend.tree.manifest_tags_dir(namespace);

        // Test the collect_directory_entries method
        let entries = backend.collect_directory_entries(&tags_dir).await.unwrap();

        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&"file1.txt".to_string()));
        assert!(entries.contains(&"file2.txt".to_string()));

        // Test empty directory case
        let empty_namespace = "empty-repo";
        let empty_tags_dir = backend.tree.manifest_tags_dir(empty_namespace);
        let empty_entries = backend.collect_directory_entries(&empty_tags_dir).await;
        assert_eq!(Ok(Vec::new()), empty_entries);

        // Test non-existent directory case
        let non_existent_dir = backend.tree.manifest_tags_dir("non-existent-repo");
        let non_existent_entries = backend.collect_directory_entries(&non_existent_dir).await;
        assert_eq!(Ok(Vec::new()), non_existent_entries);
    }

    #[tokio::test]
    async fn test_delete_empty_parent_dirs() {
        let (backend, temp_dir) = create_test_backend();

        let nested_dir = temp_dir.path().join("a/b/c/d");
        fs::create_dir_all(&nested_dir).await.unwrap();

        let test_file = nested_dir.join("test.txt");
        fs::write(&test_file, b"test").await.unwrap();

        fs::remove_file(&test_file).await.unwrap();

        backend
            .delete_empty_parent_dirs(nested_dir.to_str().unwrap())
            .await
            .unwrap();

        assert!(!nested_dir.exists());
        assert!(temp_dir.path().exists());
    }

    // Generic BlobStore trait tests
    #[tokio::test]
    async fn test_list_namespaces() {
        let (backend, _temp_dir) = create_test_backend();
        test_datastore_list_namespaces(&backend).await;
    }

    #[tokio::test]
    async fn test_list_tags() {
        let (backend, _temp_dir) = create_test_backend();
        test_datastore_list_tags(&backend).await;
    }

    #[tokio::test]
    async fn test_list_referrers() {
        let (backend, _temp_dir) = create_test_backend();
        test_datastore_list_referrers(&backend).await;
    }

    #[tokio::test]
    async fn test_list_uploads() {
        let (backend, _temp_dir) = create_test_backend();
        test_datastore_list_uploads(&backend).await;
    }

    #[tokio::test]
    async fn test_list_blobs() {
        let (backend, _temp_dir) = create_test_backend();
        test_datastore_list_blobs(&backend).await;
    }

    #[tokio::test]
    async fn test_list_revisions() {
        let (backend, _temp_dir) = create_test_backend();
        test_datastore_list_revisions(&backend).await;
    }

    #[tokio::test]
    async fn test_blob_operations() {
        let (backend, _temp_dir) = create_test_backend();
        test_datastore_blob_operations(&backend).await;
    }

    #[tokio::test]
    async fn test_upload_operations() {
        let (backend, _temp_dir) = create_test_backend();
        test_datastore_upload_operations(&backend).await;
    }

    #[tokio::test]
    async fn test_link_operations() {
        let (backend, _temp_dir) = create_test_backend();
        test_datastore_link_operations(&backend).await;
    }
}
