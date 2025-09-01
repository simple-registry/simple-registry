use crate::configuration::StorageFSConfig;
use crate::registry::blob_store::{BlobStore, Error, Reader};
use crate::registry::oci_types::Digest;
use crate::registry::reader::HashingReader;
use crate::registry::utils::sha256_ext::Sha256Ext;
use crate::registry::utils::DataPathBuilder;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sha2::{Digest as Sha256Digest, Sha256};
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
        f.debug_struct("FSBackend").finish()
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::StorageFSConfig;
    use crate::registry::blob_store::tests::{
        test_datastore_blob_operations, test_datastore_list_blobs, test_datastore_list_uploads,
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
    async fn test_blob_operations() {
        let (backend, _temp_dir) = create_test_backend();
        test_datastore_blob_operations(&backend).await;
    }

    #[tokio::test]
    async fn test_upload_operations() {
        let (backend, _temp_dir) = create_test_backend();
        test_datastore_upload_operations(&backend).await;
    }
}
