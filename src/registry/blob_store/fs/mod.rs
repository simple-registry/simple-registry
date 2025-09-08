#[cfg(test)]
pub mod tests;

use crate::registry::blob_store::{BlobStore, Error, Reader};
use crate::registry::data_store;
use crate::registry::oci::Digest;
use crate::registry::reader::HashingReader;
use crate::registry::utils::path_builder;
use crate::registry::utils::sha256_ext::Sha256Ext;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest as Sha256Digest, Sha256};
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::io::{ErrorKind, SeekFrom};
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncSeekExt};
use tracing::{error, instrument};

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct BackendConfig {
    pub root_dir: String,
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
}

impl Debug for Backend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FSBackend").finish()
    }
}

impl Backend {
    pub fn new(config: BackendConfig) -> Self {
        Self {
            store: data_store::fs::Backend::new(config.into()),
        }
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

    async fn save_hasher(
        &self,
        name: &str,
        uuid: &str,
        offset: u64,
        state: &[u8],
    ) -> Result<(), Error> {
        let state_path = path_builder::upload_hash_context_path(name, uuid, "sha256", offset);
        self.store.write(&state_path, state).await?;
        Ok(())
    }

    async fn load_hasher(&self, name: &str, uuid: &str, offset: u64) -> Result<Sha256, Error> {
        let hash_state_path = path_builder::upload_hash_context_path(name, uuid, "sha256", offset);
        let state = self.store.read(&hash_state_path).await?;
        Sha256::from_state(&state)
    }
}

#[async_trait]
impl BlobStore for Backend {
    #[instrument(skip(self))]
    async fn list_blobs(
        &self,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error> {
        let path = PathBuf::new()
            .join(path_builder::blobs_root_dir())
            .join("sha256")
            .to_string_lossy()
            .to_string();

        let all_prefixes = self.store.list_dir(&path).await?;

        let mut digests = Vec::new();

        for prefix in all_prefixes {
            let blob_path = PathBuf::from(&path)
                .join(&prefix)
                .to_string_lossy()
                .to_string();

            let all_digests = self.store.list_dir(&blob_path).await?;

            for digest in all_digests {
                digests.push(Digest::Sha256(digest));
            }
        }

        Ok(Self::paginate(&digests, n, continuation_token))
    }

    #[instrument(skip(self))]
    async fn list_uploads(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        let path = path_builder::uploads_root_dir(namespace);
        let uploads = self.store.list_dir(&path).await?;

        Ok(Self::paginate(&uploads, n, continuation_token))
    }

    #[instrument(skip(self))]
    async fn create_upload(&self, name: &str, uuid: &str) -> Result<String, Error> {
        let content_path = path_builder::upload_path(name, uuid);
        self.store.write(&content_path, &[]).await?;

        let date_path = path_builder::upload_start_date_path(name, uuid);
        self.store
            .write(&date_path, Utc::now().to_rfc3339().as_bytes())
            .await?;

        let state = Sha256::new().serialized_state();
        self.save_hasher(name, uuid, 0, &state).await?;

        Ok(uuid.to_string())
    }

    #[instrument(skip(self, stream))]
    async fn write_upload(
        &self,
        name: &str,
        uuid: &str,
        stream: Box<dyn AsyncRead + Unpin + Send + Sync>,
        append: bool,
    ) -> Result<(), Error> {
        let upload_size = if append {
            let path = path_builder::upload_path(name, uuid);
            match self.store.file_size(&path).await {
                Ok(size) => size,
                Err(e) if e.kind() == ErrorKind::NotFound => return Err(Error::UploadNotFound),
                Err(e) => return Err(e.into()),
            }
        } else {
            0
        };

        let file_path = path_builder::upload_path(name, uuid);
        let mut file = if append {
            self.store.open_file_append(&file_path).await
        } else {
            self.store.create_file(&file_path).await
        }
        .map_err(|error| {
            error!("Error opening upload file {file_path}: {error}");
            match error.kind() {
                ErrorKind::NotFound => Error::UploadNotFound,
                _ => error.into(),
            }
        })?;
        file.seek(SeekFrom::Start(upload_size)).await?;

        let hasher = self.load_hasher(name, uuid, upload_size).await?;
        let mut reader = HashingReader::with_hasher(stream, hasher);

        let written = tokio::io::copy(&mut reader, &mut file).await?;

        self.save_hasher(
            name,
            uuid,
            upload_size + written,
            &reader.serialized_state(),
        )
        .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn read_upload_summary(
        &self,
        name: &str,
        uuid: &str,
    ) -> Result<(Digest, u64, DateTime<Utc>), Error> {
        let path = path_builder::upload_path(name, uuid);
        let size = match self.store.file_size(&path).await {
            Ok(size) => size,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(Error::UploadNotFound),
            Err(e) => return Err(e.into()),
        };

        let digest = self.load_hasher(name, uuid, size).await?.digest();

        let date = path_builder::upload_start_date_path(name, uuid);
        let date_str = self.store.read_to_string(&date).await.unwrap_or_default();
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
        let path = path_builder::upload_path(name, uuid);
        let size = match self.store.file_size(&path).await {
            Ok(size) => size,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(Error::UploadNotFound),
            Err(e) => return Err(e.into()),
        };

        let digest = if let Some(digest) = digest {
            digest
        } else {
            self.load_hasher(name, uuid, size).await?.digest()
        };

        let upload_path = path_builder::upload_path(name, uuid);
        let blob_path = path_builder::blob_path(&digest);
        self.store.rename(&upload_path, &blob_path).await?;

        let path = path_builder::upload_container_path(name, uuid);
        self.store.delete_dir(&path).await?;
        let _ = self.store.delete_empty_parent_dirs(&path).await;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn delete_upload(&self, name: &str, uuid: &str) -> Result<(), Error> {
        let path = path_builder::upload_container_path(name, uuid);
        self.store.delete_dir(&path).await?;
        self.store.delete_empty_parent_dirs(&path).await?;
        Ok(())
    }

    #[instrument(skip(self, content))]
    async fn create_blob(&self, content: &[u8]) -> Result<Digest, Error> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher.digest();

        let blob_path = path_builder::blob_path(&digest);
        self.store.write(&blob_path, content).await?;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, Error> {
        let path = path_builder::blob_path(digest);
        Ok(self.store.read(&path).await?)
    }

    #[instrument(skip(self))]
    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, Error> {
        let path = path_builder::blob_path(digest);
        match self.store.file_size(&path).await {
            Ok(size) => Ok(size),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(Error::BlobNotFound),
            Err(e) => Err(e.into()),
        }
    }

    #[instrument(skip(self))]
    async fn build_blob_reader(
        &self,
        digest: &Digest,
        start_offset: Option<u64>,
    ) -> Result<Box<dyn Reader>, Error> {
        let path = path_builder::blob_path(digest);
        let mut file = match self.store.open_file(&path).await {
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
