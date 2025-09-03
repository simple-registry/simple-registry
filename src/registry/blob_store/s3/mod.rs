#[cfg(test)]
pub mod tests;

use std::fmt::{Debug, Formatter};
use std::io::Cursor;

use crate::registry::blob_store::{BlobStore, Error, Reader};
use crate::registry::data_store;
use crate::registry::oci_types::Digest;
use crate::registry::reader::{ChunkedReader, HashingReader};
use crate::registry::utils::path_builder;
use crate::registry::utils::sha256_ext::Sha256Ext;
use async_trait::async_trait;
use bytes::Bytes;
use bytesize::ByteSize;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest as ShaDigestTrait, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
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
    #[serde(default = "BackendConfig::default_multipart_copy_threshold")]
    pub multipart_copy_threshold: ByteSize,
    #[serde(default = "BackendConfig::default_multipart_copy_chunk_size")]
    pub multipart_copy_chunk_size: ByteSize,
    #[serde(default = "BackendConfig::default_multipart_copy_jobs")]
    pub multipart_copy_jobs: usize,
    #[serde(default = "BackendConfig::default_multipart_part_size")]
    pub multipart_part_size: ByteSize,
}

impl BackendConfig {
    fn default_multipart_copy_threshold() -> ByteSize {
        ByteSize::gb(5)
    }

    fn default_multipart_copy_chunk_size() -> ByteSize {
        ByteSize::mb(100)
    }

    fn default_multipart_copy_jobs() -> usize {
        4
    }

    fn default_multipart_part_size() -> ByteSize {
        ByteSize::mib(10)
    }
}

#[derive(Clone)]
pub struct Backend {
    pub store: data_store::s3::Backend,
    multipart_part_size: usize,
}

impl Debug for Backend {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3StorageEngine").finish()
    }
}

impl Backend {
    pub fn new(config: BackendConfig) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let multipart_part_size = config.multipart_part_size.as_u64() as usize;
        let store = data_store::s3::Backend::new(config.into());

        Self {
            store,
            multipart_part_size,
        }
    }

    #[instrument(skip(self, chunk))]
    async fn store_staged_chunk(
        &self,
        namespace: &str,
        upload_id: &str,
        chunk: Bytes,
        offset: u64,
    ) -> Result<(), Error> {
        let key = path_builder::upload_staged_container_path(namespace, upload_id, offset);
        self.store.put_object(&key, chunk).await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn load_staged_chunk(
        &self,
        namespace: &str,
        upload_id: &str,
        offset: u64,
    ) -> Result<Vec<u8>, Error> {
        let key = path_builder::upload_staged_container_path(namespace, upload_id, offset);
        match self.store.get_object_body(&key, None).await {
            Ok(data) => Ok(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    async fn save_hasher(
        &self,
        name: &str,
        uuid: &str,
        offset: u64,
        state: Vec<u8>,
    ) -> Result<(), Error> {
        let hash_state_path = path_builder::upload_hash_context_path(name, uuid, "sha256", offset);

        self.store.put_object(&hash_state_path, state).await?;
        Ok(())
    }

    async fn load_hasher(&self, name: &str, uuid: &str, offset: u64) -> Result<Sha256, Error> {
        let hash_state_path = path_builder::upload_hash_context_path(name, uuid, "sha256", offset);

        let state = self.store.get_object_body(&hash_state_path, None).await?;
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
        debug!("Fetching {n} blob(s) with continuation token: {continuation_token:?}");
        let algorithm = "sha256";
        let path = path_builder::blobs_root_dir();
        let blob_prefix = format!("{path}/{algorithm}/");

        // For consistent pagination, we need to get all blobs matching our criteria first
        let mut all_blobs = Vec::new();
        let mut list_continuation_token = None;

        loop {
            let (objects, next_token) = self
                .store
                .list_objects(&blob_prefix, 1000, list_continuation_token)
                .await?;

            for key in objects {
                if !key.ends_with("/data") {
                    continue;
                }

                // Extract digest from path like "ab/abcd1234.../data"
                if key.ends_with("/data") {
                    let key_without_data = &key[..key.len() - 5];
                    if let Some(slash_pos) = key_without_data.rfind('/') {
                        let digest = &key_without_data[slash_pos + 1..];
                        all_blobs.push(Digest::Sha256(digest.to_string()));
                    }
                }
            }

            if let Some(token) = next_token {
                list_continuation_token = Some(token);
            } else {
                break;
            }
        }

        let start_idx = match &continuation_token {
            Some(token) => all_blobs
                .iter()
                .position(|digest| digest.to_string() > *token)
                .unwrap_or(all_blobs.len()),
            None => 0,
        };

        let end_idx = (start_idx + n as usize).min(all_blobs.len());
        let result_blobs = all_blobs[start_idx..end_idx].to_vec();

        let next_token = if end_idx < all_blobs.len() {
            result_blobs.last().map(ToString::to_string)
        } else {
            None
        };

        Ok((result_blobs, next_token))
    }

    #[instrument(skip(self))]
    async fn list_uploads(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        debug!("Fetching {n} upload(s) for namespace '{namespace}' with continuation token: {continuation_token:?}");
        let uploads_dir = path_builder::uploads_root_dir(namespace);

        let (prefixes, _, next_continuation_token) = self
            .store
            .list_prefixes(&uploads_dir, "/", i32::from(n), continuation_token)
            .await?;

        Ok((prefixes, next_continuation_token))
    }

    #[instrument(skip(self))]
    async fn create_upload(&self, name: &str, uuid: &str) -> Result<String, Error> {
        let date_path = path_builder::upload_start_date_path(name, uuid);
        self.store
            .put_object(&date_path, Utc::now().to_rfc3339())
            .await?;

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
        let upload_path = path_builder::upload_path(name, uuid);

        let upload_id = if append {
            match self.store.search_multipart_upload_id(&upload_path).await? {
                Some(id) => id,
                None => self.store.create_multipart_upload(&upload_path).await?,
            }
        } else {
            self.store.abort_pending_uploads(&upload_path).await?;
            self.store.create_multipart_upload(&upload_path).await?
        };

        let part_list = self.store.list_parts(&upload_path, &upload_id).await?;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let mut uploaded_size: u64 = part_list.iter().map(|(_, _, size)| *size as u64).sum();
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let mut uploaded_parts = (part_list.len() + 1) as i32;

        // NOTE: if the part is not big enough (at least 5M, as per the S3 protocol),
        // we store it in as a staging blob.
        // First, we load the staged chunk if any and append the new data
        let chunk = self.load_staged_chunk(name, uuid, uploaded_size).await?;
        let hasher = self.load_hasher(name, uuid, uploaded_size).await?;

        let reader = Cursor::new(chunk).chain(stream);
        let reader = HashingReader::with_hasher(reader, hasher);
        let mut reader = ChunkedReader::new(reader, self.multipart_part_size as u64);

        while let Some(mut chunk_reader) = reader.next_chunk() {
            let mut chunk = Vec::with_capacity(self.multipart_part_size);
            chunk_reader.read_to_end(&mut chunk).await?;
            let chunk = Bytes::from(chunk);
            let chunk_len = chunk.len() as u64;

            // We always need the full hash state for the upload summary
            self.save_hasher(
                name,
                uuid,
                uploaded_size + chunk_len,
                reader.serialized_state(),
            )
            .await?;

            // Last chunk for this write(), store remaining data in staging
            if chunk.len() < self.multipart_part_size {
                reader.mark_finished();
                self.store_staged_chunk(name, uuid, chunk, uploaded_size)
                    .await?;
            } else {
                self.store
                    .upload_part(&upload_path, &upload_id, uploaded_parts, chunk)
                    .await?;
                uploaded_size += chunk_len;
                uploaded_parts += 1;
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn read_upload_summary(
        &self,
        name: &str,
        uuid: &str,
    ) -> Result<(Digest, u64, DateTime<Utc>), Error> {
        let key = path_builder::upload_path(name, uuid);

        let mut size = 0u64;
        if let Some(upload_id) = self.store.search_multipart_upload_id(&key).await? {
            #[allow(clippy::cast_sign_loss)]
            for (_, _, part_size) in self.store.list_parts(&key, &upload_id).await? {
                size += part_size as u64;
            }
        }

        let staged_path = path_builder::upload_staged_container_path(name, uuid, size);
        if let Ok(staged_size) = self.store.object_size(&staged_path).await {
            size += staged_size;
        }

        let digest = self.load_hasher(name, uuid, size).await?.digest();

        let date_path = path_builder::upload_start_date_path(name, uuid);
        let date_bytes = self.store.get_object_body(&date_path, None).await?;
        let date_str = String::from_utf8_lossy(&date_bytes);
        let start_date = DateTime::parse_from_rfc3339(&date_str)
            .unwrap_or_else(|_| Utc::now().fixed_offset())
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
        let key = path_builder::upload_path(name, uuid);

        let Ok(Some(upload_id)) = self.store.search_multipart_upload_id(&key).await else {
            return Err(Error::UploadNotFound);
        };

        let part_list = self.store.list_parts(&key, &upload_id).await?;
        let mut size = part_list
            .iter()
            .map(|(_, _, s)| u64::try_from(*s).unwrap_or(0))
            .sum::<u64>();

        let source_key = path_builder::upload_staged_container_path(name, uuid, size);

        // Build parts list for completion
        let mut parts = Vec::new();
        for (part_num, e_tag, _) in part_list {
            parts.push(
                aws_sdk_s3::types::CompletedPart::builder()
                    .part_number(part_num)
                    .e_tag(e_tag)
                    .build(),
            );
        }

        // Add staged data as final part if it exists
        if let Ok(staged_size) = self.store.object_size(&source_key).await {
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let part_number = (parts.len() + 1) as i32;
            let e_tag = self
                .store
                .upload_part_copy(&source_key, &key, &upload_id, part_number, None)
                .await?;
            parts.push(
                aws_sdk_s3::types::CompletedPart::builder()
                    .part_number(part_number)
                    .e_tag(e_tag)
                    .build(),
            );
            size += staged_size;
        }

        let digest = digest.unwrap_or(self.load_hasher(name, uuid, size).await?.digest());

        self.store
            .complete_multipart_upload(&key, &upload_id, parts)
            .await?;

        let blob_path = path_builder::blob_path(&digest);
        self.store.copy_object(&key, &blob_path).await?;

        // NOTE: in case of error, remaining parts will be deleted by the scrub job
        let key = path_builder::upload_container_path(name, uuid);
        self.store.delete_prefix(&key).await?;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn delete_upload(&self, name: &str, uuid: &str) -> Result<(), Error> {
        let upload_path = path_builder::upload_path(name, uuid);
        self.store.abort_pending_uploads(&upload_path).await?;

        let upload_path = path_builder::upload_container_path(name, uuid);
        self.store.delete_prefix(&upload_path).await?;
        Ok(())
    }

    #[instrument(skip(self, content))]
    async fn create_blob(&self, content: &[u8]) -> Result<Digest, Error> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher.digest();

        let blob_path = path_builder::blob_path(&digest);
        self.store
            .put_object(&blob_path, Bytes::copy_from_slice(content))
            .await?;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, Error> {
        let path = path_builder::blob_path(digest);
        Ok(self.store.get_object_body(&path, None).await?)
    }

    #[instrument(skip(self))]
    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, Error> {
        let path = path_builder::blob_path(digest);
        match self.store.object_size(&path).await {
            Ok(size) => Ok(size),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::BlobNotFound),
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
        let res = self
            .store
            .get_object(&path, start_offset)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Error::BlobNotFound
                } else {
                    e.into()
                }
            })?;

        Ok(Box::new(res.body.into_async_read()))
    }
}
