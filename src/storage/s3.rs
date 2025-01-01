use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::operation::head_object::HeadObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::builders::{CompletedMultipartUploadBuilder, CompletedPartBuilder};
use aws_sdk_s3::types::CompletedPart;
use aws_sdk_s3::{
    config::timeout::TimeoutConfig,
    config::{BehaviorVersion, Credentials, Region},
    Client as S3Client, Config as S3Config,
};
use chrono::{DateTime, Utc};
use sha2::{Digest as ShaDigestTrait, Sha256};
use tracing::{debug, error, instrument};

use crate::configuration::StorageS3Config;
use crate::error::RegistryError;
use crate::lock_manager::LockManager;
use crate::oci::{Descriptor, Digest, Manifest};
use crate::registry::LinkReference;
use crate::storage::tree_manager::TreeManager;
use crate::storage::{
    deserialize_hash_state, serialize_hash_empty_state, serialize_hash_state, BlobReferenceIndex,
    StorageEngine, StorageEngineReader, UploadSummary,
};

#[derive(Clone)]
pub struct S3StorageEngine {
    s3_client: S3Client,
    tree: Arc<TreeManager>,
    bucket: String,
    lock_manager: LockManager,
}

impl Debug for S3StorageEngine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3StorageEngine").finish()
    }
}

impl S3StorageEngine {
    pub fn new(config: &StorageS3Config, lock_manager: LockManager) -> Result<Self, RegistryError> {
        let credentials = Credentials::new(
            config.access_key_id.clone(),
            config.secret_key.clone(),
            None,
            None,
            "custom",
        );

        let timeout = TimeoutConfig::builder()
            .operation_timeout(Duration::from_secs(10))
            .operation_attempt_timeout(Duration::from_secs(10))
            .build();

        let s3_config = S3Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .endpoint_url(&config.endpoint)
            .credentials_provider(credentials)
            .timeout_config(timeout)
            .force_path_style(true)
            .build();

        let s3_client = S3Client::from_conf(s3_config);

        Ok(Self {
            s3_client,
            tree: Arc::new(TreeManager {
                root_dir: config.key_prefix.clone().unwrap_or_default(),
            }),
            bucket: config.bucket.clone(),
            lock_manager,
        })
    }

    #[instrument(skip(self))]
    async fn head_object(&self, key: &str) -> Result<HeadObjectOutput, RegistryError> {
        let res = self
            .s3_client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await;

        match res {
            Err(e) => {
                let service_error = e.into_service_error();

                if service_error.is_not_found() {
                    Err(RegistryError::NotFound)
                } else {
                    Err(RegistryError::InternalServerError(Some(
                        "Error head object".to_string(),
                    )))
                }
            }
            Ok(res) => Ok(res),
        }
    }

    #[instrument(skip(self))]
    async fn get_object(
        &self,
        key: &str,
        offset: Option<u64>,
    ) -> Result<GetObjectOutput, RegistryError> {
        let mut res = self.s3_client.get_object().bucket(&self.bucket).key(key);

        if let Some(offset) = offset {
            res = res.range(format!("bytes={}-", offset));
        }

        match res.send().await {
            Err(e) => {
                let service_error = e.into_service_error();
                if service_error.is_no_such_key() {
                    Err(RegistryError::NotFound)
                } else {
                    Err(RegistryError::InternalServerError(Some(
                        "Error get object".to_string(),
                    )))
                }
            }
            Ok(res) => Ok(res),
        }
    }

    #[instrument(skip(self))]
    async fn get_object_body_as_vec(
        &self,
        key: &str,
        offset: Option<u64>,
    ) -> Result<Vec<u8>, RegistryError> {
        let res = self.get_object(key, offset).await;

        let res = match res {
            Ok(res) => res,
            Err(RegistryError::NotFound) => return Err(RegistryError::NotFound),
            Err(e) => {
                error!("Error getting object: {}", e);
                return Err(RegistryError::InternalServerError(Some(
                    "Error getting object".to_string(),
                )));
            }
        };

        let body = res.body.collect().await.map_err(|e| {
            error!("Error reading object body: {}", e);
            RegistryError::InternalServerError(Some("Error reading object body".to_string()))
        })?;

        Ok(body.to_vec())
    }

    #[instrument(skip(self, data))]
    async fn put_object(&self, key: &str, data: Vec<u8>) -> Result<(), RegistryError> {
        self.s3_client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(data))
            .send()
            .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_object(&self, key: &str) -> Result<(), RegistryError> {
        self.s3_client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_object_with_prefix(&self, prefix: &str) -> Result<(), RegistryError> {
        debug!("Deleting objects with prefix: {}", prefix);

        let mut next_continuation_token = None;
        loop {
            let res = self
                .s3_client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .max_keys(1000);

            let res = match next_continuation_token.clone() {
                Some(token) => res.continuation_token(token).send().await,
                None => res.send().await,
            }?;

            for object in res.contents.unwrap_or_default() {
                if let Some(key) = object.key {
                    debug!("Deleting object: {}", key);
                    self.delete_object(&key).await?;
                }
            }

            if res.is_truncated.unwrap_or_default() {
                next_continuation_token = res.next_continuation_token;
            } else {
                break;
            }
        }

        Ok(())
    }

    #[instrument(skip(self, chunk))]
    async fn store_staged_chunk(
        &self,
        namespace: &str,
        upload_id: &str,
        chunk: Vec<u8>,
        offset: u64,
    ) -> Result<(), RegistryError> {
        let key = self
            .tree
            .upload_staged_container_path(namespace, upload_id, offset);
        self.put_object(&key, chunk.to_vec()).await
    }

    #[instrument(skip(self))]
    async fn load_staged_chunk(
        &self,
        namespace: &str,
        upload_id: &str,
        offset: u64,
    ) -> Result<Vec<u8>, RegistryError> {
        let key = self
            .tree
            .upload_staged_container_path(namespace, upload_id, offset);
        match self.get_object_body_as_vec(&key, None).await {
            Ok(data) => {
                self.delete_object(&key).await?;
                Ok(data)
            }
            Err(RegistryError::NotFound) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    #[instrument(skip(self, operation))]
    pub async fn blob_link_index_update<O>(
        &self,
        namespace: &str,
        digest: &Digest,
        operation: O,
    ) -> Result<bool, RegistryError>
    where
        O: FnOnce(&mut HashSet<LinkReference>),
    {
        let path = self.tree.blob_index_path(digest);

        let res = self.get_object_body_as_vec(&path, None).await;

        let mut reference_index = match res {
            Ok(data) => serde_json::from_slice::<BlobReferenceIndex>(&data)?,
            Err(_) => BlobReferenceIndex::default(),
        };

        let index = reference_index
            .namespace
            .entry(namespace.to_string())
            .or_insert_with(HashSet::new);

        operation(index);
        if index.is_empty() {
            reference_index.namespace.remove(namespace);
        }

        let is_referenced = !reference_index.namespace.is_empty();

        let content = serde_json::to_vec(&reference_index)?;
        self.put_object(&path, content).await?;

        Ok(is_referenced)
    }

    #[instrument(skip(self))]
    async fn search_multipart_upload_id(&self, key: &str) -> Result<Option<String>, RegistryError> {
        let mut next_key_marker = None;

        loop {
            let mut res = self
                .s3_client
                .list_multipart_uploads()
                .bucket(&self.bucket)
                .prefix(key);

            if let Some(key_marker) = next_key_marker.clone() {
                res = res.key_marker(key_marker);
            }

            let res = res.send().await?;
            if let Some(uploads) = res.uploads {
                for upload in uploads {
                    let s = upload.key.unwrap_or_default();
                    if s.as_str() == key {
                        return Ok(upload.upload_id);
                    }
                }
            }

            if res.is_truncated.unwrap_or_default() {
                next_key_marker = res.next_key_marker;
            } else {
                break;
            }
        }

        Ok(None)
    }

    #[instrument(skip(self))]
    async fn search_multipart_upload_parts(
        &self,
        key: &str,
        upload_id: &str,
    ) -> Result<(Vec<String>, u64), RegistryError> {
        let mut all_parts = Vec::new();
        let mut parts_size = 0;

        let mut part_number_marker: Option<String> = None;
        loop {
            let mut res = self
                .s3_client
                .list_parts()
                .bucket(&self.bucket)
                .key(key)
                .upload_id(upload_id);

            if let Some(marker) = part_number_marker {
                res = res.part_number_marker(marker);
            }

            let res = res.send().await?;

            let parts = res.parts.unwrap_or_default();
            parts_size += parts.iter().filter_map(|part| part.size).sum::<i64>() as u64;
            all_parts.extend(parts.iter().filter_map(|part| part.e_tag.clone()));

            if res.is_truncated.unwrap_or_default() {
                part_number_marker = res.next_part_number_marker;
            } else {
                break;
            }
        }

        Ok((all_parts, parts_size))
    }

    #[instrument(skip(self))]
    async fn create_multipart_upload(&self, path: &str) -> Result<String, RegistryError> {
        let res = self
            .s3_client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await?;

        let Some(upload_id) = res.upload_id else {
            error!("Error creating multipart upload: upload id not found");
            return Err(RegistryError::InternalServerError(Some(
                "Error creating multipart upload".to_string(),
            )));
        };

        Ok(upload_id)
    }

    #[instrument(skip(self, body))]
    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Vec<u8>,
    ) -> Result<String, RegistryError> {
        let body = ByteStream::from(body.to_vec());

        let res = self
            .s3_client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(body)
            .send()
            .await?;

        Ok(res.e_tag.unwrap_or_default())
    }

    #[instrument(skip(self))]
    async fn abort_pending_uploads(&self, key: &str) -> Result<(), RegistryError> {
        while let Some(upload_id) = self.search_multipart_upload_id(key).await? {
            let _ = self
                .s3_client
                .abort_multipart_upload()
                .bucket(&self.bucket)
                .key(key)
                .upload_id(upload_id)
                .send()
                .await?;
        }

        Ok(())
    }
}

#[async_trait]
impl StorageEngine for S3StorageEngine {
    #[instrument(skip(self))]
    async fn list_namespaces(
        &self,
        n: u32,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        debug!(
            "Fetching {} namespace(s) with continuation token: {:?}",
            n, last
        );
        let base_prefix = format!("{}/", self.tree.repository_dir());
        let base_prefix_len = base_prefix.len();

        let res = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&base_prefix)
            .delimiter("_");

        let res = match last {
            Some(last) => res.start_after(last),
            _ => res,
        };

        let res = res.max_keys(n as i32).send().await?;

        let mut repositories = Vec::new();
        for common_prefixes in res.common_prefixes.unwrap_or_default() {
            let Some(key) = common_prefixes.prefix else {
                continue;
            };

            let mut key = key[base_prefix_len..].to_string();
            if key.ends_with('_') {
                key = key.trim_end_matches('_').to_string();
            }
            if key.ends_with('/') {
                key = key.trim_end_matches('/').to_string();
            }

            repositories.push(key);
        }

        let next_last = match res.is_truncated {
            Some(true) => repositories.last().cloned(),
            _ => None,
        };

        Ok((repositories, next_last))
    }

    #[instrument(skip(self))]
    async fn list_tags(
        &self,
        namespace: &str,
        n: u32,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        debug!(
            "Listing {} tag(s) for namespace '{}' starting with continuation_token '{:?}'",
            n, namespace, last
        );
        let base_prefix = format!("{}/", self.tree.manifest_tags_dir(namespace));
        let base_prefix_len = base_prefix.len();

        let res = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&base_prefix)
            .delimiter("/")
            .max_keys(n as i32);

        let res = match last {
            Some(last) => res.start_after(last),
            _ => res,
        };

        let res = res.send().await?;

        let mut tags = Vec::new();
        for common_prefixes in res.common_prefixes.unwrap_or_default() {
            let Some(key) = common_prefixes.prefix else {
                continue;
            };

            let mut key = key[base_prefix_len..].to_string();
            if key.ends_with('/') {
                key = key.trim_end_matches('/').to_string();
            }
            tags.push(key);
        }

        let next_last = match res.is_truncated {
            Some(true) => tags.last().cloned(),
            _ => None,
        };

        Ok((tags, next_last))
    }

    #[instrument(skip(self))]
    async fn list_referrers(
        &self,
        namespace: &str,
        digest: &Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, RegistryError> {
        let base_prefix = format!("{}/", self.tree.manifest_referrers_dir(namespace, digest));
        let base_prefix_len = base_prefix.len();

        let mut referrers = Vec::new();

        let mut continuation_token = None;

        loop {
            let res = self
                .s3_client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&base_prefix)
                .max_keys(100)
                .set_continuation_token(continuation_token)
                .send()
                .await?;

            for object in res.contents.unwrap_or_default() {
                let Some(key) = object.key else {
                    continue;
                };

                let mut manifest_digest = key[base_prefix_len..].to_string();
                if manifest_digest.ends_with("/link") {
                    manifest_digest = manifest_digest.trim_end_matches("/link").to_string();
                }

                let manifest_digest = Digest::try_from(manifest_digest.as_str())?;
                let blob_path = self.tree.blob_path(&manifest_digest);

                let manifest = self.get_object_body_as_vec(&blob_path, None).await?;
                let manifest_len = manifest.len();
                let manifest = serde_json::from_slice::<Manifest>(&manifest)?;

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

            if res.is_truncated == Some(true) {
                continuation_token = res.next_continuation_token;
            } else {
                break;
            }
        }

        Ok(referrers)
    }

    #[instrument(skip(self))]
    async fn list_uploads(
        &self,
        namespace: &str,
        n: u32,
        continuation_token: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        debug!(
            "Fetching {} upload(s) for namespace '{}' with continuation token: {:?}",
            n, namespace, continuation_token
        );
        let base_prefix = format!("{}/", self.tree.uploads_root_dir(namespace));
        let base_prefix_len = base_prefix.len();

        let res = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&base_prefix)
            .delimiter("/")
            .max_keys(n as i32)
            .set_continuation_token(continuation_token)
            .send()
            .await?;

        let mut uploads = Vec::new();
        for common_prefixes in res.common_prefixes.unwrap_or_default() {
            let Some(key) = common_prefixes.prefix else {
                continue;
            };

            let mut key = key[base_prefix_len..].to_string();
            if key.ends_with('/') {
                key = key.trim_end_matches('/').to_string();
            }

            uploads.push(key);
        }

        let next_continuation_token = match res.is_truncated {
            Some(true) => res.next_continuation_token,
            _ => None,
        };

        Ok((uploads, next_continuation_token))
    }

    #[instrument(skip(self))]
    async fn list_blobs(
        &self,
        n: u32,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), RegistryError> {
        debug!(
            "Fetching {} blob(s) with continuation token: {:?}",
            n, continuation_token
        );
        let algorithm = "sha256";
        let path = self.tree.blobs_root_dir();

        let base_prefix = format!("{}/{}/", path, algorithm);
        let base_prefix_len = base_prefix.len();

        let res = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&base_prefix)
            .max_keys(n as i32)
            .set_continuation_token(continuation_token)
            .send()
            .await?;

        let mut blobs = Vec::new();

        for object in res.contents.unwrap_or_default() {
            let Some(key) = object.key else { continue };

            if !key.ends_with("data") {
                continue;
            }

            let key = key[..key.len() - 5].to_string();
            let key = key[base_prefix_len + 3..].to_string(); // +3 for the 2 char prefix + delimiter
            blobs.push(Digest::Sha256(key));
        }

        let next_last = match res.is_truncated {
            Some(true) => res.next_continuation_token,
            _ => None,
        };

        Ok((blobs, next_last))
    }

    async fn list_revisions(
        &self,
        namespace: &str,
        n: u32,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), RegistryError> {
        debug!(
            "Fetching {} revision(s) for namespace '{}' with continuation token: {:?}",
            n, namespace, continuation_token
        );
        let base_prefix = format!(
            "{}/",
            self.tree
                .manifest_revisions_link_root_dir(namespace, "sha256")
        );
        let base_prefix_len = base_prefix.len();

        let res = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&base_prefix)
            .delimiter("/")
            .max_keys(n as i32)
            .set_continuation_token(continuation_token)
            .send()
            .await?;

        let mut revisions = Vec::new();
        for common_prefixes in res.common_prefixes.unwrap_or_default() {
            let Some(key) = common_prefixes.prefix else {
                continue;
            };

            let mut key = key[base_prefix_len..].to_string();
            if key.ends_with('/') {
                key = key.trim_end_matches('/').to_string();
            }
            revisions.push(Digest::Sha256(key));
        }

        let next_last = match res.is_truncated {
            Some(true) => res.next_continuation_token,
            _ => None,
        };

        Ok((revisions, next_last))
    }

    #[instrument(skip(self))]
    async fn create_upload(&self, name: &str, uuid: &str) -> Result<String, RegistryError> {
        let date_path = self.tree.upload_start_date_path(name, uuid);
        let date = Utc::now().to_rfc3339();
        self.put_object(&date_path, date.into_bytes()).await?;

        let hash_state_path = self.tree.upload_hash_context_path(name, uuid, "sha256", 0);
        let state = serialize_hash_empty_state().await?;
        self.put_object(&hash_state_path, state).await?;

        Ok(uuid.to_string())
    }

    #[instrument(skip(self, source))]
    async fn write_upload(
        &self,
        name: &str,
        uuid: &str,
        source: &[u8],
        append: bool,
    ) -> Result<(), RegistryError> {
        let upload_path = self.tree.upload_path(name, uuid);

        let uploaded_size;
        let uploaded_parts;
        let upload_id;

        if append {
            upload_id = match self.search_multipart_upload_id(&upload_path).await? {
                Some(upload_id) => upload_id,
                None => self.create_multipart_upload(&upload_path).await?,
            };

            let (parts, parts_size) = self
                .search_multipart_upload_parts(&upload_path, &upload_id)
                .await?;

            uploaded_size = parts_size;
            uploaded_parts = parts.len() as i32;
        } else {
            self.abort_pending_uploads(&upload_path).await?;

            upload_id = self.create_multipart_upload(&upload_path).await?;
            uploaded_size = 0;
            uploaded_parts = 0;
        }

        let hasher_state_path =
            self.tree
                .upload_hash_context_path(name, uuid, "sha256", uploaded_size);
        let state = self
            .get_object_body_as_vec(&hasher_state_path, None)
            .await?;
        let mut hasher = deserialize_hash_state(state).await?;

        hasher.update(source);
        let source_len = source.len() as u64;

        let state = serialize_hash_state(&hasher).await?;
        let hash_state_path =
            self.tree
                .upload_hash_context_path(name, uuid, "sha256", uploaded_size + source_len);
        self.put_object(&hash_state_path, state).await?;

        // NOTE: if the part is not big enough (at least 5M, as per the S3 protocol),
        // store it in as a staging blob.
        // First, we load the staged chunk if any and append the new data
        let mut chunk = self.load_staged_chunk(name, uuid, uploaded_size).await?;
        chunk.extend(source);

        // If the chunk is still too small, store it again and return.
        // If there is no subsequent calls to this method, the chunk will be loaded back and stored
        // as last part in the complete_upload() method.
        if chunk.len() < 5 * 1024 * 1024 {
            self.store_staged_chunk(name, uuid, chunk, uploaded_size)
                .await?;
            return Ok(());
        }

        self.upload_part(&upload_path, &upload_id, uploaded_parts + 1, chunk)
            .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn read_upload_summary(
        &self,
        name: &str,
        uuid: &str,
    ) -> Result<UploadSummary, RegistryError> {
        let key = self.tree.upload_path(name, uuid);

        let mut size = 0;
        if let Ok(Some(upload_id)) = self.search_multipart_upload_id(&key).await {
            let (_, upload_size) = self.search_multipart_upload_parts(&key, &upload_id).await?;
            size = upload_size;
        };

        size += self
            .head_object(&self.tree.upload_staged_container_path(name, uuid, size))
            .await
            .ok()
            .map(|object| object.content_length.unwrap_or_default() as u64)
            .unwrap_or_default();

        let hash_state_path = self
            .tree
            .upload_hash_context_path(name, uuid, "sha256", size);
        let state = self.get_object_body_as_vec(&hash_state_path, None).await?;

        let hasher = deserialize_hash_state(state).await?;
        let digest = hasher.finalize();
        let digest = Digest::Sha256(hex::encode(digest));

        let date_path = self.tree.upload_start_date_path(name, uuid);
        let date = self.get_object_body_as_vec(&date_path, None).await?;
        let date = String::from_utf8(date)?;

        let start_date = DateTime::parse_from_rfc3339(&date)
            .ok()
            .unwrap_or_default() // Fallbacks to epoch
            .with_timezone(&Utc);

        // don't forget to count the staging blob
        let staged_path = self.tree.upload_staged_container_path(name, uuid, size);
        if let Ok(res) = self.head_object(&staged_path).await {
            size += res.content_length.unwrap_or_default() as u64;
        }

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
    ) -> Result<Digest, RegistryError> {
        let key = self.tree.upload_path(name, uuid);

        let Ok(Some(upload_id)) = self.search_multipart_upload_id(&key).await else {
            return Err(RegistryError::NotFound);
        };

        let (mut parts, mut size) = self.search_multipart_upload_parts(&key, &upload_id).await?;

        // load the staged chunk if any and create the last part
        let chunk = self.load_staged_chunk(name, uuid, size).await?;
        if !chunk.is_empty() {
            size += chunk.len() as u64;

            let e_tag = self
                .upload_part(&key, &upload_id, parts.len() as i32 + 1, chunk)
                .await?;

            parts.push(e_tag);
        }

        let digest = match digest {
            Some(digest) => digest,
            None => {
                let hash_state_path = self
                    .tree
                    .upload_hash_context_path(name, uuid, "sha256", size);

                let state = self.get_object_body_as_vec(&hash_state_path, None).await?;

                let hasher = deserialize_hash_state(state).await?;
                let existing_digest = hasher.finalize();
                Digest::Sha256(hex::encode(existing_digest))
            }
        };

        let _guard = self.lock_manager.write_lock(digest.to_string()).await;

        let blob_path = self.tree.blob_path(&digest);

        let parts = parts
            .iter()
            .enumerate()
            .map(|(i, etag)| {
                CompletedPartBuilder::default()
                    .part_number(i as i32 + 1)
                    .e_tag(etag.clone())
                    .build()
            })
            .collect::<Vec<CompletedPart>>();

        let _res = self
            .s3_client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(&key)
            .upload_id(upload_id)
            .multipart_upload(
                CompletedMultipartUploadBuilder::default()
                    .set_parts(Some(parts))
                    .build(),
            )
            .send()
            .await?;

        let _res = self
            .s3_client
            .copy_object()
            .bucket(&self.bucket)
            .key(&blob_path)
            .copy_source(format!("{}/{}", self.bucket, key))
            .send()
            .await?;

        self.blob_link_index_update(name, &digest, |_| {}).await?;

        // NOTE: in case of error, remaining parts will be deleted by the scrub job
        let key = self.tree.upload_container_path(name, uuid);
        let _ = self.delete_object_with_prefix(&key).await;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn delete_upload(&self, name: &str, uuid: &str) -> Result<(), RegistryError> {
        let upload_path = self.tree.upload_path(name, uuid);
        self.abort_pending_uploads(&upload_path).await?;

        let upload_path = self.tree.upload_container_path(name, uuid);
        self.delete_object_with_prefix(&upload_path).await
    }

    #[instrument(skip(self, content))]
    async fn create_blob(&self, content: &[u8]) -> Result<Digest, RegistryError> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher.finalize();
        let digest = Digest::Sha256(hex::encode(digest));

        let _guard = self.lock_manager.write_lock(digest.to_string()).await;

        let blob_path = self.tree.blob_path(&digest);
        self.put_object(&blob_path, content.to_vec()).await?;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, RegistryError> {
        let _guard = self.lock_manager.read_lock(digest.to_string()).await;
        let path = self.tree.blob_path(digest);
        let blob = self.get_object_body_as_vec(&path, None).await?;
        Ok(blob)
    }

    #[instrument(skip(self))]
    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobReferenceIndex, RegistryError> {
        let _guard = self.lock_manager.read_lock(digest.to_string()).await;
        let path = self.tree.blob_index_path(digest);

        let data = self.get_object_body_as_vec(&path, None).await?;
        let index = serde_json::from_slice(&data)?;

        Ok(index)
    }

    #[instrument(skip(self))]
    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, RegistryError> {
        let _guard = self.lock_manager.read_lock(digest.to_string()).await;
        let path = self.tree.blob_path(digest);

        let res = self.head_object(&path).await?;
        Ok(res.content_length.unwrap_or_default() as u64)
    }

    #[instrument(skip(self))]
    async fn build_blob_reader(
        &self,
        digest: &Digest,
        start_offset: Option<u64>,
    ) -> Result<Box<dyn StorageEngineReader>, RegistryError> {
        let _guard = self.lock_manager.read_lock(digest.to_string()).await;

        let path = self.tree.blob_path(digest);
        let res = self.get_object(&path, start_offset).await?;
        Ok(Box::new(res.body.into_async_read()))
    }

    #[instrument(skip(self))]
    async fn delete_blob(&self, digest: &Digest) -> Result<(), RegistryError> {
        let _guard = self.lock_manager.write_lock(digest.to_string()).await;

        let path = self.tree.blob_container_dir(digest);
        self.delete_object_with_prefix(&path).await
    }

    #[instrument(skip(self))]
    async fn read_link(
        &self,
        name: &str,
        reference: &LinkReference,
    ) -> Result<Digest, RegistryError> {
        let path = self.tree.get_link_path(reference, name);
        let data = self.get_object_body_as_vec(&path, None).await?;

        let link = String::from_utf8(data)?;
        Digest::try_from(link.as_str())
    }

    #[instrument(skip(self))]
    async fn create_link(
        &self,
        namespace: &str,
        reference: &LinkReference,
        digest: &Digest,
    ) -> Result<(), RegistryError> {
        match self.read_link(namespace, reference).await.ok() {
            Some(existing_digest) if existing_digest == *digest => return Ok(()),
            Some(existing_digest) if existing_digest != *digest => {
                self.delete_link(namespace, reference).await?;
            }
            _ => {}
        }

        let _guard = self.lock_manager.write_lock(digest.to_string()).await;

        let path = self.tree.get_link_path(reference, namespace);
        self.put_object(&path, digest.to_string().into_bytes())
            .await?;

        self.blob_link_index_update(namespace, digest, |index| {
            index.insert(reference.clone());
        })
        .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_link(
        &self,
        namespace: &str,
        reference: &LinkReference,
    ) -> Result<(), RegistryError> {
        let digest = match self.read_link(namespace, reference).await {
            Ok(digest) => digest,
            Err(RegistryError::NameUnknown) => return Ok(()),
            Err(e) => return Err(e),
        };

        let link_path = self.tree.get_link_path(reference, namespace);

        let _guard = self.lock_manager.write_lock(digest.to_string()).await;

        self.delete_object(&link_path).await?;

        let is_referenced = self
            .blob_link_index_update(namespace, &digest, |index| {
                index.remove(reference);
            })
            .await?;

        if !is_referenced {
            let path = self.tree.blob_container_dir(&digest);
            self.delete_object_with_prefix(&path).await?;
        }

        Ok(())
    }
}
