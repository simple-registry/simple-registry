use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::operation::head_object::HeadObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::builders::{CompletedMultipartUploadBuilder, CompletedPartBuilder};
use aws_sdk_s3::types::{CompletedPart, MetadataDirective};
use aws_sdk_s3::{
    config::timeout::TimeoutConfig,
    config::{BehaviorVersion, Credentials, Region},
    Client as S3Client, Config as S3Config,
};
use chrono::{DateTime, Utc};
use futures_util::future::try_join_all;
use sha2::{Digest as ShaDigestTrait, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::Semaphore;
use tracing::{debug, error, instrument};

use crate::configuration::StorageS3Config;
use crate::registry::data_store::{BlobEntityLinkIndex, DataStore, Error, Reader, ReferenceInfo};
use crate::registry::lock_store::LockStore;
use crate::registry::oci_types::{Descriptor, Digest, Manifest};
use crate::registry::utils::sha256_ext::Sha256Ext;
use crate::registry::utils::{DataLink, DataPathBuilder};

const PUSHED_AT_METADATA_KEY: &str = "pushed";
const LAST_PULLED_AT_METADATA_KEY: &str = "last-pulled";

#[derive(Clone)]
pub struct S3Backend {
    s3_client: S3Client,
    tree: Arc<DataPathBuilder>,
    bucket: String,
    lock_store: Arc<LockStore>,
    multipart_copy_threshold: u64,
    multipart_copy_chunk_size: u64,
    multipart_copy_jobs: usize,
    multipart_part_size: u64,
}

impl Debug for S3Backend {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3StorageEngine").finish()
    }
}

impl S3Backend {
    pub fn new(config: StorageS3Config, lock_store: LockStore) -> Self {
        let credentials = Credentials::new(
            config.access_key_id,
            config.secret_key,
            None,
            None,
            "custom",
        );

        let timeout = TimeoutConfig::builder()
            .operation_timeout(Duration::from_secs(10))
            .operation_attempt_timeout(Duration::from_secs(10))
            .build();

        let client_config = S3Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(config.region))
            .endpoint_url(config.endpoint)
            .credentials_provider(credentials)
            .timeout_config(timeout)
            .force_path_style(true)
            .build();

        let s3_client = S3Client::from_conf(client_config);

        Self {
            s3_client,
            tree: Arc::new(DataPathBuilder::new(config.key_prefix.unwrap_or_default())),
            bucket: config.bucket,
            lock_store: Arc::new(lock_store),
            multipart_copy_threshold: config.multipart_copy_threshold.to_u64(),
            multipart_copy_chunk_size: config.multipart_copy_chunk_size.to_u64(),
            multipart_copy_jobs: config.multipart_copy_jobs,
            multipart_part_size: config.multipart_part_size.to_u64(),
        }
    }

    #[instrument(skip(self))]
    async fn head_object(&self, key: &str) -> Result<HeadObjectOutput, Error> {
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
                    Err(Error::ReferenceNotFound)
                } else {
                    Err(service_error.into())
                }
            }
            Ok(res) => Ok(res),
        }
    }

    async fn get_object_size(&self, key: &str) -> Result<u64, Error> {
        let res = self.head_object(key).await?;

        let content_length = res
            .content_length()
            .and_then(|content_length| u64::try_from(content_length).ok())
            .unwrap_or_default();

        Ok(content_length)
    }

    #[instrument(skip(self))]
    async fn get_object(&self, key: &str, offset: Option<u64>) -> Result<GetObjectOutput, Error> {
        let mut res = self.s3_client.get_object().bucket(&self.bucket).key(key);

        if let Some(offset) = offset {
            res = res.range(format!("bytes={offset}-"));
        }

        match res.send().await {
            Err(e) => {
                let service_error = e.into_service_error();
                if service_error.is_no_such_key() {
                    Err(Error::ReferenceNotFound)
                } else {
                    Err(service_error.into())
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
    ) -> Result<Vec<u8>, Error> {
        let res = self.get_object(key, offset).await?;

        let body = res.body.collect().await?;
        Ok(body.to_vec())
    }

    #[instrument(skip(self, data))]
    async fn put_object(&self, key: &str, data: Vec<u8>) -> Result<(), Error> {
        self.s3_client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .metadata(PUSHED_AT_METADATA_KEY, Utc::now().to_rfc3339())
            .body(ByteStream::from(data))
            .send()
            .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_object(&self, key: &str) -> Result<(), Error> {
        self.s3_client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_object_with_prefix(&self, prefix: &str) -> Result<(), Error> {
        debug!("Deleting objects with prefix: {}", prefix);

        let mut next_continuation_token = None;
        loop {
            let res = self
                .s3_client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .max_keys(1000);

            let res = match next_continuation_token {
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
    ) -> Result<(), Error> {
        let key = self
            .tree
            .upload_staged_container_path(namespace, upload_id, offset);
        self.put_object(&key, chunk.clone()).await
    }

    #[instrument(skip(self))]
    async fn load_staged_chunk(
        &self,
        namespace: &str,
        upload_id: &str,
        offset: u64,
    ) -> Result<Vec<u8>, Error> {
        let key = self
            .tree
            .upload_staged_container_path(namespace, upload_id, offset);
        match self.get_object_body_as_vec(&key, None).await {
            Ok(data) => {
                self.delete_object(&key).await?;
                Ok(data)
            }
            Err(Error::ReferenceNotFound) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    async fn multipart_copy_object(
        &self,
        destination: &str,
        source: &str,
        content_length: u64,
    ) -> Result<(), Error> {
        debug!(
            "Copying object '{}' to '{}' using multipart upload (max {} jobs)",
            source, destination, self.multipart_copy_jobs
        );
        let res = self
            .s3_client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(destination)
            .send()
            .await?;

        let Some(upload_id) = res.upload_id else {
            error!("Error creating multipart upload: upload id not found");
            return Err(Error::StorageBackend(
                "Error creating multipart upload".to_string(),
            ));
        };

        let mut offsets = Vec::new();
        let mut offset = 0;
        while offset < content_length {
            let mut part_size = self.multipart_copy_chunk_size;
            if offset + part_size > content_length {
                part_size = content_length - offset;
            }
            offsets.push((offset, part_size));
            offset += part_size;
        }

        let semaphore = Arc::new(Semaphore::new(self.multipart_copy_jobs));
        let mut tasks = Vec::new();

        for (part_number, (offset, part_size)) in offsets.into_iter().enumerate() {
            let Ok(part_number) = i32::try_from(part_number + 1) else {
                error!("Error copying parts: too many parts");
                return Err(Error::StorageBackend("Error copying parts".to_string()));
            };

            let semaphore = semaphore.clone();
            let source = source.to_string();
            let destination = destination.to_string();

            let query = self
                .s3_client
                .upload_part_copy()
                .bucket(&self.bucket)
                .key(&destination)
                .part_number(part_number)
                .upload_id(&upload_id)
                .copy_source(format!("{}/{}", self.bucket, source))
                .copy_source_range(format!("bytes={}-{}", offset, offset + part_size - 1));

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap(); // TODO: fix unwrap()
                debug!(
                    "Copying part {} ({}-{}) of object '{}' to '{}'",
                    part_number,
                    offset,
                    offset + part_size - 1,
                    source,
                    destination
                );

                let res = query.send().await?;
                let res = res.copy_part_result.ok_or_else(|| {
                    error!("Error copying part: copy part result not found");
                    Error::StorageBackend("Error copying part".to_string())
                })?;

                let e_tag = res.e_tag.ok_or_else(|| {
                    error!("Error copying part: e_tag not found");
                    Error::StorageBackend("Error copying part".to_string())
                })?;

                Ok(CompletedPartBuilder::default()
                    .part_number(part_number)
                    .e_tag(e_tag)
                    .build())
            });

            tasks.push(task);
        }

        let parts = try_join_all(tasks).await.map_err(|e| {
            error!("Error copying parts: {}", e);
            Error::StorageBackend("Error copying parts".to_string())
        })?;
        let parts = parts
            .into_iter()
            .collect::<Result<Vec<CompletedPart>, Error>>()?;

        let _ = self
            .s3_client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(destination)
            .upload_id(&upload_id)
            .multipart_upload(
                CompletedMultipartUploadBuilder::default()
                    .set_parts(Some(parts))
                    .build(),
            )
            .send()
            .await?;

        Ok(())
    }

    pub async fn copy_object(&self, destination: &str, source: &str) -> Result<(), Error> {
        let content_length = self.get_object_size(source).await?;

        // AWS S3 doesn't support copying objects larger than 5GB in a single request
        // so we need to use the multipart upload API when above this configurable threshold
        if content_length >= self.multipart_copy_threshold {
            self.multipart_copy_object(destination, source, content_length)
                .await?;
        } else {
            debug!("Copying object '{}' to '{}'", source, destination);
            self.s3_client
                .copy_object()
                .bucket(&self.bucket)
                .key(destination)
                .copy_source(format!("{}/{}", self.bucket, source))
                .send()
                .await?;
        }

        Ok(())
    }

    #[instrument(skip(self, operation))]
    pub async fn blob_link_index_update<O>(
        &self,
        namespace: &str,
        digest: &Digest,
        operation: O,
    ) -> Result<(), Error>
    where
        O: FnOnce(&mut HashSet<DataLink>),
    {
        let path = self.tree.blob_index_path(digest);

        let res = self.get_object_body_as_vec(&path, None).await;

        let mut reference_index = match res {
            Ok(data) => serde_json::from_slice::<BlobEntityLinkIndex>(&data)?,
            Err(_) => BlobEntityLinkIndex::default(),
        };

        let index = reference_index
            .namespace
            .entry(namespace.to_string())
            .or_insert_with(HashSet::new);

        operation(index);
        if index.is_empty() {
            reference_index.namespace.remove(namespace);
        }

        if reference_index.namespace.is_empty() {
            let path = self.tree.blob_container_dir(digest);
            self.delete_object_with_prefix(&path).await?;
        } else {
            let content = serde_json::to_vec(&reference_index)?;
            self.put_object(&path, content).await?;
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn search_multipart_upload_id(&self, key: &str) -> Result<Option<String>, Error> {
        let mut next_key_marker = None;

        loop {
            let mut res = self
                .s3_client
                .list_multipart_uploads()
                .bucket(&self.bucket)
                .prefix(key);

            if let Some(key_marker) = next_key_marker {
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
    ) -> Result<(Vec<String>, u64), Error> {
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
            parts_size += parts.iter().filter_map(|part| part.size).sum::<i64>();
            all_parts.extend(parts.iter().filter_map(|part| part.e_tag.clone()));

            if res.is_truncated.unwrap_or_default() {
                part_number_marker = res.next_part_number_marker;
            } else {
                break;
            }
        }

        let parts_size = u64::try_from(parts_size).unwrap_or_default();
        Ok((all_parts, parts_size))
    }

    #[instrument(skip(self))]
    async fn create_multipart_upload(&self, path: &str) -> Result<String, Error> {
        let res = self
            .s3_client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await?;

        let Some(upload_id) = res.upload_id else {
            error!("Error creating multipart upload: upload id not found");
            return Err(Error::StorageBackend(
                "Error creating multipart upload".to_string(),
            ));
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
    ) -> Result<String, Error> {
        let body = ByteStream::from(body);

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
    async fn abort_pending_uploads(&self, key: &str) -> Result<(), Error> {
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

    #[instrument(skip(self))]
    async fn update_last_pulled_metadata(&self, key: &str) -> Result<(), Error> {
        let res = self.head_object(key).await?;

        let pushed_at = res
            .metadata
            .unwrap_or_default()
            .get(PUSHED_AT_METADATA_KEY)
            .cloned()
            .unwrap_or(Utc::now().to_rfc3339());

        self.s3_client
            .copy_object()
            .bucket(&self.bucket)
            .key(key)
            .copy_source(format!("{}/{}", self.bucket, key))
            .metadata_directive(MetadataDirective::Replace)
            .metadata(PUSHED_AT_METADATA_KEY, pushed_at)
            .metadata(LAST_PULLED_AT_METADATA_KEY, Utc::now().to_rfc3339())
            .send()
            .await?;

        Ok(())
    }
}

#[async_trait]
impl DataStore for S3Backend {
    #[instrument(skip(self))]
    async fn list_namespaces(
        &self,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
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

        let res = res.max_keys(i32::from(n)).send().await?;

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
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
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
            .max_keys(i32::from(n));

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
    ) -> Result<Vec<Descriptor>, Error> {
        let base_prefix = format!(
            "{}/sha256/",
            self.tree.manifest_referrers_dir(namespace, digest)
        );
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

                let manifest_digest = Digest::Sha256(manifest_digest);
                let blob_path = self.tree.blob_path(&manifest_digest);

                let manifest = self.get_object_body_as_vec(&blob_path, None).await?;
                let manifest_len = manifest.len();

                let manifest = Manifest::from_slice(&manifest)?;
                let Some(descriptor) = manifest.into_referrer_descriptor(artifact_type.as_ref())
                else {
                    continue;
                };

                referrers.push(Descriptor {
                    digest: manifest_digest.to_string(),
                    size: manifest_len as u64,
                    ..descriptor
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
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
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
            .max_keys(i32::from(n))
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
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error> {
        debug!(
            "Fetching {} blob(s) with continuation token: {:?}",
            n, continuation_token
        );
        let algorithm = "sha256";
        let path = self.tree.blobs_root_dir();

        let base_prefix = format!("{path}/{algorithm}/");
        let base_prefix_len = base_prefix.len();

        let res = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&base_prefix)
            .max_keys(i32::from(n))
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
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error> {
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
            .max_keys(i32::from(n))
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
    async fn create_upload(&self, name: &str, uuid: &str) -> Result<String, Error> {
        let date_path = self.tree.upload_start_date_path(name, uuid);
        let date = Utc::now().to_rfc3339();
        self.put_object(&date_path, date.into_bytes()).await?;

        let hash_state_path = self.tree.upload_hash_context_path(name, uuid, "sha256", 0);
        let state = Sha256::serialized_empty_state();
        self.put_object(&hash_state_path, state).await?;

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
        let upload_path = self.tree.upload_path(name, uuid);

        let mut uploaded_size;
        let mut uploaded_parts;
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
            uploaded_parts = i32::try_from(parts.len()).unwrap_or_default() + 1;
        } else {
            self.abort_pending_uploads(&upload_path).await?;

            upload_id = self.create_multipart_upload(&upload_path).await?;
            uploaded_size = 0;
            uploaded_parts = 1;
        }

        let staged_path = self
            .tree
            .upload_staged_container_path(name, uuid, uploaded_size);
        let staged_size = self.get_object_size(&staged_path).await.unwrap_or_default();

        let hasher_state_path =
            self.tree
                .upload_hash_context_path(name, uuid, "sha256", uploaded_size + staged_size);
        let state = self
            .get_object_body_as_vec(&hasher_state_path, None)
            .await?;

        // NOTE: if the part is not big enough (at least 5M, as per the S3 protocol),
        // we store it in as a staging blob.
        // First, we load the staged chunk if any and append the new data
        let mut chunk = self.load_staged_chunk(name, uuid, uploaded_size).await?;
        let mut hasher = Sha256::deserialize_state(&state)?;

        let stream_chunk_size =
            usize::try_from(self.multipart_part_size).unwrap_or(100 * 10 * 1024 * 1024);

        let mut stream_chunk = vec![0; stream_chunk_size];
        loop {
            let bytes_read = stream.read(&mut stream_chunk).await?;
            if bytes_read == 0 {
                break;
            }

            let stream_chunk = &stream_chunk[..bytes_read];
            chunk.extend(stream_chunk);
            hasher.update(stream_chunk);

            let chunk_len = chunk.len() as u64;

            if chunk_len >= self.multipart_part_size {
                // The hash computation must take into account:
                // - completed parts
                // - current staged chunk if any + source: chunk.len()
                let hash_state_path = self.tree.upload_hash_context_path(
                    name,
                    uuid,
                    "sha256",
                    uploaded_size + chunk_len,
                );
                self.put_object(&hash_state_path, hasher.serialize_state())
                    .await?;

                self.upload_part(&upload_path, &upload_id, uploaded_parts, chunk.clone())
                    .await?;

                uploaded_parts += 1;
                uploaded_size += chunk_len;
                chunk.clear();
            }
        }

        // If the chunk is still too small, store it again and return.
        // If there is no subsequent calls to this method, the chunk will be loaded back and stored
        // as last part in the complete_upload() method.
        if !chunk.is_empty() {
            let hash_state_path = self.tree.upload_hash_context_path(
                name,
                uuid,
                "sha256",
                uploaded_size + (chunk.len() as u64),
            );
            self.put_object(&hash_state_path, hasher.serialize_state())
                .await?;

            self.store_staged_chunk(name, uuid, chunk, uploaded_size)
                .await?;
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn read_upload_summary(
        &self,
        name: &str,
        uuid: &str,
    ) -> Result<(Digest, u64, DateTime<Utc>), Error> {
        let key = self.tree.upload_path(name, uuid);

        let mut size = 0;
        if let Ok(Some(upload_id)) = self.search_multipart_upload_id(&key).await {
            let (_, upload_size) = self.search_multipart_upload_parts(&key, &upload_id).await?;
            size = upload_size;
        };

        let staged_path = self.tree.upload_staged_container_path(name, uuid, size);
        size += self.get_object_size(&staged_path).await.unwrap_or_default();

        let hash_state_path = self
            .tree
            .upload_hash_context_path(name, uuid, "sha256", size);
        let state = self.get_object_body_as_vec(&hash_state_path, None).await?;

        let hasher = Sha256::deserialize_state(&state)?;
        let digest = hasher.to_digest();

        let date_path = self.tree.upload_start_date_path(name, uuid);
        let date = self.get_object_body_as_vec(&date_path, None).await?;
        let date = String::from_utf8(date)?;

        let start_date = DateTime::parse_from_rfc3339(&date)
            .ok()
            .unwrap_or_default() // Fallbacks to epoch
            .with_timezone(&Utc);

        // don't forget to count the staging blob
        let staged_path = self.tree.upload_staged_container_path(name, uuid, size);
        size += self.get_object_size(&staged_path).await.unwrap_or_default();

        Ok((digest, size, start_date))
    }

    #[instrument(skip(self))]
    async fn complete_upload(
        &self,
        name: &str,
        uuid: &str,
        digest: Option<Digest>,
    ) -> Result<Digest, Error> {
        let key = self.tree.upload_path(name, uuid);

        let Ok(Some(upload_id)) = self.search_multipart_upload_id(&key).await else {
            return Err(Error::UploadNotFound);
        };

        let (mut parts, mut size) = self.search_multipart_upload_parts(&key, &upload_id).await?;

        // load the staged chunk if any and create the last part
        let chunk = self.load_staged_chunk(name, uuid, size).await?;
        if !chunk.is_empty() {
            size += chunk.len() as u64;

            let part_number = i32::try_from(parts.len()).unwrap_or_default() + 1; // Safe unwrap, max parts is 10000

            let e_tag = self
                .upload_part(&key, &upload_id, part_number, chunk)
                .await?;

            parts.push(e_tag);
        }

        let digest = if let Some(digest) = digest {
            digest
        } else {
            let hash_state_path = self
                .tree
                .upload_hash_context_path(name, uuid, "sha256", size);

            let state = self.get_object_body_as_vec(&hash_state_path, None).await?;

            let hasher = Sha256::deserialize_state(&state)?;
            hasher.to_digest()
        };

        let _guard = self
            .lock_store
            .acquire_write_lock(&digest.to_string())
            .await;

        let parts = parts
            .iter()
            .enumerate()
            .map(|(i, e_tag)| {
                let part_number = i32::try_from(i).unwrap_or_default() + 1; // Safe unwrap, max parts is 10000

                CompletedPartBuilder::default()
                    .part_number(part_number)
                    .e_tag(e_tag)
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

        let blob_path = self.tree.blob_path(&digest);
        self.copy_object(&blob_path, &key).await?;

        // NOTE: in case of error, remaining parts will be deleted by the scrub job
        let key = self.tree.upload_container_path(name, uuid);
        let _ = self.delete_object_with_prefix(&key).await;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn delete_upload(&self, name: &str, uuid: &str) -> Result<(), Error> {
        let upload_path = self.tree.upload_path(name, uuid);
        self.abort_pending_uploads(&upload_path).await?;

        let upload_path = self.tree.upload_container_path(name, uuid);
        self.delete_object_with_prefix(&upload_path).await
    }

    #[instrument(skip(self, content))]
    async fn create_blob(&self, content: &[u8]) -> Result<Digest, Error> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher.to_digest();

        let _guard = self
            .lock_store
            .acquire_write_lock(&digest.to_string())
            .await;

        let blob_path = self.tree.blob_path(&digest);
        self.put_object(&blob_path, content.to_vec()).await?;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, Error> {
        let path = self.tree.blob_path(digest);
        let blob = self.get_object_body_as_vec(&path, None).await?;
        Ok(blob)
    }

    #[instrument(skip(self))]
    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobEntityLinkIndex, Error> {
        let path = self.tree.blob_index_path(digest);

        let data = self.get_object_body_as_vec(&path, None).await?;
        let index = serde_json::from_slice(&data)?;

        Ok(index)
    }

    #[instrument(skip(self))]
    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, Error> {
        let path = self.tree.blob_path(digest);

        let content_length = self.get_object_size(&path).await?;
        Ok(content_length)
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

        let res = self.head_object(&key).await?;

        let metadata = res.metadata.unwrap_or_default();

        let created_at = metadata
            .get(PUSHED_AT_METADATA_KEY)
            .and_then(|s| s.parse::<DateTime<Utc>>().ok())
            .unwrap_or_default();

        let accessed_at = metadata
            .get(LAST_PULLED_AT_METADATA_KEY)
            .and_then(|s| s.parse::<DateTime<Utc>>().ok())
            .unwrap_or_default();

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
        let res = self.get_object(&path, start_offset).await?;
        Ok(Box::new(res.body.into_async_read()))
    }

    #[instrument(skip(self))]
    async fn delete_blob(&self, digest: &Digest) -> Result<(), Error> {
        let _guard = self
            .lock_store
            .acquire_write_lock(&digest.to_string())
            .await;

        let path = self.tree.blob_container_dir(digest);
        self.delete_object_with_prefix(&path).await
    }

    #[instrument(skip(self))]
    async fn update_last_pulled(&self, name: &str, reference: &DataLink) -> Result<(), Error> {
        match reference {
            DataLink::Tag(_) => {
                let key = self.tree.get_link_path(reference, name);
                self.update_last_pulled_metadata(&key).await?;

                let digest = self.read_link(name, reference).await?;
                let link = DataLink::Digest(digest);
                let key = self.tree.get_link_path(&link, name);
                self.update_last_pulled_metadata(&key).await?;
            }
            DataLink::Digest(_) => {
                let key = self.tree.get_link_path(reference, name);
                self.update_last_pulled_metadata(&key).await?;
            }
            _ => {
                return Ok(()); // No-op
            }
        };

        Ok(())
    }

    #[instrument(skip(self))]
    async fn read_link(&self, name: &str, reference: &DataLink) -> Result<Digest, Error> {
        let path = self.tree.get_link_path(reference, name);
        let data = self.get_object_body_as_vec(&path, None).await?;

        let link = String::from_utf8(data)?;
        Ok(Digest::try_from(link.as_str())?)
    }

    #[instrument(skip(self))]
    async fn create_link(
        &self,
        namespace: &str,
        reference: &DataLink,
        digest: &Digest,
    ) -> Result<(), Error> {
        let _guard = self
            .lock_store
            .acquire_write_lock(&digest.to_string())
            .await;

        let link_path = self.tree.get_link_path(reference, namespace);

        match self.read_link(namespace, reference).await.ok() {
            Some(existing_digest) if existing_digest == *digest => return Ok(()),
            Some(existing_digest) if existing_digest != *digest => {
                let _existing_digest_guard = self
                    .lock_store
                    .acquire_write_lock(&existing_digest.to_string())
                    .await;

                self.delete_object(&link_path).await?;

                self.blob_link_index_update(namespace, digest, |index| {
                    index.remove(reference);
                })
                .await?;
            }
            _ => {}
        }

        self.put_object(&link_path, digest.to_string().into_bytes())
            .await?;

        self.blob_link_index_update(namespace, digest, |index| {
            index.insert(reference.clone());
        })
        .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_link(&self, namespace: &str, reference: &DataLink) -> Result<(), Error> {
        let digest = match self.read_link(namespace, reference).await {
            Ok(digest) => digest,
            Err(Error::ReferenceNotFound) => return Ok(()),
            Err(e) => return Err(e),
        };

        let link_path = self.tree.get_link_path(reference, namespace);

        let _guard = self
            .lock_store
            .acquire_write_lock(&digest.to_string())
            .await;

        self.delete_object(&link_path).await?;

        self.blob_link_index_update(namespace, &digest, |index| {
            index.remove(reference);
        })
        .await?;

        Ok(())
    }
}
