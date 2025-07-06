use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use crate::configuration::StorageS3Config;
use crate::registry::data_store::{DataStore, Error, LinkMetadata, Reader};
use crate::registry::oci_types::{Descriptor, Digest, Manifest};
use crate::registry::reader::{ChunkedReader, HashingReader};
use crate::registry::utils::sha256_ext::Sha256Ext;
use crate::registry::utils::{BlobLink, BlobMetadata, DataPathBuilder};
use async_trait::async_trait;
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::operation::head_object::HeadObjectOutput;
use aws_sdk_s3::operation::upload_part_copy::UploadPartCopyOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::builders::{CompletedMultipartUploadBuilder, CompletedPartBuilder};
use aws_sdk_s3::types::{CompletedPart, CopyPartResult};
use aws_sdk_s3::{
    config::timeout::TimeoutConfig,
    config::{BehaviorVersion, Credentials, Region},
    Client as S3Client, Config as S3Config,
};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::{stream, StreamExt, TryFutureExt, TryStreamExt};
use sha2::{Digest as ShaDigestTrait, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, error, instrument};
use x509_parser::nom::ToUsize;

#[derive(Clone)]
pub struct S3Backend {
    s3_client: S3Client,
    tree: Arc<DataPathBuilder>,
    bucket: String,
    multipart_copy_threshold: u64,
    multipart_copy_chunk_size: u64,
    multipart_copy_jobs: usize,
    multipart_part_size: usize,
}

impl Debug for S3Backend {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3StorageEngine").finish()
    }
}

impl S3Backend {
    pub fn new(config: StorageS3Config) -> Self {
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
            tree: Arc::new(DataPathBuilder::new(config.key_prefix)),
            bucket: config.bucket,
            multipart_copy_threshold: config.multipart_copy_threshold.as_u64(),
            multipart_copy_chunk_size: config.multipart_copy_chunk_size.as_u64(),
            multipart_copy_jobs: config.multipart_copy_jobs,
            multipart_part_size: config.multipart_part_size.as_u64().to_usize(),
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
            .and_then(|content_length| content_length.try_into().ok())
            .ok_or(Error::InvalidFormat(
                "Content length not provided".to_string(),
            ))?;

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
    async fn put_object<T>(&self, key: &str, data: T) -> Result<(), Error>
    where
        T: Into<Bytes>,
    {
        self.s3_client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(data.into()))
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
        debug!("Deleting objects with prefix: {prefix}");

        let mut continuation_token = None;
        loop {
            let res = self
                .s3_client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .max_keys(1000)
                .set_continuation_token(continuation_token)
                .send()
                .await?;

            for object in res.contents.unwrap_or_default() {
                if let Some(key) = object.key {
                    debug!("Deleting object: {key}");
                    self.delete_object(&key).await?;
                }
            }

            if res.is_truncated.unwrap_or_default() {
                continuation_token = res.next_continuation_token;
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
        chunk: Bytes,
        offset: u64,
    ) -> Result<(), Error> {
        let key = self
            .tree
            .upload_staged_container_path(namespace, upload_id, offset);
        self.put_object(&key, chunk).await
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
            Ok(data) => Ok(data),
            Err(Error::ReferenceNotFound) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
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

        self.put_object(&hash_state_path, state).await
    }

    async fn load_hasher(&self, name: &str, uuid: &str, offset: u64) -> Result<Sha256, Error> {
        let hash_state_path = self
            .tree
            .upload_hash_context_path(name, uuid, "sha256", offset);

        let state = self.get_object_body_as_vec(&hash_state_path, None).await?;
        Sha256::from_state(&state)
    }

    async fn multipart_copy_object(
        &self,
        destination: &str,
        source: &str,
        content_length: u64,
    ) -> Result<(), Error> {
        debug!(
            "Copying object '{source}' to '{destination}' using multipart upload (max {} jobs)",
            self.multipart_copy_jobs
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

        let copy_jobs = offsets.into_iter()
            .enumerate()
            .map(|(part_number, (start_offset, part_size))| {
                let part_number = (part_number + 1).try_into()?;
                let end_offset = start_offset + part_size - 1;

                debug!("Preparing to copy part {part_number} ({start_offset}-{end_offset}) from '{source}' to '{destination}'");

                Ok(self.s3_client
                    .upload_part_copy()
                    .bucket(&self.bucket)
                    .key(destination)
                    .part_number(part_number)
                    .upload_id(&upload_id)
                    .copy_source(format!("{}/{source}", self.bucket))
                    .copy_source_range(format!("bytes={start_offset}-{end_offset}"))
                    .send()
                    .map_ok(move |res| (part_number, res))
                )
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let copy_jobs: Vec<(i32, UploadPartCopyOutput)> = stream::iter(copy_jobs)
            .buffered(self.multipart_copy_jobs)
            .try_collect()
            .await?;

        let parts: Vec<CompletedPart> = copy_jobs
            .into_iter()
            .map(|(part_number, res)| {
                let UploadPartCopyOutput {
                    copy_part_result:
                        Some(CopyPartResult {
                            e_tag: Some(e_tag), ..
                        }),
                    ..
                } = res
                else {
                    error!("Error copying part: e_tag not found");
                    return Err(Error::StorageBackend("Error copying part".to_string()));
                };

                Ok(CompletedPartBuilder::default()
                    .part_number(part_number)
                    .e_tag(e_tag)
                    .build())
            })
            .collect::<Result<_, Error>>()?;

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
            debug!("Copying object '{source}' to '{destination}'");
            self.s3_client
                .copy_object()
                .bucket(&self.bucket)
                .key(destination)
                .copy_source(format!("{}/{source}", self.bucket))
                .send()
                .await?;
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn search_multipart_upload_id(&self, key: &str) -> Result<Option<String>, Error> {
        let mut key_marker = None;

        loop {
            let res = self
                .s3_client
                .list_multipart_uploads()
                .bucket(&self.bucket)
                .prefix(key)
                .set_key_marker(key_marker)
                .send()
                .await?;

            if let Some(uploads) = res.uploads {
                for upload in uploads {
                    if upload.key.is_some_and(|s| s == key) {
                        return Ok(upload.upload_id);
                    }
                }
            }

            if res.is_truncated.unwrap_or_default() {
                key_marker = res.next_key_marker;
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

        Ok((all_parts, parts_size.try_into()?))
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
        body: Bytes,
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

    async fn upload_part_copy(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        source: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<(String, u64)>, Error> {
        let Ok(source_object) = self
            .s3_client
            .head_object()
            .bucket(&self.bucket)
            .key(source)
            .send()
            .await
        else {
            return Ok(None);
        };

        let copied_size = source_object
            .content_length
            .unwrap_or_default()
            .try_into()?;

        let res = self
            .s3_client
            .upload_part_copy()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .copy_source(format!("{}/{source}", self.bucket));

        let res = if let Some((start, end)) = range {
            res.copy_source_range(format!("bytes={start}-{end}"))
        } else {
            res
        };

        let res = res.send().await?;

        let e_tag = res
            .copy_part_result
            .and_then(|res| res.e_tag)
            .unwrap_or_default();

        Ok(Some((e_tag, copied_size)))
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
}

#[async_trait]
impl DataStore for S3Backend {
    #[instrument(skip(self))]
    async fn list_namespaces(
        &self,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        debug!("Fetching {n} namespace(s) with continuation token: {last:?}");

        // List all objects under the repository directory
        let base_prefix = format!("{}/", self.tree.repository_dir());
        let base_prefix_len = base_prefix.len();

        let mut namespaces = Vec::new();
        let mut continuation_token = None;

        // List all objects recursively to find all namespaces
        loop {
            let mut request = self
                .s3_client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&base_prefix)
                .max_keys(i32::from(n));

            if let Some(token) = continuation_token {
                request = request.continuation_token(token);
            }

            let res = request.send().await?;

            for object in res.contents.unwrap_or_default() {
                let Some(key) = object.key else {
                    continue;
                };

                // We need to extract the namespace from the path
                // In S3, the path will be something like:
                // v2/repositories/namespace/_manifests/... or
                // v2/repositories/namespace/nested/_manifests/...
                let rel_path = &key[base_prefix_len..];

                // Look for special directories that indicate a namespace
                for marker in &["/_manifests/", "/_layers/", "/_uploads/", "/_config/"] {
                    if let Some(idx) = rel_path.find(marker) {
                        let namespace = rel_path[..idx].to_string();
                        namespaces.push(namespace);
                        break; // Found a namespace, no need to check other markers
                    }
                }
            }

            if res.is_truncated == Some(true) {
                continuation_token = res.next_continuation_token;
            } else {
                break;
            }
        }

        let start_idx = if let Some(last_item) = &last {
            namespaces
                .iter()
                .position(|ns| ns > last_item)
                .unwrap_or(namespaces.len())
        } else {
            0
        };

        let end_idx = std::cmp::min(start_idx + usize::from(n), namespaces.len());
        let result_namespaces = namespaces[start_idx..end_idx].to_vec();

        let next_token = if end_idx < namespaces.len() {
            result_namespaces.last().cloned()
        } else {
            None
        };

        Ok((result_namespaces, next_token))
    }

    #[instrument(skip(self))]
    async fn list_tags(
        &self,
        namespace: &str,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        debug!("Listing {n} tag(s) for namespace '{namespace}' starting with continuation_token '{last:?}'");
        let base_prefix = format!("{}/", self.tree.manifest_tags_dir(namespace));
        let base_prefix_len = base_prefix.len();

        let mut all_tags = Vec::new();
        let mut continuation_token = None;

        loop {
            let mut request = self
                .s3_client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&base_prefix)
                .delimiter("/")
                .max_keys(i32::from(n));

            if let Some(token) = continuation_token {
                request = request.continuation_token(token);
            }

            let res = request.send().await?;

            for common_prefixes in res.common_prefixes.unwrap_or_default() {
                if let Some(key) = common_prefixes.prefix {
                    let mut tag = key[base_prefix_len..].to_string();
                    if tag.ends_with('/') {
                        tag = tag.trim_end_matches('/').to_string();
                    }
                    all_tags.push(tag);
                }
            }

            if res.is_truncated == Some(true) {
                continuation_token = res.next_continuation_token;
            } else {
                break;
            }
        }

        let start_idx = if let Some(last_tag) = &last {
            all_tags
                .iter()
                .position(|tag| tag > last_tag)
                .unwrap_or(all_tags.len())
        } else {
            0
        };

        let end_idx = std::cmp::min(start_idx + usize::from(n), all_tags.len());
        let result_tags = all_tags[start_idx..end_idx].to_vec();

        let next_token = if end_idx < all_tags.len() {
            result_tags.last().cloned()
        } else {
            None
        };

        Ok((result_tags, next_token))
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
        debug!("Fetching {n} upload(s) for namespace '{namespace}' with continuation token: {continuation_token:?}");
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
        debug!("Fetching {n} blob(s) with continuation token: {continuation_token:?}");
        let algorithm = "sha256";
        let path = self.tree.blobs_root_dir();
        let base_prefix = format!("{path}/{algorithm}/");
        let base_prefix_len = base_prefix.len();

        // For consistent pagination, we need to get all blobs matching our criteria first
        let mut all_blobs = Vec::new();
        let mut list_continuation_token = None;

        loop {
            let mut request = self
                .s3_client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&base_prefix)
                .max_keys(i32::from(n)); // Use larger value to reduce API calls

            if let Some(token) = list_continuation_token {
                request = request.continuation_token(token);
            }

            let res = request.send().await?;

            for object in res.contents.unwrap_or_default() {
                if let Some(key) = object.key {
                    if !key.ends_with("data") {
                        continue;
                    }

                    let key = key[..key.len() - 5].to_string();
                    let digest_value = key[base_prefix_len + 3..].to_string();
                    all_blobs.push(Digest::Sha256(digest_value));
                }
            }

            if res.is_truncated == Some(true) {
                list_continuation_token = res.next_continuation_token;
            } else {
                break;
            }
        }

        let start_idx = if let Some(token) = &continuation_token {
            all_blobs
                .iter()
                .position(|digest| digest.to_string() > *token)
                .unwrap_or(all_blobs.len())
        } else {
            0
        };

        let end_idx = std::cmp::min(start_idx + usize::from(n), all_blobs.len());
        let result_blobs = all_blobs[start_idx..end_idx].to_vec();

        let next_token = if end_idx < all_blobs.len() {
            result_blobs.last().map(ToString::to_string)
        } else {
            None
        };

        Ok((result_blobs, next_token))
    }

    async fn list_revisions(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error> {
        debug!("Fetching {n} revision(s) for namespace '{namespace}' with continuation token: {continuation_token:?}");
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
        self.put_object(&date_path, Utc::now().to_rfc3339()).await?;

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
            uploaded_parts = (parts.len() + 1).try_into()?;
        } else {
            self.abort_pending_uploads(&upload_path).await?;

            upload_id = self.create_multipart_upload(&upload_path).await?;
            uploaded_size = 0;
            uploaded_parts = 1;
        }

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
                self.upload_part(&upload_path, &upload_id, uploaded_parts, chunk)
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
        let key = self.tree.upload_path(name, uuid);

        let mut size = 0;
        if let Ok(Some(upload_id)) = self.search_multipart_upload_id(&key).await {
            (_, size) = self.search_multipart_upload_parts(&key, &upload_id).await?;
        }

        let staged_path = self.tree.upload_staged_container_path(name, uuid, size);
        size += self.get_object_size(&staged_path).await.unwrap_or_default();

        let digest = self.load_hasher(name, uuid, size).await?.digest();

        let date_path = self.tree.upload_start_date_path(name, uuid);
        let date = self.get_object_body_as_vec(&date_path, None).await?;
        let date = String::from_utf8(date)?;

        let start_date = DateTime::parse_from_rfc3339(&date)
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
        let key = self.tree.upload_path(name, uuid);

        let Ok(Some(upload_id)) = self.search_multipart_upload_id(&key).await else {
            return Err(Error::UploadNotFound);
        };

        let (mut parts, mut size) = self.search_multipart_upload_parts(&key, &upload_id).await?;

        let source_key = self.tree.upload_staged_container_path(name, uuid, size);

        let last_part = self
            .upload_part_copy(
                &key,
                &upload_id,
                (parts.len() + 1).try_into()?,
                &source_key,
                None,
            )
            .await?;

        if let Some((e_tag, part_size)) = last_part {
            parts.push(e_tag);
            size += part_size;
        }

        let digest = if let Some(digest) = digest {
            digest
        } else {
            self.load_hasher(name, uuid, size).await?.digest()
        };

        let parts = parts
            .into_iter()
            .enumerate()
            .map(|(i, e_tag)| -> Result<_, Error> {
                let part_number = (i + 1).try_into()?;
                Ok(CompletedPartBuilder::default()
                    .part_number(part_number)
                    .e_tag(e_tag)
                    .build())
            })
            .collect::<Result<Vec<CompletedPart>, Error>>()?;

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
        let digest = hasher.digest();

        let content = Bytes::from(content.to_vec());
        let blob_path = self.tree.blob_path(&digest);
        self.put_object(&blob_path, content).await?;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, Error> {
        let path = self.tree.blob_path(digest);
        let blob = self.get_object_body_as_vec(&path, None).await?;
        Ok(blob)
    }

    #[instrument(skip(self))]
    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobMetadata, Error> {
        let path = self.tree.blob_index_path(digest);

        let data = self.get_object_body_as_vec(&path, None).await?;
        let index = serde_json::from_slice(&data)?;

        Ok(index)
    }

    #[instrument(skip(self, operation))]
    async fn update_blob_index<O>(
        &self,
        namespace: &str,
        digest: &Digest,
        operation: O,
    ) -> Result<(), Error>
    where
        O: FnOnce(&mut HashSet<BlobLink>) + Send,
    {
        let path = self.tree.blob_index_path(digest);

        let res = self.get_object_body_as_vec(&path, None).await;

        let mut reference_index = match res {
            Ok(data) => serde_json::from_slice::<BlobMetadata>(&data)?,
            Err(_) => BlobMetadata::default(),
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
            let content = Bytes::from(serde_json::to_vec(&reference_index)?);
            self.put_object(&path, content).await?;
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, Error> {
        let path = self.tree.blob_path(digest);

        let content_length = self.get_object_size(&path).await?;
        Ok(content_length)
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

    async fn read_link(&self, namespace: &str, link: &BlobLink) -> Result<LinkMetadata, Error> {
        let link_path = self.tree.get_link_path(link, namespace);
        self.get_object_body_as_vec(&link_path, None)
            .await
            .and_then(LinkMetadata::from_bytes)
    }

    async fn write_link(
        &self,
        namespace: &str,
        link: &BlobLink,
        metadata: &LinkMetadata,
    ) -> Result<(), Error> {
        let link_path = self.tree.get_link_path(link, namespace);
        let serialized_link_data = Bytes::from(serde_json::to_vec(metadata)?);
        self.put_object(&link_path, serialized_link_data).await
    }

    async fn delete_link(&self, namespace: &str, link: &BlobLink) -> Result<(), Error> {
        let link_path = self.tree.get_link_path(link, namespace);
        self.delete_object(&link_path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::StorageS3Config;
    use crate::registry::data_store::tests::{
        test_datastore_blob_operations, test_datastore_link_operations, test_datastore_list_blobs,
        test_datastore_list_namespaces, test_datastore_list_referrers,
        test_datastore_list_revisions, test_datastore_list_tags, test_datastore_list_uploads,
        test_datastore_upload_operations,
    };
    use bytesize::ByteSize;
    use uuid::Uuid;

    // Helper function to create a test S3Backend
    fn create_test_backend() -> S3Backend {
        let config = StorageS3Config {
            endpoint: "http://127.0.0.1:9000".to_string(),
            region: "region".to_string(),
            bucket: "registry".to_string(),
            access_key_id: "root".to_string(),
            secret_key: "roottoor".to_string(),
            key_prefix: format!("test-{}", Uuid::new_v4()),
            multipart_copy_threshold: ByteSize::mb(5),
            multipart_copy_chunk_size: ByteSize::mb(5),
            multipart_copy_jobs: 4,
            multipart_part_size: ByteSize::mb(5),
        };

        S3Backend::new(config)
    }

    // Helper to clean up test data
    async fn cleanup_test_prefix(backend: &S3Backend) {
        if let Err(e) = backend
            .delete_object_with_prefix(&backend.tree.prefix)
            .await
        {
            println!("Warning: Failed to clean up test data: {e:?}");
        }
    }

    // Generic DataStore trait tests
    #[tokio::test]
    async fn test_list_namespaces() {
        let backend = create_test_backend();
        test_datastore_list_namespaces(&backend).await;
        cleanup_test_prefix(&backend).await;
    }

    #[tokio::test]
    async fn test_list_tags() {
        let backend = create_test_backend();
        test_datastore_list_tags(&backend).await;
        cleanup_test_prefix(&backend).await;
    }

    #[tokio::test]
    async fn test_list_referrers() {
        let backend = create_test_backend();
        test_datastore_list_referrers(&backend).await;
        cleanup_test_prefix(&backend).await;
    }

    #[tokio::test]
    async fn test_list_uploads() {
        let backend = create_test_backend();
        test_datastore_list_uploads(&backend).await;
        cleanup_test_prefix(&backend).await;
    }

    #[tokio::test]
    async fn test_list_blobs() {
        let backend = create_test_backend();
        test_datastore_list_blobs(&backend).await;
        cleanup_test_prefix(&backend).await;
    }

    #[tokio::test]
    async fn test_list_revisions() {
        let backend = create_test_backend();
        test_datastore_list_revisions(&backend).await;
        cleanup_test_prefix(&backend).await;
    }

    #[tokio::test]
    async fn test_blob_operations() {
        let backend = create_test_backend();
        test_datastore_blob_operations(&backend).await;
        cleanup_test_prefix(&backend).await;
    }

    #[tokio::test]
    async fn test_upload_operations() {
        let backend = create_test_backend();
        test_datastore_upload_operations(&backend).await;
        cleanup_test_prefix(&backend).await;
    }

    #[tokio::test]
    async fn test_link_operations() {
        let backend = create_test_backend();
        test_datastore_link_operations(&backend).await;
        cleanup_test_prefix(&backend).await;
    }
}
