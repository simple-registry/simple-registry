use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::operation::head_object::HeadObjectOutput;
use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output;
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
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tracing::{debug, error, instrument};

use crate::config::StorageS3Config;
use crate::error::RegistryError;
use crate::lock_manager::LockManager;
use crate::oci::{Descriptor, Digest, Manifest};
use crate::registry::LinkReference;
use crate::storage::tree_manager::TreeManager;
use crate::storage::{
    deserialize_hash_state, serialize_hash_empty_state, serialize_hash_state, BlobReferenceIndex,
    StorageEngine, StorageEngineReader, UploadSummary,
};

/*

<bucket root>
└── v2
    ├── blobs
    │   └── sha256
    │       ├── 19
    │       │   └── 195245f0c79279e8b8e012efa02c91dad4cf7d0e44c0f4382fea68cd93088e6c
    │       │       ├── data
    │       │       └── index.json
    │       ├── 33
    │       │   └── 33791ce134bf8cde1f6f9473576cdbd3c087aec33541fa492051bc2dbb6872ba
    │       │       ├── data
    │       │       └── index.json
    │       ├── 3c
    │       │   └── 3cad04a21c991089f34f9da43b355f48785352cee1b72182a0d9ffcad16e63d9
    │       │       ├── data
    │       │       └── index.json
    │       ├── 48
    │       │   └── 486c5264d3ad516a7daceee96f00c0999acc47c3c2230491df3f1071e3df93c3
    │       │       ├── data
    │       │       └── index.json
    │       ├── 92
    │       │   └── 92c3b3500be621c72c7ac6432a9d8f731f145f4a1535361ffd3a304e55f7ccda
    │       │       ├── data
    │       │       └── index.json
    │       ├── b0
    │       │   └── b0b54414d65769944d731c5e47f89bf217b197e36293812b0d7c1354f5008ff5
    │       │       ├── data
    │       │       └── index.json
    │       ├── b3
    │       │   └── b3fd15a82525302ad66ab4a6c8109db464206085e4755cd0b7de443dcf5bb295
    │       │       ├── data
    │       │       └── index.json
    │       ├── cc
    │       │   └── cc4f24efc205f5b338585fde826ee60f4d21fe7b9e95073e0676378a84140e22
    │       │       ├── data
    │       │       └── index.json
    │       └── ee
    │           └── ee57511b3c684acfe64e2025b557909406ca31f8dd53e0b0399a644c10ec1940
    │               ├── data
    │               └── index.json
    └── repositories
        └── test
            └── nginx
                ├── _config
                │   └── sha256
                │       └── 195245f0c79279e8b8e012efa02c91dad4cf7d0e44c0f4382fea68cd93088e6c
                │           └── link
                ├── _layers
                │   └── sha256
                │       ├── 33791ce134bf8cde1f6f9473576cdbd3c087aec33541fa492051bc2dbb6872ba
                │       │   └── link
                │       ├── 3cad04a21c991089f34f9da43b355f48785352cee1b72182a0d9ffcad16e63d9
                │       │   └── link
                │       ├── 486c5264d3ad516a7daceee96f00c0999acc47c3c2230491df3f1071e3df93c3
                │       │   └── link
                │       ├── 92c3b3500be621c72c7ac6432a9d8f731f145f4a1535361ffd3a304e55f7ccda
                │       │   └── link
                │       ├── b3fd15a82525302ad66ab4a6c8109db464206085e4755cd0b7de443dcf5bb295
                │       │   └── link
                │       ├── cc4f24efc205f5b338585fde826ee60f4d21fe7b9e95073e0676378a84140e22
                │       │   └── link
                │       └── ee57511b3c684acfe64e2025b557909406ca31f8dd53e0b0399a644c10ec1940
                │           └── link
                └── _manifests
                    ├── revisions
                    │   └── sha256
                    │       └── b0b54414d65769944d731c5e47f89bf217b197e36293812b0d7c1354f5008ff5
                    │           └── link
                    └── tags
                        └── latest
                            └── current
                                └── link
 */

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

    async fn list_objects(
        &self,
        prefix: &str,
        continuation_token: Option<String>,
        max_keys: Option<i32>,
    ) -> Result<ListObjectsV2Output, RegistryError> {
        let max_keys = max_keys.unwrap_or(1000);

        let res = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .delimiter("/")
            .set_continuation_token(continuation_token)
            .max_keys(max_keys)
            .send()
            .await?;

        Ok(res)
    }

    #[instrument]
    async fn collect_directory_entries(&self, prefix: &str) -> Result<Vec<String>, RegistryError> {
        let mut entries = Vec::new();
        let mut continuation_token = None;

        loop {
            let res = self
                .list_objects(prefix, continuation_token.clone(), None)
                .await?;

            if let Some(contents) = res.contents.as_ref() {
                for object in contents {
                    if let Some(key) = object.key.as_ref() {
                        let name = key.trim_end_matches('/');
                        let name = name.strip_prefix(prefix).unwrap_or(name);
                        entries.push(name.to_string());
                    }
                }
            }

            if res.is_truncated.unwrap_or_default() {
                continuation_token = res.next_continuation_token;
            } else {
                break;
            }
        }

        Ok(entries)
    }

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
                error!("Error head object: {}", service_error.to_string());
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
                error!("Error get object: {}", service_error.to_string());
                if service_error.is_no_such_key() {
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

    async fn get_object_body_as_vec(
        &self,
        key: &str,
        offset: Option<u64>,
    ) -> Result<Vec<u8>, RegistryError> {
        let res = self.get_object(key, offset).await?;
        let body = res.body.collect().await.map_err(|e| {
            error!("Error reading object body: {}", e);
            RegistryError::InternalServerError(Some("Error reading object body".to_string()))
        })?;

        Ok(body.to_vec())
    }

    async fn get_object_body_as_stream(
        &self,
        key: &str,
        offset: Option<u64>,
    ) -> Result<Box<dyn StorageEngineReader>, RegistryError> {
        let res = self.get_object(key, offset).await?;
        Ok(Box::new(res.body.into_async_read()))
    }

    async fn put_object(&self, key: &str, data: Vec<u8>) -> Result<(), RegistryError> {
        let _res = self
            .s3_client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(data))
            .send()
            .await
            .map_err(|e| {
                // TODO: implement a trait for this kind of error handling
                error!("Error putting object: {}", e);
                RegistryError::InternalServerError(Some("Error putting object".to_string()))
            })?;

        Ok(())
    }

    async fn delete_object(&self, key: &str) -> Result<(), RegistryError> {
        let _res = self
            .s3_client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                error!("Error deleting object: {}", e);
                RegistryError::InternalServerError(Some("Error deleting object".to_string()))
            })?;

        Ok(())
    }

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
                    error!("Deleting object: {}", key);
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

            let res = res.send().await.map_err(|e| {
                error!("Error listing multipart uploads: {}", e);
                RegistryError::InternalServerError(Some(
                    "Error listing multipart uploads".to_string(),
                ))
            })?;

            let key = key.to_string();
            let upload_ids: Vec<String> = res
                .uploads
                .unwrap_or_default()
                .iter()
                .filter(|upload| upload.key.as_ref() == Some(&key))
                .filter_map(|upload| upload.upload_id.clone())
                .take(1)
                .collect();

            if let Some(upload_id) = upload_ids.first() {
                return Ok(Some(upload_id.clone()));
            }

            if res.is_truncated.unwrap_or_default() {
                next_key_marker = res.next_key_marker;
            } else {
                break;
            }
        }

        Ok(None)
    }

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

            if let Some(marker) = part_number_marker.clone() {
                res = res.part_number_marker(marker);
            }

            let res = res.send().await.map_err(|e| {
                error!("Error listing parts: {}", e);
                RegistryError::InternalServerError(Some("Error listing parts".to_string()))
            })?;

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

    async fn create_multipart_upload(&self, path: &str) -> Result<String, RegistryError> {
        let res = self
            .s3_client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await
            .map_err(|e| {
                error!("Error creating multipart upload: {}", e);
                RegistryError::InternalServerError(Some(
                    "Error creating multipart upload".to_string(),
                ))
            })?;

        let Some(upload_id) = res.upload_id else {
            error!("Error creating multipart upload: upload id not found");
            return Err(RegistryError::InternalServerError(Some(
                "Error creating multipart upload".to_string(),
            )));
        };

        Ok(upload_id)
    }

    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Vec<u8>,
    ) -> Result<(), RegistryError> {
        self.s3_client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|e| {
                error!("Error uploading part: {:?}", e);
                RegistryError::InternalServerError(Some("Error uploading part".to_string()))
            })?;

        Ok(())
    }
}

#[async_trait]
impl StorageEngine for S3StorageEngine {
    #[instrument(skip(self))]
    async fn list_namespaces(
        &self,
        n: u32,
        continuation_token: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        debug!(
            "Fetching {} namespace(s) with continuation token: {:?}",
            n, continuation_token
        );
        let base_prefix = format!("{}/", self.tree.repository_dir());
        let base_prefix_len = base_prefix.len();

        let res = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&base_prefix)
            .delimiter("_")
            .set_continuation_token(continuation_token)
            .max_keys(n as i32)
            .send()
            .await?;

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
            Some(true) => res.next_continuation_token,
            _ => None,
        };

        Ok((repositories, next_last))
    }

    #[instrument(skip(self))]
    async fn list_tags(
        &self,
        namespace: &str,
        n: u32,
        continuation_token: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), RegistryError> {
        error!(
            "Listing {} tag(s) for namespace '{}' starting with continuation_token '{:?}'",
            n, namespace, continuation_token
        );
        let base_prefix = format!("{}/", self.tree.manifest_tags_dir(namespace));
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
            Some(true) => res.next_continuation_token,
            _ => None,
        };

        Ok((tags, next_last))
    }

    #[instrument(skip(self))]
    async fn list_referrers(
        // TODO: cleanup & remove dependency to collect_directory_entries
        &self,
        namespace: &str,
        digest: &Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, RegistryError> {
        let path = format!("{}/", self.tree.manifest_referrers_dir(namespace, digest));
        let all_manifests = self.collect_directory_entries(&path).await?;
        let mut referrers = Vec::new();

        for manifest_digest_str in all_manifests {
            let manifest_digest = Digest::from_str(&manifest_digest_str)?;
            let blob_path = self.tree.blob_path(&manifest_digest);

            let manifest_bytes = self.get_object_body_as_vec(&blob_path, None).await;
            if let Ok(manifest) = manifest_bytes {
                let size = manifest.len() as u64;
                let manifest: Manifest = serde_json::from_slice(&manifest)?;

                if let Some(media_type) = manifest.media_type.clone() {
                    if let Some(ref artifact_type_filter) = artifact_type {
                        let manifest_artifact_type = manifest
                            .artifact_type
                            .clone()
                            .or_else(|| manifest.config.as_ref().map(|c| c.media_type.clone()));

                        if manifest_artifact_type != Some(artifact_type_filter.clone()) {
                            continue;
                        }
                    }

                    referrers.push(Descriptor {
                        media_type,
                        digest: manifest_digest.to_string(),
                        size,
                        annotations: manifest.annotations,
                        artifact_type: manifest.artifact_type,
                    });
                }
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

    #[instrument(skip(self, source_reader))]
    async fn write_upload(
        &self,
        name: &str,
        uuid: &str,
        source_reader: Box<dyn AsyncRead + Send + Sync + Unpin>,
        append: bool,
    ) -> Result<(), RegistryError> {
        let key = self.tree.upload_path(name, uuid);

        let uploaded_size;
        let uploaded_parts;
        let upload_id;

        if append {
            upload_id = match self.search_multipart_upload_id(&key).await? {
                Some(upload_id) => upload_id,
                None => self.create_multipart_upload(&key).await?,
            };

            let (parts, parts_size) = self.search_multipart_upload_parts(&key, &upload_id).await?;

            uploaded_size = parts_size as usize;
            uploaded_parts = parts.len() as i32;
        } else {
            // TODO: cleanup eventual dangling multipart uploads
            upload_id = self.create_multipart_upload(&key).await?;
            uploaded_size = 0;
            uploaded_parts = 0;
        }

        let mut hasher = Sha256::new();

        // TODO: upload by chunks of fixed size
        let mut reader = BufReader::new(source_reader);
        let mut data = Vec::new();

        let read = reader.read_to_end(&mut data).await?;
        let total_size = (uploaded_size + read) as u64;

        hasher.update(&data);

        self.upload_part(&key, &upload_id, uploaded_parts + 1, data)
            .await?;

        let state = serialize_hash_state(&hasher).await?;
        let hash_state_path = self
            .tree
            .upload_hash_context_path(name, uuid, "sha256", total_size);
        self.put_object(&hash_state_path, state).await?;

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

        let hash_state_path = self
            .tree
            .upload_hash_context_path(name, uuid, "sha256", size);
        let state = self.get_object_body_as_vec(&hash_state_path, None).await?;

        let hasher = deserialize_hash_state(state).await?;
        let digest = hasher.finalize();
        let digest = Digest::Sha256(hex::encode(digest));

        let date_path = self.tree.upload_start_date_path(name, uuid);
        let date = self.get_object_body_as_vec(&date_path, None).await?;
        let date = String::from_utf8(date).map_err(|e| {
            error!("Error reading upload start date: {}", e);
            RegistryError::InternalServerError(Some("Error reading upload start date".to_string()))
        })?;

        let start_date = fs::read_to_string(&date)
            .await
            .ok()
            .and_then(|date| DateTime::parse_from_rfc3339(&date).ok())
            .unwrap_or_default() // Fallbacks to epoch
            .with_timezone(&Utc);

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

        let (parts, size) = self.search_multipart_upload_parts(&key, &upload_id).await?;

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
            .await
            .map_err(|e| {
                error!("Error copying object: {:?}", e);
                RegistryError::InternalServerError(Some("Error copying object".to_string()))
            })?;

        let _res = self
            .s3_client
            .copy_object()
            .bucket(&self.bucket)
            .key(&blob_path)
            .copy_source(format!("{}/{}", self.bucket, key))
            .send()
            .await
            .map_err(|e| {
                error!("Error copying object: {:?}", e);
                RegistryError::InternalServerError(Some("Error copying object".to_string()))
            })?;

        self.blob_link_index_update(name, &digest, |_| {}).await?;

        // NOTE: in case of error, remaining parts will be deleted by the scrub job
        let key = self.tree.upload_container_path(name, uuid);
        let _ = self.delete_object_with_prefix(&key).await;

        Ok(digest)
    }

    #[instrument(skip(self))]
    async fn delete_upload(&self, name: &str, uuid: &str) -> Result<(), RegistryError> {
        let upload_path = self.tree.upload_container_path(name, uuid);
        // TODO: abort eventual dangling multipart uploads
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
        self.get_object_body_as_stream(&path, start_offset).await
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

        let link = String::from_utf8(data).map_err(|e| {
            error!("Error reading link: {}", e);
            RegistryError::InternalServerError(Some("Error reading link".to_string()))
        })?;

        Digest::from_str(&link)
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
