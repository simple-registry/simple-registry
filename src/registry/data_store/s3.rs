use crate::registry::data_store::Error;
use aws_sdk_s3::config::{timeout::TimeoutConfig, BehaviorVersion, Credentials, Region};
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_sdk_s3::{Client as S3Client, Config as S3Config};
use bytes::Bytes;
use bytesize::ByteSize;
use serde::Deserialize;
use std::io::{Error as IoError, ErrorKind};
use std::time::Duration;

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
    pub fn default_multipart_copy_threshold() -> ByteSize {
        ByteSize::gb(5)
    }

    pub fn default_multipart_copy_chunk_size() -> ByteSize {
        ByteSize::mb(100)
    }

    pub fn default_multipart_copy_jobs() -> usize {
        4
    }

    pub fn default_multipart_part_size() -> ByteSize {
        ByteSize::mib(50)
    }
}

#[derive(Clone)]
pub struct Backend {
    s3_client: S3Client,
    bucket: String,
    key_prefix: String,
}

impl Backend {
    pub fn new(config: &BackendConfig) -> Result<Self, Error> {
        if config.multipart_part_size < ByteSize::mib(5) {
            return Err(Error::Configuration(
                "Multipart part size must be at least 5MiB".to_string(),
            ));
        }

        if config.multipart_copy_chunk_size > ByteSize::gib(5) {
            return Err(Error::Configuration(
                "Multipart copy chunk size must be at most 5GiB".to_string(),
            ));
        }

        let credentials = Credentials::new(
            &config.access_key_id,
            &config.secret_key,
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
            .region(Region::new(config.region.clone()))
            .endpoint_url(&config.endpoint)
            .credentials_provider(credentials)
            .timeout_config(timeout)
            .force_path_style(true)
            .build();

        let s3_client = S3Client::from_conf(client_config);

        Ok(Self {
            s3_client,
            bucket: config.bucket.clone(),
            key_prefix: config.key_prefix.clone(),
        })
    }

    fn full_key(&self, path: &str) -> String {
        if self.key_prefix.is_empty() {
            path.to_string()
        } else {
            format!("{}/{}", self.key_prefix, path)
        }
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>, IoError> {
        let key = self.full_key(path);

        let result = self
            .s3_client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| {
                let service_error = e.into_service_error();
                if service_error.is_no_such_key() {
                    IoError::new(ErrorKind::NotFound, "object not found")
                } else {
                    IoError::other(service_error.to_string())
                }
            })?;

        let body = result
            .body
            .collect()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;

        Ok(body.into_bytes().to_vec())
    }

    pub async fn delete(&self, path: &str) -> Result<(), IoError> {
        let key = self.full_key(path);

        self.s3_client
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;

        Ok(())
    }

    pub async fn delete_prefix(&self, prefix: &str) -> Result<(), IoError> {
        let full_prefix = self.full_key(prefix);
        let mut continuation_token = None;

        loop {
            let res = self
                .s3_client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&full_prefix)
                .max_keys(1000)
                .set_continuation_token(continuation_token)
                .send()
                .await
                .map_err(|e| IoError::other(e.to_string()))?;

            for object in res.contents.unwrap_or_default() {
                if let Some(key) = object.key {
                    self.s3_client
                        .delete_object()
                        .bucket(&self.bucket)
                        .key(&key)
                        .send()
                        .await
                        .map_err(|e| IoError::other(e.to_string()))?;
                }
            }

            if res.is_truncated.unwrap_or(false) {
                continuation_token = res.next_continuation_token;
            } else {
                break;
            }
        }

        Ok(())
    }

    pub async fn object_size(&self, path: &str) -> Result<u64, IoError> {
        let key = self.full_key(path);

        let result = self
            .s3_client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| {
                let service_error = e.into_service_error();
                if service_error.is_not_found() {
                    IoError::new(ErrorKind::NotFound, "object not found")
                } else {
                    IoError::other(service_error.to_string())
                }
            })?;

        Ok(result
            .content_length
            .unwrap_or_default()
            .try_into()
            .unwrap_or(0))
    }

    pub async fn list_prefixes(
        &self,
        path: &str,
        delimiter: &str,
        max_keys: i32,
        continuation_token: Option<String>,
    ) -> Result<(Vec<String>, Vec<String>, Option<String>), IoError> {
        let mut full_prefix = self.full_key(path);
        // Ensure prefix ends with / if not empty to list items inside the directory
        if !full_prefix.is_empty() && !full_prefix.ends_with('/') {
            full_prefix.push('/');
        }

        let res = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&full_prefix)
            .delimiter(delimiter)
            .max_keys(max_keys)
            .set_continuation_token(continuation_token)
            .send()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;

        let mut prefixes = Vec::new();
        for prefix in res.common_prefixes.unwrap_or_default() {
            if let Some(p) = prefix.prefix {
                if let Some(name) = p.strip_prefix(&full_prefix) {
                    let name = name
                        .strip_suffix(delimiter)
                        .unwrap_or(name)
                        .trim_start_matches('/');
                    prefixes.push(name.to_string());
                }
            }
        }

        let mut objects = Vec::new();
        for object in res.contents.unwrap_or_default() {
            if let Some(key) = object.key {
                if let Some(name) = key.strip_prefix(&full_prefix) {
                    objects.push(name.to_string());
                }
            }
        }

        let next_token = if res.is_truncated.unwrap_or(false) {
            res.next_continuation_token
        } else {
            None
        };

        Ok((prefixes, objects, next_token))
    }

    pub async fn list_objects(
        &self,
        path: &str,
        max_keys: i32,
        continuation_token: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), IoError> {
        let mut full_prefix = self.full_key(path);
        // Ensure prefix ends with / if not empty to list items inside the directory
        if !full_prefix.is_empty() && !full_prefix.ends_with('/') {
            full_prefix.push('/');
        }

        let res = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&full_prefix)
            .max_keys(max_keys)
            .set_continuation_token(continuation_token)
            .send()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;

        let mut objects = Vec::new();
        for object in res.contents.unwrap_or_default() {
            if let Some(key) = object.key {
                let relative = if let Some(stripped) = key.strip_prefix(&full_prefix) {
                    stripped.trim_start_matches('/')
                } else {
                    &key
                };
                objects.push(relative.to_string());
            }
        }

        let next_token = if res.is_truncated.unwrap_or(false) {
            res.next_continuation_token
        } else {
            None
        };

        Ok((objects, next_token))
    }

    pub async fn get_object(
        &self,
        path: &str,
        offset: Option<u64>,
    ) -> Result<GetObjectOutput, IoError> {
        let key = self.full_key(path);
        let mut req = self.s3_client.get_object().bucket(&self.bucket).key(&key);

        if let Some(offset) = offset {
            req = req.range(format!("bytes={offset}-"));
        }

        req.send().await.map_err(|e| {
            let service_error = e.into_service_error();
            if service_error.is_no_such_key() {
                IoError::new(ErrorKind::NotFound, "object not found")
            } else {
                IoError::other(service_error.to_string())
            }
        })
    }

    pub async fn put_object(&self, path: &str, data: impl Into<Bytes>) -> Result<(), IoError> {
        let key = self.full_key(path);

        self.s3_client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(data.into()))
            .send()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;

        Ok(())
    }

    pub async fn copy_object(&self, source: &str, destination: &str) -> Result<(), IoError> {
        let source_key = self.full_key(source);
        let destination_key = self.full_key(destination);

        self.s3_client
            .copy_object()
            .bucket(&self.bucket)
            .key(&destination_key)
            .copy_source(format!("{}/{}", self.bucket, source_key))
            .send()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;

        Ok(())
    }

    pub async fn create_multipart_upload(&self, path: &str) -> Result<String, IoError> {
        let key = self.full_key(path);

        let res = self
            .s3_client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;

        res.upload_id
            .ok_or_else(|| IoError::other("upload_id not found in response"))
    }

    pub async fn upload_part(
        &self,
        path: &str,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
    ) -> Result<String, IoError> {
        let key = self.full_key(path);

        let res = self
            .s3_client
            .upload_part()
            .bucket(&self.bucket)
            .key(&key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;

        Ok(res.e_tag.unwrap_or_default())
    }

    pub async fn upload_part_copy(
        &self,
        source: &str,
        destination: &str,
        upload_id: &str,
        part_number: i32,
        range: Option<String>,
    ) -> Result<String, IoError> {
        let source_key = self.full_key(source);
        let destination_key = self.full_key(destination);

        let mut req = self
            .s3_client
            .upload_part_copy()
            .bucket(&self.bucket)
            .key(&destination_key)
            .upload_id(upload_id)
            .part_number(part_number)
            .copy_source(format!("{}/{}", self.bucket, source_key));

        if let Some(range) = range {
            req = req.copy_source_range(range);
        }

        let response = req
            .send()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;

        response
            .copy_part_result
            .and_then(|r| r.e_tag)
            .ok_or_else(|| IoError::other("e_tag not found in copy result"))
    }

    pub async fn complete_multipart_upload(
        &self,
        path: &str,
        upload_id: &str,
        parts: Vec<CompletedPart>,
    ) -> Result<(), IoError> {
        let key = self.full_key(path);

        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();

        self.s3_client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(&key)
            .upload_id(upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;

        Ok(())
    }

    pub async fn abort_multipart_upload(&self, path: &str, upload_id: &str) -> Result<(), IoError> {
        let key = self.full_key(path);

        self.s3_client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(&key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;

        Ok(())
    }

    pub async fn list_multipart_uploads(
        &self,
        prefix: Option<&str>,
    ) -> Result<Vec<(String, String)>, IoError> {
        let mut req = self.s3_client.list_multipart_uploads().bucket(&self.bucket);

        if let Some(prefix) = prefix {
            req = req.prefix(self.full_key(prefix));
        }

        let response = req
            .send()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;

        let mut uploads = Vec::new();
        for upload in response.uploads.unwrap_or_default() {
            if let (Some(key), Some(upload_id)) = (upload.key, upload.upload_id) {
                let relative_key = if let Some(stripped) = key.strip_prefix(&self.key_prefix) {
                    stripped.trim_start_matches('/')
                } else {
                    &key
                };
                uploads.push((relative_key.to_string(), upload_id));
            }
        }

        Ok(uploads)
    }

    pub async fn search_multipart_upload_id(&self, path: &str) -> Result<Option<String>, IoError> {
        let uploads = self.list_multipart_uploads(Some(path)).await?;

        for (upload_key, upload_id) in uploads {
            if upload_key == path {
                return Ok(Some(upload_id));
            }
        }

        Ok(None)
    }

    pub async fn get_object_body(
        &self,
        path: &str,
        offset: Option<u64>,
    ) -> Result<Vec<u8>, IoError> {
        let res = self.get_object(path, offset).await?;
        let body = res
            .body
            .collect()
            .await
            .map_err(|e| IoError::other(e.to_string()))?;
        Ok(body.to_vec())
    }

    pub async fn abort_pending_uploads(&self, path: &str) -> Result<(), IoError> {
        while let Some(upload_id) = self.search_multipart_upload_id(path).await? {
            self.abort_multipart_upload(path, &upload_id).await?;
        }
        Ok(())
    }

    pub async fn list_parts(
        &self,
        path: &str,
        upload_id: &str,
    ) -> Result<Vec<(i32, String, i64)>, IoError> {
        let key = self.full_key(path);
        let mut parts = Vec::new();
        let mut part_number_marker = None;

        loop {
            let mut req = self
                .s3_client
                .list_parts()
                .bucket(&self.bucket)
                .key(&key)
                .upload_id(upload_id);

            if let Some(marker) = part_number_marker {
                req = req.part_number_marker(marker);
            }

            let response = req
                .send()
                .await
                .map_err(|e| IoError::other(e.to_string()))?;

            for part in response.parts.unwrap_or_default() {
                if let (Some(part_number), Some(e_tag), Some(size)) =
                    (part.part_number, part.e_tag, part.size)
                {
                    parts.push((part_number, e_tag, size));
                }
            }

            if response.is_truncated.unwrap_or(false) {
                part_number_marker = response.next_part_number_marker;
            } else {
                break;
            }
        }

        Ok(parts)
    }
}
