use crate::configuration::StorageS3Config;
use crate::registry::blob_store::{Error, LinkMetadata};
use crate::registry::metadata_store::MetadataStore;
use crate::registry::oci_types::{Descriptor, Digest, Manifest};
use crate::registry::utils::{BlobMetadata, DataPathBuilder};
use crate::registry::BlobLink;
use async_trait::async_trait;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::{Client as S3Client, Config as S3Config};
use bytes::Bytes;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, instrument};

#[derive(Clone)]
pub struct S3Backend {
    s3_client: S3Client,
    tree: Arc<DataPathBuilder>,
    bucket: String,
}

impl S3Backend {
    // TODO: implement simplified S3 client
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
        }
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
}

#[async_trait]
impl MetadataStore for S3Backend {
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
    use crate::configuration::StorageS3Config;
    use crate::registry::blob_store;
    use crate::registry::metadata_store::tests::{
        test_datastore_link_operations, test_datastore_list_namespaces,
        test_datastore_list_referrers, test_datastore_list_revisions, test_datastore_list_tags,
    };
    use crate::registry::metadata_store::S3Backend;
    use bytesize::ByteSize;
    use uuid::Uuid;

    // Helper function to create a test S3Backend
    fn create_test_backend() -> (S3Backend, blob_store::S3Backend) {
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

        (
            S3Backend::new(config.clone()),
            blob_store::S3Backend::new(config),
        )
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

    // Generic BlobStore trait tests
    #[tokio::test]
    async fn test_list_namespaces() {
        let (backend, _) = create_test_backend();
        test_datastore_list_namespaces(&backend).await;
        cleanup_test_prefix(&backend).await;
    }

    #[tokio::test]
    async fn test_list_tags() {
        let (backend, _) = create_test_backend();
        test_datastore_list_tags(&backend).await;
        cleanup_test_prefix(&backend).await;
    }

    #[tokio::test]
    async fn test_list_referrers() {
        let (backend, blob_store) = create_test_backend();
        test_datastore_list_referrers(&blob_store, &backend).await;
        cleanup_test_prefix(&backend).await;
    }

    #[tokio::test]
    async fn test_list_revisions() {
        let (backend, _) = create_test_backend();
        test_datastore_list_revisions(&backend).await;
        cleanup_test_prefix(&backend).await;
    }

    #[tokio::test]
    async fn test_link_operations() {
        let (backend, _) = create_test_backend();
        test_datastore_link_operations(&backend).await;
        cleanup_test_prefix(&backend).await;
    }
}
