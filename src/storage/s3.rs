use std::fmt::{Debug, Formatter};
// use std::sync::Arc;
// use std::time::Duration;

use async_trait::async_trait;
// use aws_sdk_s3::{
// config::timeout::TimeoutConfig,
// config::{BehaviorVersion, Credentials, Region},
//     Client as S3Client, Config as S3Config,
// };
use chrono::{DateTime, Utc};
use sha2::Sha256;
use tokio::io::AsyncRead;
use tracing::instrument;

use crate::config::StorageS3Config;
use crate::error::RegistryError;
use crate::lock_manager::LockManager;
use crate::oci::{Descriptor, Digest};
use crate::registry::LinkReference;
// use crate::storage::tree_manager::TreeManager;
use crate::storage::{BlobReferenceIndex, StorageEngine, StorageEngineReader, UploadSummary};

#[derive(Clone)]
pub struct S3StorageEngine {
    // s3_client: S3Client,
    // tree: Arc<TreeManager>,
    // bucket: String,
    // lock_manager: LockManager,
}

impl Debug for S3StorageEngine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3StorageEngine").finish()
    }
}

impl S3StorageEngine {
    pub fn new(
        _config: &StorageS3Config,
        _lock_manager: LockManager,
    ) -> Result<Self, RegistryError> {
        /*
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
            tree: Arc::new(TreeManager { config.key_prefix.unwrap_or_default() }),
            bucket: config.bucket.clone(),
            lock_manager,
        })
        */
        todo!("Implement this function")
    }
}

#[async_trait]
impl StorageEngine for S3StorageEngine {
    #[instrument(skip(self))]
    async fn list_namespaces(&self) -> Result<Box<dyn Iterator<Item = String>>, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn list_uploads(
        &self,
        _namespace: &str,
    ) -> Result<
        Box<dyn Iterator<Item = (String, Option<Sha256>, Option<DateTime<Utc>>)>>,
        RegistryError,
    > {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn list_blobs(&self) -> Result<Box<dyn Iterator<Item = Digest>>, RegistryError> {
        todo!("Implement this function")
    }

    async fn list_revisions(
        &self,
        _namespace: &str,
    ) -> Result<Box<dyn Iterator<Item = Digest>>, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn list_tags(
        &self,
        _name: &str,
    ) -> Result<Box<dyn Iterator<Item = String> + Send + Sync>, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn list_referrers(
        &self,
        _name: &str,
        _digest: &Digest,
        _artifact_type: Option<String>,
    ) -> Result<Box<dyn Iterator<Item = Descriptor>>, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn create_upload(&self, _name: &str, _uuid: &str) -> Result<String, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self, _source_reader))]
    async fn write_upload(
        &self,
        _name: &str,
        _uuid: &str,
        _source_reader: Box<dyn AsyncRead + Send + Sync + Unpin>,
        _append: bool,
    ) -> Result<(), RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn read_upload_summary(
        &self,
        _name: &str,
        _uuid: &str,
    ) -> Result<UploadSummary, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn complete_upload(
        &self,
        _name: &str,
        _uuid: &str,
        _digest: Option<Digest>,
    ) -> Result<Digest, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn delete_upload(&self, _name: &str, _uuid: &str) -> Result<(), RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self, _content))]
    async fn create_blob(&self, _content: &[u8]) -> Result<Digest, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn read_blob(&self, _digest: &Digest) -> Result<Vec<u8>, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn read_blob_index(&self, _digest: &Digest) -> Result<BlobReferenceIndex, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn get_blob_size(&self, _digest: &Digest) -> Result<u64, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn build_blob_reader(
        &self,
        _digest: &Digest,
        _start_offset: Option<u64>,
    ) -> Result<Box<dyn StorageEngineReader>, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn delete_blob(&self, _digest: &Digest) -> Result<(), RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn read_link(
        &self,
        name: &str,
        reference: &LinkReference,
    ) -> Result<Digest, RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn create_link(
        &self,
        namespace: &str,
        reference: &LinkReference,
        digest: &Digest,
    ) -> Result<(), RegistryError> {
        todo!("Implement this function")
    }

    #[instrument(skip(self))]
    async fn delete_link(
        &self,
        namespace: &str,
        reference: &LinkReference,
    ) -> Result<(), RegistryError> {
        todo!("Implement this function")
    }
}
