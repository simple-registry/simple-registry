mod backend;
mod entity_link;
mod entity_path_builder;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::digest::crypto_common::hazmat::SerializableState;
use sha2::{Digest as Sha256Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::{Debug, Formatter};
use tokio::io::AsyncRead;

use crate::configuration;
use crate::configuration::StorageConfig;
use crate::oci::{Descriptor, Digest};
use crate::registry::Error;

use crate::registry::lock_store::LockStore;
use crate::storage::backend::{filesystem, s3};
pub use entity_link::EntityLink;

pub struct UploadSummary {
    pub digest: Digest,
    pub size: u64,
    pub start_date: DateTime<Utc>,
}

pub fn build_storage_engine(
    storage_config: StorageConfig,
    lock_store: LockStore,
) -> Result<Box<dyn GenericStorageEngine>, configuration::Error> {
    if storage_config.fs.is_some() && storage_config.s3.is_some() {
        return Err(configuration::Error::StorageBackend(
            "Multiple storage backends are configured".to_string(),
        ));
    }

    if let Some(fs_config) = storage_config.fs {
        Ok(Box::new(filesystem::StorageEngine::new(
            fs_config, lock_store,
        )))
    } else if let Some(s3_config) = storage_config.s3 {
        Ok(Box::new(s3::StorageEngine::new(s3_config, lock_store)))
    } else {
        Err(configuration::Error::StorageBackend(
            "No storage backend is configured".to_string(),
        ))
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BlobEntityLinkIndex {
    pub namespace: HashMap<String, HashSet<EntityLink>>,
}

#[derive(Clone)]
pub struct ReferenceInfo {
    pub created_at: DateTime<Utc>,
    pub accessed_at: DateTime<Utc>,
}

pub trait Reader: AsyncRead + Unpin + Send {}
impl<T> Reader for T where T: AsyncRead + Unpin + Send {}

#[async_trait]
pub trait GenericStorageEngine: Send + Sync {
    async fn list_namespaces(
        &self,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error>;

    async fn list_tags(
        &self,
        namespace: &str,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error>;

    async fn list_referrers(
        &self,
        namespace: &str,
        digest: &Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, Error>;

    async fn list_uploads(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error>;

    async fn list_blobs(
        &self,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error>;

    async fn list_revisions(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error>;

    async fn create_upload(&self, namespace: &str, uuid: &str) -> Result<String, Error>;

    async fn write_upload(
        &self,
        namespace: &str,
        uuid: &str,
        source: &[u8],
        append: bool,
    ) -> Result<(), Error>;

    async fn read_upload_summary(
        &self,
        namespace: &str,
        uuid: &str,
    ) -> Result<UploadSummary, Error>;

    async fn complete_upload(
        &self,
        namespace: &str,
        uuid: &str,
        digest: Option<Digest>,
    ) -> Result<Digest, Error>;

    async fn delete_upload(&self, namespace: &str, uuid: &str) -> Result<(), Error>;

    async fn create_blob(&self, content: &[u8]) -> Result<Digest, Error>;

    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, Error>;

    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobEntityLinkIndex, Error>;

    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, Error>;

    async fn read_reference_info(
        &self,
        name: &str,
        reference: &EntityLink,
    ) -> Result<ReferenceInfo, Error>;

    async fn build_blob_reader(
        &self,
        digest: &Digest,
        start_offset: Option<u64>,
    ) -> Result<Box<dyn Reader>, Error>;

    async fn delete_blob(&self, digest: &Digest) -> Result<(), Error>;

    async fn update_last_pulled(&self, name: &str, reference: &EntityLink) -> Result<(), Error>;

    async fn read_link(&self, namespace: &str, reference: &EntityLink) -> Result<Digest, Error>;

    async fn create_link(
        &self,
        namespace: &str,
        reference: &EntityLink,
        digest: &Digest,
    ) -> Result<(), Error>;

    async fn delete_link(&self, namespace: &str, reference: &EntityLink) -> Result<(), Error>;
}

impl Debug for (dyn GenericStorageEngine + 'static) {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageEngine").finish()
    }
}

// Hash helpers

pub async fn serialize_hash_state(sha256: &Sha256) -> Result<Vec<u8>, Error> {
    let state = sha256.serialize();
    Ok(state.as_slice().to_vec())
}

pub async fn serialize_hash_empty_state() -> Result<Vec<u8>, Error> {
    let state = Sha256::new();
    serialize_hash_state(&state).await
}

pub async fn deserialize_hash_state(state: Vec<u8>) -> Result<Sha256, Error> {
    let state = state
        .as_slice()
        .try_into()
        .map_err(|_| Error::Internal(Some("Unable to resume hash state".to_string())))?;
    let state = Sha256::deserialize(state)?;
    let hasher = Sha256::from(state);

    Ok(hasher)
}
