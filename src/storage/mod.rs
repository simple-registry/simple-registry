mod filesystem;
mod reference;
mod s3;
mod tree_manager;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sha2::digest::crypto_common::hazmat::SerializableState;
use sha2::{Digest as Sha256Digest, Sha256};
use std::fmt;
use std::fmt::{Debug, Formatter};
use tokio::io::AsyncRead;

pub use filesystem::FileSystemStorageEngine;
pub use reference::BlobReferenceIndex;
pub use s3::S3StorageEngine;

use crate::error::RegistryError;
use crate::oci::{Descriptor, Digest};
use crate::registry::LinkReference;

pub struct UploadSummary {
    pub digest: Digest,
    pub size: u64,
}

pub trait StorageEngineReader: AsyncRead + Unpin + Send {}
impl<T> StorageEngineReader for T where T: AsyncRead + Unpin + Send {}

#[async_trait]
pub trait StorageEngine: Send + Sync {
    async fn list_namespaces(&self) -> Result<Box<dyn Iterator<Item = String>>, RegistryError>;

    async fn list_uploads(
        &self,
        namespace: &str,
    ) -> Result<Box<dyn Iterator<Item = (String, Option<DateTime<Utc>>)>>, RegistryError>;

    async fn list_blobs(&self) -> Result<Box<dyn Iterator<Item = Digest>>, RegistryError>;

    async fn list_revisions(
        &self,
        namespace: &str,
    ) -> Result<Box<dyn Iterator<Item = Digest>>, RegistryError>;

    async fn list_tags(
        &self,
        namespace: &str,
    ) -> Result<Box<dyn Iterator<Item = String> + Send + Sync>, RegistryError>;

    async fn list_referrers(
        &self,
        namespace: &str,
        digest: &Digest,
        artifact_type: Option<String>,
    ) -> Result<Box<dyn Iterator<Item = Descriptor>>, RegistryError>;

    async fn create_upload(&self, namespace: &str, uuid: &str) -> Result<String, RegistryError>;

    async fn write_upload(
        &self,
        namespace: &str,
        uuid: &str,
        source_reader: Box<dyn AsyncRead + Send + Sync + Unpin>,
        append: bool,
    ) -> Result<(), RegistryError>;

    async fn read_upload_summary(
        &self,
        namespace: &str,
        uuid: &str,
    ) -> Result<UploadSummary, RegistryError>;

    async fn complete_upload(
        &self,
        namespace: &str,
        uuid: &str,
        digest: Option<Digest>,
    ) -> Result<Digest, RegistryError>;

    async fn delete_upload(&self, namespace: &str, uuid: &str) -> Result<(), RegistryError>;

    async fn create_blob(&self, content: &[u8]) -> Result<Digest, RegistryError>;

    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, RegistryError>;

    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobReferenceIndex, RegistryError>;

    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, RegistryError>;

    async fn build_blob_reader(
        &self,
        digest: &Digest,
        start_offset: Option<u64>,
    ) -> Result<Box<dyn StorageEngineReader>, RegistryError>;

    async fn delete_blob(&self, digest: &Digest) -> Result<(), RegistryError>;

    async fn read_link(
        &self,
        namespace: &str,
        reference: &LinkReference,
    ) -> Result<Digest, RegistryError>;

    async fn create_link(
        &self,
        namespace: &str,
        reference: &LinkReference,
        digest: &Digest,
    ) -> Result<(), RegistryError>;

    async fn delete_link(
        &self,
        namespace: &str,
        reference: &LinkReference,
    ) -> Result<(), RegistryError>;
}

impl Debug for (dyn StorageEngine + 'static) {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageEngine").finish()
    }
}

// Hash helpers

pub async fn serialize_hash_state(sha256: &Sha256) -> Result<Vec<u8>, RegistryError> {
    let state = sha256.serialize();
    Ok(state.as_slice().to_vec())
}

pub async fn serialize_hash_empty_state() -> Result<Vec<u8>, RegistryError> {
    let state = Sha256::new();
    serialize_hash_state(&state).await
}

pub async fn deserialize_hash_state(state: Vec<u8>) -> Result<Sha256, RegistryError> {
    let state = state.as_slice().try_into().map_err(|_| {
        RegistryError::InternalServerError(Some("Unable to resume hash state".to_string()))
    })?;
    let state = Sha256::deserialize(state)?;
    let hasher = Sha256::from(state);

    Ok(hasher)
}
