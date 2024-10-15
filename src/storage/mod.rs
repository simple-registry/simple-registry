mod filesystem;
mod reference;
mod tree_manager;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sha2::Sha256;
use std::fmt;
use std::fmt::{Debug, Formatter};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};

use crate::error::RegistryError;
use crate::oci::{Descriptor, Digest};
use crate::registry::LinkReference;

pub use filesystem::FileSystemStorageEngine;
pub use reference::BlobReferenceIndex;

pub struct UploadSummary {
    pub digest: Digest,
    pub size: u64,
}

pub trait StorageEngineReader: AsyncSeek + AsyncRead + Unpin + Send {}
impl<T> StorageEngineReader for T where T: AsyncSeek + AsyncRead + Unpin + Send {}

pub trait StorageEngineWriter: AsyncWrite + Unpin + Send {}
impl<T> StorageEngineWriter for T where T: AsyncWrite + Unpin + Send {}

#[async_trait]
pub trait StorageEngine: Send + Sync {
    async fn list_namespaces(&self) -> Result<Box<dyn Iterator<Item = String>>, RegistryError>;

    async fn list_uploads(
        &self,
        namespace: &str,
    ) -> Result<
        Box<dyn Iterator<Item = (String, Option<Sha256>, Option<DateTime<Utc>>)>>,
        RegistryError,
    >;

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

    async fn build_upload_writer(
        &self,
        namespace: &str,
        uuid: &str,
        start_offset: Option<u64>,
    ) -> Result<Box<dyn StorageEngineWriter>, RegistryError>;

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
