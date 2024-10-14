mod filesystem;
mod reference;
mod tree_manager;

use async_trait::async_trait;
use std::fmt;
use std::fmt::{Debug, Formatter};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};
use uuid::Uuid;

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
    async fn read_catalog(
        &self,
        n: u32,
        last: String,
    ) -> Result<(Vec<String>, Option<String>), RegistryError>;

    async fn list_tags(
        &self,
        namespace: &str,
        pagination: Option<(u32, String)>,
    ) -> Result<(Vec<String>, Option<String>), RegistryError>;

    async fn list_referrers(
        &self,
        namespace: &str,
        digest: &Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, RegistryError>;

    async fn create_upload(&self, namespace: &str, uuid: Uuid) -> Result<String, RegistryError>;

    async fn build_upload_writer(
        &self,
        namespace: &str,
        uuid: Uuid,
        start_offset: Option<u64>,
    ) -> Result<Box<dyn StorageEngineWriter>, RegistryError>;

    async fn read_upload_summary(
        &self,
        namespace: &str,
        uuid: Uuid,
    ) -> Result<UploadSummary, RegistryError>;

    async fn complete_upload(
        &self,
        namespace: &str,
        uuid: Uuid,
        digest: Option<Digest>,
    ) -> Result<Digest, RegistryError>;

    async fn delete_upload(&self, namespace: &str, uuid: Uuid) -> Result<(), RegistryError>;

    async fn create_blob(&self, content: &[u8]) -> Result<Digest, RegistryError>;

    async fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>, RegistryError>;

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

pub fn paginate(items: &[String], n: u32, last: String) -> (Vec<String>, Option<String>) {
    let start = if last.is_empty() {
        0
    } else {
        items.iter().position(|x| x == &last).map_or(0, |i| i + 1)
    };

    let end = usize::min(start + n as usize, items.len());
    let next = if end < items.len() {
        Some(items[end - 1].clone())
    } else {
        None
    };

    (items[start..end].to_vec(), next)
}

impl Debug for (dyn StorageEngine + 'static) {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageEngine").finish()
    }
}
