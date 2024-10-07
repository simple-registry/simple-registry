mod disk_engine;
mod tree_manager;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncWrite};
use uuid::Uuid;

use crate::error::RegistryError;
use crate::oci::{Descriptor, Digest, LinkReference};

pub use crate::storage::disk_engine::DiskStorageEngine;

pub struct UploadSummary {
    pub digest: Digest,
    pub size: u64,
}

#[async_trait]
pub trait StorageEngine {
    type Reader: AsyncSeek + AsyncRead + AsyncReadExt + Unpin + Send + 'static;
    type Writer: AsyncWrite + Unpin + Send;

    async fn read_catalog(
        &self,
        n: u32,
        last: String,
    ) -> Result<(Vec<String>, Option<String>), RegistryError>;

    async fn list_tags(
        &self,
        namespace: &str,
        n: u32,
        last: String,
    ) -> Result<(Vec<String>, Option<String>), RegistryError>;

    async fn list_referrers(
        &self,
        namespace: &str,
        digest: &Digest,
    ) -> Result<Vec<Descriptor>, RegistryError>;

    async fn create_upload(&self, namespace: &str, uuid: Uuid) -> Result<String, RegistryError>;

    async fn build_upload_writer(
        &self,
        namespace: &str,
        uuid: Uuid,
        start_offset: Option<u64>,
    ) -> Result<Self::Writer, RegistryError>;

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

    async fn get_blob_size(&self, digest: &Digest) -> Result<u64, RegistryError>;

    async fn build_blob_reader(
        &self,
        digest: &Digest,
        start_offset: Option<u64>,
    ) -> Result<Self::Reader, RegistryError>;

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
