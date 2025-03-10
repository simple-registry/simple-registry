mod error;
mod fs_backend;
mod s3_backend;

use crate::registry::oci_types::{Descriptor, Digest};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use tokio::io::AsyncRead;

pub use fs_backend::FSBackend;
pub use s3_backend::S3Backend;

use crate::registry::utils::DataLink;
pub use error::Error;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BlobEntityLinkIndex {
    pub namespace: HashMap<String, HashSet<DataLink>>,
}

#[derive(Clone)]
pub struct ReferenceInfo {
    pub created_at: DateTime<Utc>,
    pub accessed_at: DateTime<Utc>,
}

pub trait Reader: AsyncRead + Unpin + Send {}
impl<T> Reader for T where T: AsyncRead + Unpin + Send {}

#[async_trait]
pub trait DataStore: Send + Sync {
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

    async fn write_upload<S: AsyncRead + Unpin + Send + Sync>(
        &self,
        namespace: &str,
        uuid: &str,
        stream: S,
        append: bool,
    ) -> Result<(), Error>;

    async fn read_upload_summary(
        &self,
        namespace: &str,
        uuid: &str,
    ) -> Result<(Digest, u64, DateTime<Utc>), Error>;

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
        reference: &DataLink,
    ) -> Result<ReferenceInfo, Error>;

    async fn build_blob_reader(
        &self,
        digest: &Digest,
        start_offset: Option<u64>,
    ) -> Result<Box<dyn Reader>, Error>;

    async fn delete_blob(&self, digest: &Digest) -> Result<(), Error>;

    async fn update_last_pulled(
        &self,
        name: &str,
        tag: Option<String>,
        digest: &Digest,
    ) -> Result<(), Error>;

    async fn read_link(&self, namespace: &str, reference: &DataLink) -> Result<Digest, Error>;

    async fn create_link(
        &self,
        namespace: &str,
        reference: &DataLink,
        digest: &Digest,
    ) -> Result<(), Error>;

    async fn delete_link(&self, namespace: &str, reference: &DataLink) -> Result<(), Error>;
}
