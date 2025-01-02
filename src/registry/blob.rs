use crate::error::RegistryError;
use crate::oci::Digest;
use crate::registry::{LinkReference, Registry};
use crate::storage::StorageEngineReader;
use tokio::io::AsyncRead;
use tracing::{instrument, warn};

pub enum BlobData<R>
where
    R: AsyncRead + Send + Unpin,
{
    Empty,
    Reader(R, u64),
    RangedReader(R, (u64, u64), u64),
}

pub struct BlobSummary {
    pub digest: Digest,
    pub size: u64,
}

impl Registry {
    #[instrument]
    pub async fn head_blob(
        &self,
        namespace: &str,
        digest: Digest,
    ) -> Result<BlobSummary, RegistryError> {
        self.validate_namespace(namespace)?;

        let size = self.storage.get_blob_size(&digest).await?;

        Ok(BlobSummary { digest, size })
    }

    #[instrument]
    pub async fn get_blob(
        &self,
        namespace: &str,
        digest: &Digest,
        range: Option<(u64, u64)>,
    ) -> Result<BlobData<impl StorageEngineReader>, RegistryError> {
        self.validate_namespace(namespace)?;

        let total_length = self.storage.get_blob_size(digest).await?;

        let start = if let Some((start, _)) = range {
            if start > total_length {
                warn!("Range start does not match content length");
                return Err(RegistryError::RangeNotSatisfiable);
            }
            Some(start)
        } else {
            None
        };

        let reader = match self.storage.build_blob_reader(digest, start).await {
            Ok(reader) => reader,
            Err(RegistryError::BlobUnknown) => return Ok(BlobData::Empty),
            Err(err) => return Err(err),
        };

        match range {
            Some((start, end)) => Ok(BlobData::RangedReader(reader, (start, end), total_length)),
            None => Ok(BlobData::Reader(reader, total_length)),
        }
    }

    #[instrument]
    pub async fn delete_blob(&self, namespace: &str, digest: Digest) -> Result<(), RegistryError> {
        self.validate_namespace(namespace)?;

        // TODO: ensure that the blob is not used by any other layer or config!
        let link = LinkReference::Layer(digest.clone());
        if let Err(e) = self.storage.delete_link(namespace, &link).await {
            warn!("Failed to delete layer link: {:?}", e);
        }

        let link = LinkReference::Config(digest.clone());
        if let Err(e) = self.storage.delete_link(namespace, &link).await {
            warn!("Failed to delete config link: {:?}", e);
        }

        Ok(())
    }
}
