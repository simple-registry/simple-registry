use crate::oci::Digest;
use crate::registry::{Error, Registry};
use crate::storage::{EntityLink, Reader};
use tokio::io::AsyncRead;
use tracing::{instrument, warn};

pub enum GetBlobResponse<R>
where
    R: AsyncRead + Send + Unpin,
{
    Empty,
    Reader(R, u64),
    RangedReader(R, (u64, u64), u64),
}

pub struct HeadBlobResponse {
    pub digest: Digest,
    pub size: u64,
}

impl Registry {
    #[instrument]
    pub async fn head_blob(
        &self,
        namespace: &str,
        digest: Digest,
    ) -> Result<HeadBlobResponse, Error> {
        self.validate_namespace(namespace)?;

        let size = self.storage_engine.get_blob_size(&digest).await?;

        Ok(HeadBlobResponse { digest, size })
    }

    #[instrument]
    pub async fn get_blob(
        &self,
        namespace: &str,
        digest: &Digest,
        range: Option<(u64, u64)>,
    ) -> Result<GetBlobResponse<impl Reader>, Error> {
        self.validate_namespace(namespace)?;

        let total_length = self.storage_engine.get_blob_size(digest).await?;

        let start = if let Some((start, _)) = range {
            if start > total_length {
                warn!("Range start does not match content length");
                return Err(Error::RangeNotSatisfiable);
            }
            Some(start)
        } else {
            None
        };

        let reader = match self.storage_engine.build_blob_reader(digest, start).await {
            Ok(reader) => reader,
            Err(Error::BlobUnknown) => return Ok(GetBlobResponse::Empty),
            Err(err) => return Err(err),
        };

        match range {
            Some((start, end)) => Ok(GetBlobResponse::RangedReader(
                reader,
                (start, end),
                total_length,
            )),
            None => Ok(GetBlobResponse::Reader(reader, total_length)),
        }
    }

    #[instrument]
    pub async fn delete_blob(&self, namespace: &str, digest: Digest) -> Result<(), Error> {
        self.validate_namespace(namespace)?;

        let link = EntityLink::Layer(digest.clone());
        if let Err(e) = self.storage_engine.delete_link(namespace, &link).await {
            warn!("Failed to delete layer link: {:?}", e);
        }

        let link = EntityLink::Config(digest);
        if let Err(e) = self.storage_engine.delete_link(namespace, &link).await {
            warn!("Failed to delete config link: {:?}", e);
        }

        Ok(())
    }
}
