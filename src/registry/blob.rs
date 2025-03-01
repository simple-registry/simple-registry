use crate::registry::api::hyper::response_ext::IntoAsyncRead;
use crate::registry::api::hyper::response_ext::ResponseExt;
use crate::registry::api::hyper::DOCKER_CONTENT_DIGEST;
use crate::registry::data_store::{DataStore, Reader};
use crate::registry::oci_types::Digest;
use crate::registry::utils::{tee_reader, DataLink};
use crate::registry::{data_store, Error, Registry, Repository};
use hyper::header::CONTENT_LENGTH;
use hyper::Method;
use std::sync::Arc;
use tokio::io::AsyncRead;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

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

impl<D: DataStore + 'static> Registry<D> {
    #[instrument(skip(repository))]
    pub async fn head_blob(
        &self,
        repository: &Repository,
        accepted_mime_types: &[String],
        namespace: &str,
        digest: Digest,
    ) -> Result<HeadBlobResponse, Error> {
        if repository.is_pull_through() {
            let res = repository
                .query_upstream_blob(&Method::HEAD, accepted_mime_types, namespace, &digest)
                .await?;

            let digest = res.parse_header(DOCKER_CONTENT_DIGEST)?;
            let size = res.parse_header(CONTENT_LENGTH)?;
            return Ok(HeadBlobResponse { digest, size });
        }

        let size = self.storage_engine.get_blob_size(&digest).await?;

        Ok(HeadBlobResponse { digest, size })
    }

    #[instrument(skip(storage_engine, stream))]
    async fn copy_blob<E, S>(
        storage_engine: Arc<E>,
        stream: S,
        namespace: String,
        digest: Digest,
    ) -> Result<(), data_store::Error>
    where
        E: DataStore,
        S: AsyncRead + Send + Sync + Unpin,
    {
        let session_id = Uuid::new_v4().to_string();

        storage_engine
            .create_upload(&namespace, &session_id)
            .await?;

        storage_engine
            .write_upload(&namespace, &session_id, stream, false)
            .await?;

        if let Err(e) = storage_engine
            .complete_upload(&namespace, &session_id, Some(digest))
            .await
        {
            debug!("Failed to complete upload: {:?}", e);
            return Err(e);
        }

        Ok::<(), data_store::Error>(())
    }

    #[instrument(skip(repository))]
    pub async fn get_blob(
        &self,
        repository: &Repository,
        accepted_mime_types: &[String],
        namespace: &str,
        digest: &Digest,
        range: Option<(u64, u64)>,
    ) -> Result<GetBlobResponse<impl Reader>, Error> {
        if repository.is_pull_through() {
            if range.is_some() {
                warn!("Range requests are not supported for pull-through repositories");
                return Err(Error::RangeNotSatisfiable);
            }

            match self.get_local_blob(digest, range).await {
                Ok(local_blob) => {
                    debug!("Returning blob from local store: {:?}", digest);
                    return Ok(local_blob);
                }
                Err(e) => {
                    debug!(
                        "Failed to get blob from local store, pulling from upstream {:?}: {:?}",
                        digest, e
                    );
                }
            }

            let res = repository
                .query_upstream_blob(&Method::GET, accepted_mime_types, namespace, digest)
                .await?;

            let total_length = res.parse_header(CONTENT_LENGTH)?;

            let stream = res.into_async_read();
            let (response_reader, copy_reader) = tee_reader(stream).await?;

            tokio::spawn(Self::copy_blob(
                self.storage_engine.clone(),
                copy_reader,
                namespace.to_string(),
                digest.to_owned(),
            ));

            let reader: Box<dyn Reader> = Box::new(response_reader);
            return Ok(GetBlobResponse::Reader(reader, total_length));
        }

        self.get_local_blob(digest, range).await
    }

    async fn get_local_blob(
        &self,
        digest: &Digest,
        range: Option<(u64, u64)>,
    ) -> Result<GetBlobResponse<Box<dyn Reader>>, Error> {
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
            Err(data_store::Error::BlobNotFound) => return Ok(GetBlobResponse::Empty),
            Err(err) => Err(err)?,
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

        let link = DataLink::Layer(digest.clone());
        if let Err(e) = self.storage_engine.delete_link(namespace, &link).await {
            warn!("Failed to delete layer link: {:?}", e);
        }

        let link = DataLink::Config(digest);
        if let Err(e) = self.storage_engine.delete_link(namespace, &link).await {
            warn!("Failed to delete config link: {:?}", e);
        }

        Ok(())
    }
}
