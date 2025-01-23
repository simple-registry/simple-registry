use crate::oci::Digest;
use crate::registry::notifying_reader::NotifyingReader;
use crate::registry::{Error, Registry};
use crate::storage::{EntityLink, Reader};
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use hyper::header::CONTENT_LENGTH;
use hyper::Method;
use tokio::io;
use tokio::io::AsyncRead;
use tokio_util::io::StreamReader;
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

impl Registry {
    #[instrument]
    pub async fn head_blob(
        &self,
        accepted_mime_types: &[String],
        namespace: &str,
        digest: Digest,
    ) -> Result<HeadBlobResponse, Error> {
        let (repository_name, repository) = self.validate_namespace(namespace)?;

        if repository.is_pull_through() {
            let res = repository
                .query_upstream_blob(
                    &Method::HEAD,
                    accepted_mime_types,
                    repository_name,
                    namespace,
                    &digest,
                )
                .await?;

            let digest = Self::parse_header(&res, "docker-content-digest")?;
            let size = Self::parse_header(&res, CONTENT_LENGTH)?;
            return Ok(HeadBlobResponse { digest, size });
        }

        let size = self.storage_engine.get_blob_size(&digest).await?;

        Ok(HeadBlobResponse { digest, size })
    }

    #[instrument]
    pub async fn get_blob(
        &self,
        accepted_mime_types: &[String],
        namespace: &str,
        digest: &Digest,
        range: Option<(u64, u64)>,
    ) -> Result<GetBlobResponse<impl Reader>, Error> {
        let (repository_name, repository) = self.validate_namespace(namespace)?;

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
                .query_upstream_blob(
                    &Method::GET,
                    accepted_mime_types,
                    repository_name,
                    namespace,
                    digest,
                )
                .await?;

            let total_length = Self::parse_header(&res, CONTENT_LENGTH)?;

            let stream = res
                .into_data_stream()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e));
            let reader = StreamReader::new(stream);

            let (stream_reader, mut receiver) =
                NotifyingReader::new(reader, self.streaming_chunk_size);

            let chunk_size = self.streaming_chunk_size;
            let digest = Some(digest.clone());
            let namespace = namespace.to_string();
            let storage_engine = self.storage_engine.clone();
            tokio::spawn(async move {
                let mut append = false;
                let session_id = Uuid::new_v4().to_string();
                let mut buffer = Vec::with_capacity(chunk_size);

                storage_engine
                    .create_upload(&namespace, &session_id)
                    .await?;
                while let Some(chunk) = receiver.recv().await {
                    buffer.extend_from_slice(&chunk);
                    if buffer.len() >= chunk_size {
                        let (current_part, next_part) = buffer.split_at(chunk_size);
                        debug!("Uploading chunk {:?} (len = {:?})", digest, buffer.len());
                        storage_engine
                            .write_upload(&namespace, &session_id, current_part, append)
                            .await?;

                        buffer = next_part.to_vec();
                        if !append {
                            append = true;
                        }
                    }
                }
                if !buffer.is_empty() {
                    debug!(
                        "Uploading final chunk {:?} (len = {:?})",
                        digest,
                        buffer.len()
                    );
                    storage_engine
                        .write_upload(&namespace, &session_id, &buffer, append)
                        .await?;
                }

                if let Err(e) = storage_engine
                    .complete_upload(&namespace, &session_id, digest)
                    .await
                {
                    debug!("Failed to complete upload: {:?}", e);
                    return Err(e);
                }

                Ok::<(), Error>(())
            });

            let reader: Box<dyn Reader> = Box::new(stream_reader);
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
