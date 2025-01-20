use crate::oci::Digest;
use crate::registry::{Error, Registry};
use futures_util::StreamExt;
use http_body_util::BodyDataStream;
use hyper::body::Incoming;
use hyper::Request;
use tracing::{debug, error, instrument, warn};
use uuid::Uuid;

pub enum StartUploadResponse {
    ExistingBlob(Digest),
    Session(String, String),
}

impl Registry {
    #[instrument]
    pub async fn start_upload(
        &self,
        namespace: &str,
        digest: Option<Digest>,
    ) -> Result<StartUploadResponse, Error> {
        self.validate_namespace(namespace)?;

        if let Some(digest) = digest {
            if self.storage_engine.get_blob_size(&digest).await.is_ok() {
                return Ok(StartUploadResponse::ExistingBlob(digest));
            }
        }

        let session_uuid = Uuid::new_v4().to_string();
        self.storage_engine
            .create_upload(namespace, &session_uuid)
            .await?;

        let location = format!("/v2/{namespace}/blobs/uploads/{session_uuid}");
        Ok(StartUploadResponse::Session(location, session_uuid))
    }

    #[instrument(skip(body))]
    pub async fn patch_upload(
        &self,
        namespace: &str,
        session_id: Uuid,
        start_offset: Option<u64>,
        body: BodyDataStream<Request<Incoming>>,
    ) -> Result<u64, Error> {
        self.validate_namespace(namespace)?;

        let session_id = session_id.to_string();
        if let Some(start_offset) = start_offset {
            let summary = self
                .storage_engine
                .read_upload_summary(namespace, &session_id)
                .await?;

            if start_offset != summary.size {
                return Err(Error::RangeNotSatisfiable);
            }
        };

        self.upload_body_chunk(namespace, &session_id, body, true)
            .await?;

        let summary = self
            .storage_engine
            .read_upload_summary(namespace, &session_id)
            .await
            .map_err(|e| {
                error!("Error reading uploaded file: {:?}", e);
                e
            })?;

        if summary.size < 1 {
            return Ok(0);
        }

        Ok(summary.size - 1)
    }

    #[instrument(skip(body))]
    pub async fn complete_upload(
        &self,
        namespace: &str,
        session_id: Uuid,
        digest: Digest,
        body: BodyDataStream<Request<Incoming>>,
    ) -> Result<(), Error> {
        self.validate_namespace(namespace)?;

        let session_id = session_id.to_string();

        self.upload_body_chunk(namespace, &session_id, body, false)
            .await?;

        let summary = self
            .storage_engine
            .read_upload_summary(namespace, &session_id)
            .await?;

        if summary.digest != digest {
            warn!("Expected digest '{}', got '{}'", digest, summary.digest);
            return Err(Error::DigestInvalid);
        }

        self.storage_engine
            .complete_upload(namespace, &session_id, Some(digest))
            .await?;
        self.storage_engine
            .delete_upload(namespace, &session_id)
            .await
    }

    async fn upload_body_chunk(
        &self,
        namespace: &str,
        session_id: &str,
        mut body: BodyDataStream<Request<Incoming>>, // TODO: is there a mean to share this logic with the pull through channel?
        mut append: bool,
    ) -> Result<(), Error> {
        let mut chunk = Vec::new();
        while let Some(frame) = body.next().await {
            let frame = frame.map_err(|e| {
                error!("Data stream error: {}", e);
                std::io::Error::new(std::io::ErrorKind::Other, e)
            })?;
            chunk.extend_from_slice(&frame);

            while chunk.len() >= self.streaming_chunk_size {
                debug!("Chunk too large, creating a part: {}", chunk.len());
                let (current_part, next_part) = chunk.split_at(self.streaming_chunk_size);

                self.storage_engine
                    .write_upload(namespace, session_id, current_part, append)
                    .await?;

                if !append {
                    append = true;
                }
                chunk = next_part.to_vec();
            }
        }

        if !chunk.is_empty() {
            debug!("Remaining chunk data, creating a part: {}", chunk.len());
            self.storage_engine
                .write_upload(namespace, session_id, &chunk, append)
                .await?;
        }

        Ok(())
    }

    #[instrument]
    pub async fn delete_upload(&self, namespace: &str, session_id: Uuid) -> Result<(), Error> {
        self.validate_namespace(namespace)?;

        let uuid = session_id.to_string();
        self.storage_engine.delete_upload(namespace, &uuid).await
    }

    #[instrument]
    pub async fn get_upload_range_max(
        &self,
        namespace: &str,
        session_id: Uuid,
    ) -> Result<u64, Error> {
        self.validate_namespace(namespace)?;

        let uuid = session_id.to_string();
        let summary = self
            .storage_engine
            .read_upload_summary(namespace, &uuid)
            .await?;

        if summary.size < 1 {
            return Ok(0);
        }

        Ok(summary.size - 1)
    }
}
