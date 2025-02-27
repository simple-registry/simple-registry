use crate::registry::data_store::DataStore;
use crate::registry::oci_types::Digest;
use crate::registry::{Error, Registry};
use tokio::io::AsyncRead;
use tracing::{error, instrument, warn};
use uuid::Uuid;

pub enum StartUploadResponse {
    ExistingBlob(Digest),
    Session(String, String),
}

impl<D: DataStore> Registry<D> {
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

    #[instrument(skip(stream))]
    pub async fn patch_upload<S>(
        &self,
        namespace: &str,
        session_id: Uuid,
        start_offset: Option<u64>,
        stream: S,
    ) -> Result<u64, Error>
    where
        S: AsyncRead + Unpin + Send + Sync,
    {
        self.validate_namespace(namespace)?;

        let session_id = session_id.to_string();
        if let Some(start_offset) = start_offset {
            let (_, size, _) = self
                .storage_engine
                .read_upload_summary(namespace, &session_id)
                .await?;

            if start_offset != size {
                return Err(Error::RangeNotSatisfiable);
            }
        };

        self.storage_engine
            .write_upload(namespace, &session_id, stream, true)
            .await?;

        let (_, size, _) = self
            .storage_engine
            .read_upload_summary(namespace, &session_id)
            .await
            .map_err(|e| {
                error!("Error reading uploaded file: {:?}", e);
                e
            })?;

        if size < 1 {
            return Ok(0);
        }

        Ok(size - 1)
    }

    #[instrument(skip(stream))]
    pub async fn complete_upload<S>(
        &self,
        namespace: &str,
        session_id: Uuid,
        digest: Digest,
        stream: S,
    ) -> Result<(), Error>
    where
        S: AsyncRead + Unpin + Send + Sync,
    {
        self.validate_namespace(namespace)?;

        let session_id = session_id.to_string();

        let append = self
            .storage_engine
            .read_upload_summary(namespace, &session_id)
            .await
            .is_ok();

        self.storage_engine
            .write_upload(namespace, &session_id, stream, append)
            .await?;

        let (upload_digest, _, _) = self
            .storage_engine
            .read_upload_summary(namespace, &session_id)
            .await?;

        if upload_digest != digest {
            warn!("Expected digest '{}', got '{}'", digest, upload_digest);
            return Err(Error::DigestInvalid);
        }

        self.storage_engine
            .complete_upload(namespace, &session_id, Some(digest))
            .await?;
        self.storage_engine
            .delete_upload(namespace, &session_id)
            .await?;

        Ok(())
    }

    #[instrument]
    pub async fn delete_upload(&self, namespace: &str, session_id: Uuid) -> Result<(), Error> {
        self.validate_namespace(namespace)?;

        let uuid = session_id.to_string();
        self.storage_engine.delete_upload(namespace, &uuid).await?;

        Ok(())
    }

    #[instrument]
    pub async fn get_upload_range_max(
        &self,
        namespace: &str,
        session_id: Uuid,
    ) -> Result<u64, Error> {
        self.validate_namespace(namespace)?;

        let uuid = session_id.to_string();
        let (_, size, _) = self
            .storage_engine
            .read_upload_summary(namespace, &uuid)
            .await?;

        if size < 1 {
            return Ok(0);
        }

        Ok(size - 1)
    }
}
