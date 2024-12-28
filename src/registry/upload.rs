use crate::error::RegistryError;
use crate::oci::Digest;
use crate::registry::Registry;
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use tokio_util::io::StreamReader;
use tracing::{debug, error, instrument};
use uuid::Uuid;

pub enum NewUpload {
    ExistingBlob(Digest),
    Session(String, String),
}

impl Registry {
    #[instrument]
    pub async fn start_upload(
        &self,
        namespace: &str,
        digest: Option<Digest>,
    ) -> Result<NewUpload, RegistryError> {
        self.validate_namespace(namespace)?;

        if let Some(digest) = digest {
            if self.storage.get_blob_size(&digest).await.is_ok() {
                return Ok(NewUpload::ExistingBlob(digest));
            }
        }

        let session_uuid = Uuid::new_v4().to_string();
        self.storage.create_upload(namespace, &session_uuid).await?;

        let location = format!("/v2/{}/blobs/uploads/{}", namespace, session_uuid);
        Ok(NewUpload::Session(location, session_uuid))
    }

    #[instrument(skip(body))]
    pub async fn patch_upload(
        &self,
        namespace: &str,
        session_id: Uuid,
        start_offset: Option<u64>,
        body: Incoming,
    ) -> Result<u64, RegistryError> {
        self.validate_namespace(namespace)?;

        let session_id = session_id.to_string();
        if let Some(start_offset) = start_offset {
            let summary = self
                .storage
                .read_upload_summary(namespace, &session_id)
                .await?;

            if start_offset != summary.size {
                return Err(RegistryError::RangeNotSatisfiable);
            }
        };

        let body = body.into_data_stream().map_err(|e| {
            error!("Data stream error: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        });
        let body = StreamReader::new(body);

        self.storage
            .write_upload(namespace, &session_id, Box::new(body), true)
            .await?;

        let summary = self
            .storage
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
        body: Incoming,
    ) -> Result<(), RegistryError> {
        self.validate_namespace(namespace)?;

        let uuid = session_id.to_string();
        let body = body.into_data_stream().map_err(|e| {
            error!("Data stream error: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        });
        let body = StreamReader::new(body);

        self.storage
            .write_upload(namespace, &uuid, Box::new(body), false)
            .await?;

        let summary = self.storage.read_upload_summary(namespace, &uuid).await?;

        if summary.digest != digest {
            debug!(
                "Digest mismatch: expected {}, got {}",
                digest, summary.digest
            );
            return Err(RegistryError::DigestInvalid);
        }

        self.storage
            .complete_upload(namespace, &uuid, Some(digest.clone()))
            .await?;
        self.storage.delete_upload(namespace, &uuid).await
    }

    #[instrument]
    pub async fn delete_upload(
        &self,
        namespace: &str,
        session_id: Uuid,
    ) -> Result<(), RegistryError> {
        self.validate_namespace(namespace)?;

        let uuid = session_id.to_string();
        self.storage.delete_upload(namespace, &uuid).await
    }

    #[instrument]
    pub async fn get_upload_range_max(
        &self,
        namespace: &str,
        session_id: Uuid,
    ) -> Result<u64, RegistryError> {
        self.validate_namespace(namespace)?;

        let uuid = session_id.to_string();
        let summary = self.storage.read_upload_summary(namespace, &uuid).await?;

        if summary.size < 1 {
            return Ok(0);
        }

        Ok(summary.size - 1)
    }
}
