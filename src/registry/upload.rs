use bytes::Buf;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use log::debug;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::error::RegistryError;
use crate::oci::Digest;
use crate::registry::Registry;
use crate::storage::StorageEngine;

pub enum NewUpload {
    ExistingBlob(Digest),
    Session(String, Uuid),
}

impl<T> Registry<T>
where
    T: StorageEngine,
{
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

        let session_uuid = Uuid::new_v4();
        self.storage.create_upload(namespace, session_uuid).await?;

        let location = format!("/v2/{}/blobs/uploads/{}", namespace, session_uuid);
        Ok(NewUpload::Session(location, session_uuid))
    }

    pub async fn patch_upload(
        &self,
        namespace: &str,
        session_id: Uuid,
        start_offset: Option<u64>,
        body: Incoming,
    ) -> Result<u64, RegistryError> {
        self.validate_namespace(namespace)?;

        if let Some(start_offset) = start_offset {
            let summary = self
                .storage
                .read_upload_summary(namespace, session_id)
                .await?;

            if start_offset != summary.size {
                return Err(RegistryError::RangeNotSatisfiable);
            }
        };

        let mut writer = self
            .storage
            .build_upload_writer(namespace, session_id, start_offset)
            .await?;

        let mut body = body.into_data_stream();
        while let Some(data) = body.next().await {
            let data = data?;
            writer.write_all(data.chunk()).await?;
        }

        writer.flush().await?;

        let summary = self
            .storage
            .read_upload_summary(namespace, session_id)
            .await?;

        if summary.size < 1 {
            return Ok(0);
        }

        Ok(summary.size - 1)
    }

    pub async fn complete_upload(
        &self,
        namespace: &str,
        uuid: Uuid,
        digest: Digest,
        body: Incoming,
    ) -> Result<(), RegistryError> {
        self.validate_namespace(namespace)?;

        let mut writer = self
            .storage
            .build_upload_writer(namespace, uuid, None)
            .await?;

        let mut body = body.into_data_stream();
        while let Some(data) = body.next().await {
            let data = data?;
            writer.write_all(data.chunk()).await?;
        }
        writer.flush().await?;

        let summary = self.storage.read_upload_summary(namespace, uuid).await?;

        if summary.digest != digest {
            debug!(
                "Digest mismatch: expected {}, got {}",
                digest, summary.digest
            );
            return Err(RegistryError::DigestInvalid);
        }

        self.storage
            .complete_upload(namespace, uuid, Some(digest.clone()))
            .await?;
        self.storage.delete_upload(namespace, uuid).await
    }

    pub async fn delete_upload(&self, namespace: &str, uuid: Uuid) -> Result<(), RegistryError> {
        self.validate_namespace(namespace)?;

        self.storage.delete_upload(namespace, uuid).await
    }

    pub async fn get_upload_range_max(
        &self,
        namespace: &str,
        uuid: Uuid,
    ) -> Result<u64, RegistryError> {
        self.validate_namespace(namespace)?;

        let summary = self.storage.read_upload_summary(namespace, uuid).await?;

        if summary.size < 1 {
            return Ok(0);
        }

        Ok(summary.size - 1)
    }
}
