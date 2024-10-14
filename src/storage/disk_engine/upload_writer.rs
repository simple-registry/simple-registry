use futures_util::ready;
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, SeekFrom};
use std::sync::Arc;
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWrite};
use tracing::error;
use uuid::Uuid;

use crate::error::RegistryError;
use crate::storage::disk_engine::{load_hash_state, save_hash_state};
use crate::storage::tree_manager::TreeManager;

pub struct DiskUploadWriter {
    file: File,
    hasher: Sha256,
    offset: u64,
    name: String,
    uuid: Uuid,
    tree_manager: Arc<TreeManager>,
}

impl DiskUploadWriter {
    pub async fn new(
        tree_manager: Arc<TreeManager>,
        name: &str,
        uuid: Uuid,
        offset: u64,
    ) -> Result<Self, RegistryError> {
        let file_path = tree_manager.upload_path(name, &uuid);
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .append(false)
            .write(true)
            .open(&file_path)
            .await
            .map_err(|e| {
                error!("Error opening upload file {:}: {}", file_path, e);
                if e.kind() == ErrorKind::NotFound {
                    RegistryError::BlobUploadUnknown
                } else {
                    RegistryError::InternalServerError(Some(
                        "Error opening upload file".to_string(),
                    ))
                }
            })?;

        file.seek(SeekFrom::Start(offset)).await?;

        let hasher = load_hash_state(&tree_manager, name, &uuid, "sha256", offset).await?;

        Ok(Self {
            file,
            hasher,
            offset,
            name: name.to_string(),
            uuid,
            tree_manager,
        })
    }

    fn save_hashstate_sync(&self) -> Result<(), RegistryError> {
        let storage = self.tree_manager.clone();
        let name = self.name.clone();
        let uuid = self.uuid;
        let offset = self.offset;

        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async move {
                save_hash_state(&storage, &self.hasher, &name, &uuid, "sha256", offset).await
            })
        })
    }
}

impl AsyncWrite for DiskUploadWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let n = ready!(std::pin::Pin::new(&mut self.file).poll_write(cx, buf))?;
        self.offset += n as u64;
        self.hasher.update(&buf[..n]);

        std::task::Poll::Ready(Ok(n))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if let Err(e) = self.save_hashstate_sync() {
            error!("Error saving hashstate: {:?}", e);
            return std::task::Poll::Ready(Err(std::io::Error::new(
                ErrorKind::Other,
                "Error saving hashstate",
            )));
        }
        std::pin::Pin::new(&mut self.file).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if let Err(e) = self.save_hashstate_sync() {
            error!("Error saving hashstate: {:?}", e);
            return std::task::Poll::Ready(Err(std::io::Error::new(
                ErrorKind::Other,
                "Error saving hashstate",
            )));
        }
        std::pin::Pin::new(&mut self.file).poll_shutdown(cx)
    }
}
