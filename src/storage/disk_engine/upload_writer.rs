use futures_util::ready;
use log::error;
use sha2::digest::crypto_common::hazmat::SerializableState;
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, SeekFrom};
use std::sync::Arc;
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite};
use uuid::Uuid;

use crate::error::RegistryError;
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
        start_offset: u64,
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
                    RegistryError::NotFound
                } else {
                    RegistryError::InternalServerError
                }
            })?;

        file.seek(SeekFrom::Start(start_offset)).await?;

        let mut offset = 0;
        let mut hasher = Sha256::new();

        let offsets = tree_manager
            .list_hashstates(name, &uuid, "sha256")
            .await
            .unwrap_or_default();

        if let Some(&last_offset) = offsets.iter().filter(|&&o| o <= start_offset).last() {
            let state = tree_manager
                .load_hashstate(name, &uuid, "sha256", last_offset)
                .await?;
            let state = state
                .as_slice()
                .try_into()
                .map_err(|_| RegistryError::InternalServerError)?;
            let state = Sha256::deserialize(&state)?;
            offset = last_offset;
            hasher = Sha256::from(state)
        };

        // NOTE: this may be unnecessary since out-of-order uploads are not supported in the OCI spec.
        if start_offset > offset {
            let mut read_file = File::open(&file_path).await.map_err(|e| {
                error!("Error opening upload file for reading {}: {}", file_path, e);
                if e.kind() == ErrorKind::NotFound {
                    RegistryError::NotFound
                } else {
                    RegistryError::InternalServerError
                }
            })?;

            read_file.seek(SeekFrom::Start(offset)).await?;

            let mut buffer = [0u8; 8192];
            let mut bytes_to_read = start_offset - offset;

            while bytes_to_read > 0 {
                let n = read_file.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                let n = n as u64;
                let to_update = std::cmp::min(n, bytes_to_read) as usize;
                hasher.update(&buffer[..to_update]);
                offset += to_update as u64;
                bytes_to_read -= to_update as u64;
            }

            if offset != start_offset {
                return Err(RegistryError::InternalServerError);
            }
        }

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
        let hasher_state = self.hasher.clone();
        let storage = self.tree_manager.clone();
        let name = self.name.clone();
        let uuid = self.uuid;
        let offset = self.offset;

        let hasher_state = hasher_state.serialize();
        let hasher_state = hasher_state.as_slice().to_vec();

        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async move {
                storage
                    .save_hashstate(&name, &uuid, "sha256", offset, &hasher_state)
                    .await
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
