use crate::registry::{blob_store, metadata_store};
use serde::Deserialize;
use std::io::ErrorKind;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct BackendConfig {
    pub root_dir: String,
}

impl From<blob_store::fs::BackendConfig> for BackendConfig {
    fn from(config: blob_store::fs::BackendConfig) -> Self {
        Self {
            root_dir: config.root_dir,
        }
    }
}

impl From<metadata_store::fs::BackendConfig> for BackendConfig {
    fn from(config: metadata_store::fs::BackendConfig) -> Self {
        Self {
            root_dir: config.root_dir,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Backend {
    root: PathBuf,
}

impl Backend {
    pub fn new(config: BackendConfig) -> Self {
        Self {
            root: config.root_dir.into(),
        }
    }

    fn full_path(&self, path: &str) -> PathBuf {
        self.root.join(path)
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>, std::io::Error> {
        fs::read(self.full_path(path)).await
    }

    pub async fn read_to_string(&self, path: &str) -> Result<String, std::io::Error> {
        fs::read_to_string(self.full_path(path)).await
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<(), std::io::Error> {
        let full_path = self.full_path(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let mut file = fs::File::create(full_path).await?;
        file.write_all(data).await?;
        file.sync_all().await?;
        Ok(())
    }

    #[cfg(test)]
    pub async fn delete(&self, path: &str) -> Result<(), std::io::Error> {
        let full_path = self.full_path(path);
        match fs::remove_file(&full_path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub async fn delete_dir(&self, path: &str) -> Result<(), std::io::Error> {
        let full_path = self.full_path(path);
        match fs::remove_dir_all(&full_path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub async fn file_size(&self, path: &str) -> Result<u64, std::io::Error> {
        let metadata = fs::metadata(self.full_path(path)).await?;
        Ok(metadata.len())
    }

    pub async fn list_dir(&self, path: &str) -> Result<Vec<String>, std::io::Error> {
        let full_path = self.full_path(path);
        let mut entries = Vec::new();

        let mut read_dir = match fs::read_dir(full_path).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(entries),
            Err(e) => return Err(e),
        };

        while let Some(entry) = read_dir.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                entries.push(name.to_string());
            }
        }

        Ok(entries)
    }

    pub async fn delete_empty_parent_dirs(&self, path: &str) -> Result<(), std::io::Error> {
        let full_path = self.full_path(path);
        let mut current_path = full_path.parent();

        while let Some(parent_path) = current_path {
            if parent_path == self.root || !parent_path.starts_with(&self.root) {
                break;
            }

            let Ok(mut entries) = fs::read_dir(parent_path).await else {
                break;
            };

            if entries.next_entry().await?.is_some() {
                break;
            }

            fs::remove_dir(parent_path).await?;
            current_path = parent_path.parent();
        }

        Ok(())
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<(), std::io::Error> {
        let from_path = self.full_path(from);
        let to_path = self.full_path(to);

        if let Some(parent) = to_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        fs::rename(from_path, to_path).await
    }

    pub async fn open_file(&self, path: &str) -> Result<fs::File, std::io::Error> {
        fs::File::open(self.full_path(path)).await
    }

    pub async fn create_file(&self, path: &str) -> Result<fs::File, std::io::Error> {
        let full_path = self.full_path(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::File::create(full_path).await
    }

    pub async fn open_file_append(&self, path: &str) -> Result<fs::File, std::io::Error> {
        let full_path = self.full_path(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(full_path)
            .await
    }
}
