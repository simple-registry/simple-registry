#[cfg(test)]
mod tests;

use crate::registry::blob_store::{Error, LinkMetadata};
use crate::registry::metadata_store::MetadataStore;
use crate::registry::oci_types::{Descriptor, Digest, Manifest};
use crate::registry::utils::{BlobMetadata, DataPathBuilder};
use crate::registry::BlobLink;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::{debug, instrument};

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct BackendConfig {
    pub root_dir: String,
}

#[derive(Clone)]
pub struct Backend {
    pub tree: Arc<DataPathBuilder>,
}

impl Debug for Backend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FSBackend").finish()
    }
}

impl Backend {
    pub fn new(config: BackendConfig) -> Self {
        Self {
            tree: Arc::new(DataPathBuilder::new(config.root_dir)),
        }
    }

    // TODO: move to extension trait or utility module
    #[instrument(skip(path, contents))]
    async fn write_file<P>(path: P, contents: &[u8]) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut file = File::create(&path).await?;
        file.write_all(contents).await?;
        file.sync_all().await?;

        Ok(())
    }

    #[instrument]
    pub async fn delete_empty_parent_dirs(&self, path: &str) -> Result<(), Error> {
        let path = PathBuf::from(path);
        let root_dir = Path::new(&self.tree.prefix);

        let _ = fs::remove_dir_all(&path).await;

        let mut parent = path.parent();
        while let Some(parent_path) = parent {
            if parent_path == root_dir {
                break;
            }

            let mut entries = match fs::read_dir(parent_path).await {
                Ok(entries) => entries,
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e.into()),
            };

            if entries.next_entry().await?.is_some() {
                break;
            }

            debug!("Deleting empty parent dir: {}", parent_path.display());
            fs::remove_dir(parent_path).await?;

            parent = parent_path.parent();
        }

        Ok(())
    }

    #[instrument]
    pub async fn collect_directory_entries(&self, path: &str) -> Result<Vec<String>, Error> {
        let mut entries = Vec::new();
        let mut read_dir = match fs::read_dir(path).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(entries),
            Err(e) => return Err(e.into()),
        };

        while let Ok(Some(entry)) = read_dir.next_entry().await {
            entries.push(entry.file_name().to_string_lossy().to_string());
        }

        Ok(entries)
    }

    pub fn paginate<T>(
        items: &[T],
        n: u16,
        continuation_token: Option<String>,
    ) -> (Vec<T>, Option<String>)
    where
        T: Clone + ToString + Ord,
    {
        let start = match continuation_token {
            Some(token) => match items.iter().position(|item| item.to_string() == token) {
                Some(pos) => pos + 1,
                None => 0,
            },
            None => 0,
        };

        let end = (start + n as usize).min(items.len());
        let result = items[start..end].to_vec();

        let next_token = if !result.is_empty() && end < items.len() {
            Some(result.last().unwrap().to_string())
        } else {
            None
        };

        (result, next_token)
    }

    //

    #[instrument]
    async fn collect_repositories(&self, base_path: &Path) -> Vec<String> {
        let mut path_stack: Vec<PathBuf> = vec![base_path.to_path_buf()];
        let mut repositories = Vec::new();

        while let Some(current_path) = path_stack.pop() {
            if let Ok(mut entries) = fs::read_dir(&current_path).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();

                    if path.is_dir() {
                        debug!("checking path: {}", path.display());
                        // check entries starting with a "_": it means it's a repository
                        // add entries not starting with a "_" as paths to explore
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if name.starts_with('_') {
                                if let Some(name) =
                                    path.parent().and_then(|p| p.strip_prefix(base_path).ok())
                                {
                                    if let Some(name) = name.to_str() {
                                        debug!("Found repository: {name}");
                                        repositories.push(name.to_string());
                                    }
                                }
                            } else {
                                debug!("Exploring path: {}", path.display());
                                path_stack.push(path);
                            }
                        }
                    }
                }
            }
        }

        repositories.sort();
        repositories
    }
}

#[async_trait]
impl MetadataStore for Backend {
    #[instrument(skip(self))]
    async fn list_namespaces(
        &self,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        let base_path = self.tree.repository_dir();
        let base_path = Path::new(&base_path);

        let mut repositories = self.collect_repositories(base_path).await;
        repositories.dedup();

        Ok(Self::paginate(&repositories, n, last))
    }

    #[instrument(skip(self))]
    async fn list_tags(
        &self,
        namespace: &str,
        n: u16,
        last: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), Error> {
        let path = self.tree.manifest_tags_dir(namespace);
        debug!("Listing tags in path: {path}");
        let mut tags = self.collect_directory_entries(&path).await?;
        tags.sort();

        Ok(Self::paginate(&tags, n, last))
    }

    #[instrument(skip(self))]
    async fn list_referrers(
        &self,
        namespace: &str,
        digest: &Digest,
        artifact_type: Option<String>,
    ) -> Result<Vec<Descriptor>, Error> {
        let path = format!(
            "{}/sha256",
            self.tree.manifest_referrers_dir(namespace, digest)
        );
        let all_manifest = self.collect_directory_entries(&path).await?;
        let mut referrers = Vec::new();

        for manifest_digest in all_manifest {
            let manifest_digest = Digest::Sha256(manifest_digest);
            let blob_path = self.tree.blob_path(&manifest_digest);

            let manifest = fs::read(&blob_path).await?;
            let manifest_len = manifest.len();

            let manifest = Manifest::from_slice(&manifest)?;
            let Some(descriptor) = manifest.into_referrer_descriptor(artifact_type.as_ref()) else {
                continue;
            };

            referrers.push(Descriptor {
                digest: manifest_digest.to_string(),
                size: manifest_len as u64,
                ..descriptor
            });
        }

        Ok(referrers)
    }

    async fn list_revisions(
        &self,
        namespace: &str,
        n: u16,
        continuation_token: Option<String>,
    ) -> Result<(Vec<Digest>, Option<String>), Error> {
        let path = self
            .tree
            .manifest_revisions_link_root_dir(namespace, "sha256"); // HACK: hardcoded sha256

        let all_revisions = self.collect_directory_entries(&path).await?;
        let mut revisions = Vec::new();

        for revision in all_revisions {
            revisions.push(Digest::Sha256(revision));
        }

        Ok(Self::paginate(&revisions, n, continuation_token))
    }

    #[instrument(skip(self))]
    async fn read_blob_index(&self, digest: &Digest) -> Result<BlobMetadata, Error> {
        let path = self.tree.blob_index_path(digest);
        let content = fs::read_to_string(&path).await?;

        let index = serde_json::from_str(&content)?;
        Ok(index)
    }

    async fn update_blob_index<O>(
        &self,
        namespace: &str,
        digest: &Digest,
        operation: O,
    ) -> Result<(), Error>
    where
        O: FnOnce(&mut HashSet<BlobLink>) + Send,
    {
        debug!("Ensuring container directory for digest: {digest}");
        let path = self.tree.blob_container_dir(digest);
        fs::create_dir_all(&path).await?;

        debug!("Updating reference count for digest: {digest}");
        let path = self.tree.blob_index_path(digest);

        let mut reference_index = match fs::read_to_string(&path).await.map_err(Error::from) {
            Ok(content) => serde_json::from_str::<BlobMetadata>(&content)?,
            Err(Error::ReferenceNotFound) => BlobMetadata::default(),
            Err(e) => Err(e)?,
        };

        debug!("Updating reference index");
        if let Some(index) = reference_index.namespace.get_mut(namespace) {
            operation(index);
            if index.is_empty() {
                reference_index.namespace.remove(namespace);
            }
        } else {
            let mut index = HashSet::new();
            operation(&mut index);
            if !index.is_empty() {
                reference_index
                    .namespace
                    .insert(namespace.to_string(), index);
            }
        }

        if reference_index.namespace.is_empty() {
            debug!("Deleting no longer referenced Blob: {digest}");
            let path = self.tree.blob_container_dir(digest);
            let _ = self.delete_empty_parent_dirs(&path).await;
        } else {
            debug!("Writing reference count to path: {path}");
            let content = serde_json::to_string(&reference_index)?;
            Self::write_file(&path, content.as_bytes()).await?;
            debug!("Reference index for {digest} updated");
        }

        Ok(())
    }

    async fn read_link(&self, namespace: &str, link: &BlobLink) -> Result<LinkMetadata, Error> {
        let link_path = self.tree.get_link_path(link, namespace);

        let link = fs::read(&link_path).await?;
        Ok(LinkMetadata::from_bytes(link)?)
    }

    async fn write_link(
        &self,
        namespace: &str,
        link: &BlobLink,
        metadata: &LinkMetadata,
    ) -> Result<(), Error> {
        let link_path = self.tree.get_link_path(link, namespace);
        let serialized_link_data = serde_json::to_vec(metadata)?;
        Self::write_file(&link_path, &serialized_link_data).await
    }

    async fn delete_link(&self, namespace: &str, link: &BlobLink) -> Result<(), Error> {
        let path = self.tree.get_link_container_path(link, namespace);
        debug!("Deleting link at path: {path}");

        let _ = self.delete_empty_parent_dirs(&path).await;

        Ok(())
    }
}
