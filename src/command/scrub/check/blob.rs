use crate::oci::Digest;
use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::link_kind::LinkKind;
use crate::registry::metadata_store::{BlobIndexOperation, MetadataStore};
use crate::registry::Error;
use std::sync::Arc;
use tracing::{debug, error, info};

pub struct BlobChecker {
    blob_store: Arc<dyn BlobStore + Send + Sync>,
    metadata_store: Arc<dyn MetadataStore + Send + Sync>,
    dry_run: bool,
}

impl BlobChecker {
    pub fn new(
        blob_store: Arc<dyn BlobStore + Send + Sync>,
        metadata_store: Arc<dyn MetadataStore + Send + Sync>,
        dry_run: bool,
    ) -> Self {
        Self {
            blob_store,
            metadata_store,
            dry_run,
        }
    }

    pub async fn check_all(&self) -> Result<(), Error> {
        debug!("Checking blobs");

        let mut marker = None;
        loop {
            let (blobs, next_marker) = self.blob_store.list_blobs(100, marker).await?;

            for blob in &blobs {
                if let Err(e) = self.check_blob(blob).await {
                    error!("Failed to process blob index for {blob}: {e}");
                }
            }

            if next_marker.is_none() {
                break;
            }
            marker = next_marker;
        }

        Ok(())
    }

    async fn check_blob(&self, blob: &Digest) -> Result<(), Error> {
        debug!("Checking blob index for blob '{blob}'");
        let blob_index = self.metadata_store.read_blob_index(blob).await?;

        for (namespace, references) in blob_index.namespace {
            for link in references {
                if self
                    .metadata_store
                    .read_link(&namespace, &link, false)
                    .await
                    .is_err()
                {
                    if let Err(err) = self.remove_invalid_link(&namespace, blob, &link).await {
                        error!(
                            "Failed to remove invalid link '{link}' from blob index '{namespace}/{blob}': {err}"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    async fn remove_invalid_link(
        &self,
        namespace: &str,
        blob: &Digest,
        link: &LinkKind,
    ) -> Result<(), Error> {
        if self.dry_run {
            info!(
                "DRY RUN: would remove invalid link from blob index '{namespace}/{blob}': '{link}'"
            );
            return Ok(());
        }

        info!("Removing invalid link from blob index '{namespace}/{blob}': '{link}'");
        self.metadata_store
            .update_blob_index(namespace, blob, BlobIndexOperation::Remove(link.clone()))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::Digest;
    use crate::registry::metadata_store::BlobIndexOperation;
    use crate::registry::test_utils;
    use crate::registry::tests::backends;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_cleanup_orphan_blobs_removes_invalid_index_entries() {
        for test_case in backends() {
            let namespace = "test-repo/app";
            let registry = test_case.registry();
            let metadata_store = test_case.metadata_store();
            let blob_store = test_case.blob_store();

            let (blob_digest, _) =
                test_utils::create_test_blob(registry, namespace, b"test content").await;

            let orphan_layer_link = LinkKind::Layer(
                Digest::from_str(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
            );
            metadata_store
                .update_blob_index(
                    namespace,
                    &blob_digest,
                    BlobIndexOperation::Insert(orphan_layer_link.clone()),
                )
                .await
                .unwrap();

            let blob_index_before = metadata_store.read_blob_index(&blob_digest).await.unwrap();

            let initial_refs = blob_index_before
                .namespace
                .get(namespace)
                .map_or(0, std::collections::HashSet::len);

            let scrubber = BlobChecker::new(blob_store.clone(), metadata_store.clone(), false);

            scrubber.check_all().await.unwrap();

            let blob_index_after = metadata_store.read_blob_index(&blob_digest).await.unwrap();

            let final_refs = blob_index_after
                .namespace
                .get(namespace)
                .map_or(0, std::collections::HashSet::len);

            assert!(
                final_refs < initial_refs,
                "Invalid blob index entry should be removed. Before: {initial_refs}, After: {final_refs}"
            );
        }
    }
}
