mod blob;
mod manifest;
mod retention;
mod tag;
mod upload;

use crate::oci::Digest;
use crate::registry::metadata_store::link_kind::LinkKind;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::Error;
pub use blob::BlobChecker;
pub use manifest::ManifestChecker;
pub use retention::RetentionChecker;
use std::sync::Arc;
pub use tag::TagChecker;
use tracing::{debug, info};
pub use upload::UploadChecker;

pub async fn ensure_link(
    metadata_store: &Arc<dyn MetadataStore + Send + Sync>,
    namespace: &str,
    link: &LinkKind,
    expected_target: &Digest,
    dry_run: bool,
) -> Result<(), Error> {
    match metadata_store.read_link(namespace, link, false).await {
        Ok(metadata) if &metadata.target == expected_target => {
            debug!("Link {link} -> {expected_target} is valid");
            Ok(())
        }
        _ => {
            debug!("Missing or invalid link: {link} -> {expected_target}");
            recreate_link(metadata_store, namespace, link, expected_target, dry_run).await
        }
    }
}

async fn recreate_link(
    metadata_store: &Arc<dyn MetadataStore + Send + Sync>,
    namespace: &str,
    link: &LinkKind,
    target: &Digest,
    dry_run: bool,
) -> Result<(), Error> {
    if dry_run {
        info!("DRY RUN: would recreate invalid link from namespace '{namespace}': {link}' -> '{target}'");
        return Ok(());
    }

    info!("Recreating invalid link from namespace '{namespace}': {link}' -> '{target}'");
    if let Err(e) = metadata_store.delete_link(namespace, link).await {
        debug!("Failed to delete invalid link '{link}': {e}");
    }

    metadata_store.create_link(namespace, link, target).await?;
    Ok(())
}
