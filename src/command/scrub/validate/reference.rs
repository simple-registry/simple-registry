//! Blob-index reference validation: each `v2/ref/` key is probed against the
//! link backing it. Runs after the link pass, so every grant a manifest implies
//! has been re-issued before entries are pruned against the links.

use tracing::{debug, warn};

use angos_oci::{Digest, Namespace};
use angos_storage::Error as StorageError;

use crate::{
    command::{
        maintenance::{Error, action::Action},
        scrub::validate::Validator,
    },
    registry::{Error as RegistryError, metadata_store::LinkKind},
};

impl Validator {
    /// Validate one reference key of `digest`'s blob index: the link that
    /// backs it must still exist, or the key is removed.
    pub async fn validate_ref(
        &self,
        key: &str,
        digest: &Digest,
        namespace_raw: &str,
        link: LinkKind,
    ) -> Result<(), Error> {
        let Ok(namespace) = Namespace::new(namespace_raw) else {
            warn!("scrub: reference key '{key}' names invalid namespace '{namespace_raw}'");
            return Ok(());
        };
        // Witness for blob GC, an enumeration independent of the per-blob listing.
        self.record_reference_seen(digest);

        match self.blob_store.size(digest).await {
            Ok(_) => {}
            Err(RegistryError::BlobUnknown | RegistryError::NotFound) => {
                // Normal for an in-flight upload or a lazily filled cache
                // entry; the age-gated purge is prune's job.
                debug!("scrub: reference key '{key}' references byteless blob '{digest}'");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }

        // The blob's own ownership key carries the grant itself.
        if matches!(link, LinkKind::Blob(_)) {
            return Ok(());
        }
        // A key younger than the grace period may belong to a push between its
        // reference wave and its commit, whose backing does not exist yet. A
        // gone key reads as not-young, and the reverify below sees its absence.
        if self.younger_than_grace(key).await? {
            return Ok(());
        }
        // Only a confirmed-dead backing justifies removing the key; a transient
        // read error must not.
        if self
            .metadata_store
            .reference_backed(&namespace, &link, digest)
            .await?
        {
            return Ok(());
        }
        let namespace_ref = &namespace;
        let link_ref = &link;
        let reverify = move || self.ref_still_dangling(key, namespace_ref, link_ref, digest);
        if !reverify().await? {
            return Ok(());
        }
        self.emit(Action::RemoveBlobIndexLink {
            namespace,
            blob: digest.clone(),
            link,
        })
        .await
    }

    /// Re-observe a dangling reference key: it still exists while its backing
    /// is still dead.
    async fn ref_still_dangling(
        &self,
        key: &str,
        namespace: &Namespace,
        link: &LinkKind,
        blob: &Digest,
    ) -> Result<bool, Error> {
        match self.metadata_store.object_store().head(key).await {
            Ok(_) => {}
            Err(StorageError::NotFound) => return Ok(false),
            Err(e) => return Err(RegistryError::from(e).into()),
        }
        Ok(!self
            .metadata_store
            .reference_backed(namespace, link, blob)
            .await?)
    }
}
