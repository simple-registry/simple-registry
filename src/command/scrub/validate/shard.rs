//! Blob-index reference validation. Legacy `refs/{ns}.json` shards are
//! converted into per-link reference keys; each reference key is then probed
//! against the link that backs it. Runs after the link pass, so every grant a
//! manifest implies has been re-issued before entries are pruned against the
//! links.

use std::collections::HashSet;

use tracing::{debug, warn};

use angos_oci::{Digest, Namespace};
use angos_tx_engine::StorageError;

use crate::{
    command::{
        maintenance::{
            Error,
            action::{Action, WalkedStore},
        },
        scrub::validate::Validator,
    },
    registry::{Error as RegistryError, metadata_store::LinkKind, path_builder},
};

impl Validator {
    /// Convert one legacy `refs/{ns}.json` shard of `digest`'s blob index
    /// into reference keys. Content defects keep their old handling (corrupt
    /// and empty shards are deleted, an invalid name is left alone); a healthy
    /// shard is rewritten as keys and deleted, keys first, and its entries are
    /// validated by the reference-key walk that follows.
    pub async fn validate_shard(
        &self,
        key: &str,
        digest: &Digest,
        namespace_raw: &str,
    ) -> Result<(), Error> {
        let raw = match self.metadata_store.store().object_store().get(key).await {
            Ok(raw) => raw,
            Err(StorageError::NotFound) => return Ok(()),
            Err(e) => return Err(RegistryError::from(e).into()),
        };
        let Ok(links) = serde_json::from_slice::<HashSet<LinkKind>>(&raw) else {
            // Unreadable shard content: delete; the next run's link pass
            // re-grants every entry a manifest implies (a grant cannot land
            // on unreadable shard content this run). Hold the blob out of
            // this run's GC so the vanished references do not read as orphan.
            warn!("scrub: blob-index shard '{key}' does not parse; deleting");
            self.hold_blob_gc(digest);
            return self.delete_corrupt(WalkedStore::Metadata, key).await;
        };
        let Ok(namespace) = Namespace::new(namespace_raw) else {
            warn!("scrub: blob-index shard '{key}' names invalid namespace '{namespace_raw}'");
            return Ok(());
        };
        if links.is_empty() {
            // The old write path deleted a shard when its set emptied; a
            // persisted empty set is degenerate leftover.
            return self.delete_corrupt(WalkedStore::Metadata, key).await;
        }
        // Witness for blob GC, which otherwise decides from a per-blob listing:
        // the walk reached this shard through a whole-store scan, so the two
        // enumerations can be compared.
        self.record_shard_reference(digest);

        // Reference keys spell out only foreign digests, so an entry whose
        // self-digest is not the shard's blob cannot be represented. No angos
        // writer produces such an entry; converting it would alias a real one,
        // so it is dropped with the shard instead.
        let (links, nonsense): (Vec<LinkKind>, Vec<LinkKind>) = links
            .into_iter()
            .partition(|link| convertible(digest, link));
        for link in nonsense {
            warn!("scrub: dropping unrepresentable entry '{link}' of shard '{key}'");
        }

        self.emit(Action::ConvertBlobIndexShard {
            key: key.to_string(),
            namespace,
            blob: digest.clone(),
            links,
        })
        .await
    }

    /// Validate one reference key of `digest`'s blob index: the link that
    /// backs it must still exist, or the key is removed. The per-entry probing
    /// the legacy shard pass used to do, one key at a time.
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
        // Witness for blob GC, as for the shards above.
        self.record_shard_reference(digest);

        match self.blob_store.size(digest).await {
            Ok(_) => {}
            Err(RegistryError::BlobUnknown | RegistryError::NotFound) => {
                // Bytes absent: an in-flight upload that granted before its
                // bytes landed, or a pull-through cache entry whose bytes are
                // fetched lazily. Normal state; the age-gated purge is
                // prune's job, so no warning here.
                debug!("scrub: reference key '{key}' references byteless blob '{digest}'");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }

        // The blob's own ownership key carries the grant itself.
        if matches!(link, LinkKind::Blob(_)) {
            return Ok(());
        }
        // Only a confirmed-dead backing justifies removing the key; a
        // transient read error must not. The reads are raw so the metadata
        // cache cannot mask this run's repairs.
        if self.ref_backed(&namespace, &link, digest).await? {
            return Ok(());
        }
        let evidence = [key.to_string(), path_builder::link_path(&link, &namespace)];
        let namespace_ref = &namespace;
        let link_ref = &link;
        let reverify = move || self.ref_still_dangling(key, namespace_ref, link_ref, digest);
        if !self.confirm_repair(&evidence, reverify).await? {
            return Ok(());
        }
        self.emit(Action::RemoveBlobIndexLink {
            namespace,
            blob: digest.clone(),
            link,
        })
        .await
    }

    /// Whether the link behind a reference key still backs it: a tag backs
    /// its key while it resolves to the blob, every other kind while its link
    /// file exists.
    async fn ref_backed(
        &self,
        namespace: &Namespace,
        link: &LinkKind,
        blob: &Digest,
    ) -> Result<bool, Error> {
        if matches!(link, LinkKind::Tag(_)) {
            return match self
                .metadata_store
                .read_link_reference(namespace, link)
                .await
            {
                Ok(metadata) => Ok(&metadata.target == blob),
                Err(RegistryError::NotFound) => Ok(false),
                Err(e) => Err(e.into()),
            };
        }
        let link_key = path_builder::link_path(link, namespace);
        match self
            .metadata_store
            .store()
            .object_store()
            .head(&link_key)
            .await
        {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound) => Ok(false),
            Err(e) => Err(RegistryError::from(e).into()),
        }
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
        match self.metadata_store.store().object_store().head(key).await {
            Ok(_) => {}
            Err(StorageError::NotFound) => return Ok(false),
            Err(e) => return Err(RegistryError::from(e).into()),
        }
        Ok(!self.ref_backed(namespace, link, blob).await?)
    }
}

/// Whether a legacy shard entry is representable as a reference key of
/// `digest`: the kinds whose self-digest the key omits must actually name the
/// shard's blob.
fn convertible(digest: &Digest, link: &LinkKind) -> bool {
    match link {
        LinkKind::Blob(d) | LinkKind::Digest(d) | LinkKind::Layer(d) | LinkKind::Config(d) => {
            d == digest
        }
        LinkKind::Tag(_) => true,
        LinkKind::Referrer { referrer, .. } => referrer == digest,
        LinkKind::Manifest { child, .. } => child == digest,
    }
}
