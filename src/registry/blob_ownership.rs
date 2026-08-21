use std::collections::HashSet;

use angos_oci::{Digest, Namespace, UploadSessionId};

use crate::registry::{
    Error,
    blob_store::BlobStore,
    metadata_store::{BlobIndexOperation, LinkKind, MetadataStore},
};

/// Promote the upload session's staged bytes to the canonical blob path and
/// grant `namespace` its reference. No lock is needed: fresh bytes and a fresh
/// `_own` key sit inside the collector's grace period, and both steps are
/// idempotent.
pub async fn promote_and_grant(
    blob_store: &BlobStore,
    metadata_store: &MetadataStore,
    namespace: &Namespace,
    session_key: &UploadSessionId,
    digest: &Digest,
    hashed_size: u64,
) -> Result<(), Error> {
    match blob_store.size(digest).await {
        Ok(_) => {
            // The bytes may be old, so the guarded grant catches a mid-flight
            // reclaim; only vanished bytes fall back to a fresh promotion.
            match BlobOwnership::new(metadata_store)
                .grant_existing(blob_store, namespace, digest)
                .await?
            {
                GrantOutcome::Granted => return Ok(()),
                GrantOutcome::BytesAbsent => {}
                GrantOutcome::ReclaimBlocked => {
                    return Err(Error::ReclamationInProgress(
                        "blob reclamation in progress; retry".to_string(),
                    ));
                }
            }
        }
        Err(Error::BlobUnknown | Error::NotFound) => {}
        Err(error) => return Err(error),
    }
    blob_store
        .complete_upload(namespace, session_key, digest, hashed_size)
        .await?;
    BlobOwnership::new(metadata_store)
        .grant(namespace, digest)
        .await
}

/// Outcome of a guarded grant against pre-existing bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantOutcome {
    /// The grant landed and the bytes are still present.
    Granted,
    /// The bytes are gone; the dangling grant is byteless and prune reaps it.
    BytesAbsent,
    /// An unexpired collector run still covers the digest after the backoff
    /// budget, so a reclaim may be mid-flight and the caller must fail closed.
    ReclaimBlocked,
}

pub struct BlobOwnership<'a> {
    metadata_store: &'a MetadataStore,
}

impl<'a> BlobOwnership<'a> {
    pub fn new(metadata_store: &'a MetadataStore) -> Self {
        Self { metadata_store }
    }

    /// Insert `namespace`'s blob ownership reference with one idempotent put.
    /// Correct on its own only for freshly written bytes, which the grace
    /// period covers; pre-existing bytes need [`Self::grant_existing`].
    pub async fn grant(&self, namespace: &Namespace, digest: &Digest) -> Result<(), Error> {
        self.metadata_store
            .update_blob_index(
                namespace,
                digest,
                BlobIndexOperation::Insert(LinkKind::Blob(digest.clone())),
            )
            .await
    }

    /// Grant a reference to bytes that already exist (a mount, a cache fill, a
    /// re-upload). The grant must land before the collector check and the
    /// re-probe, so any reclaim that could still take the bytes is seen here;
    /// anything but [`GrantOutcome::Granted`] must not be relied on.
    pub async fn grant_existing(
        &self,
        blob_store: &BlobStore,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<GrantOutcome, Error> {
        self.grant(namespace, digest).await?;
        if !self.metadata_store.gc_clear(&[digest]).await? {
            return Ok(GrantOutcome::ReclaimBlocked);
        }
        match blob_store.size(digest).await {
            Ok(_) => Ok(GrantOutcome::Granted),
            Err(Error::BlobUnknown | Error::NotFound) => Ok(GrantOutcome::BytesAbsent),
            Err(error) => Err(error),
        }
    }

    pub async fn can_read(&self, namespace: &Namespace, digest: &Digest) -> Result<bool, Error> {
        // The own key grants directly, so one head answers the common case
        // before the fuller reference listing.
        if self.metadata_store.has_own_grant(namespace, digest).await? {
            return Ok(true);
        }
        // Writers never remove reference entries, so a non-own entry counts
        // only while its backing link still resolves: a stale manifest
        // reference must not resurrect a blob the namespace deleted.
        let links = self.references(namespace, digest).await?;
        for link in &links {
            if matches!(link, LinkKind::Blob(link_digest) if link_digest == digest) {
                return Ok(true);
            }
            if self
                .metadata_store
                .reference_backed(namespace, link, digest)
                .await?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn references(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<HashSet<LinkKind>, Error> {
        match self
            .metadata_store
            .read_blob_index_namespace(namespace, digest)
            .await
        {
            Ok(links) => Ok(links),
            Err(Error::NotFound) => Ok(HashSet::new()),
            Err(error) => Err(error),
        }
    }

    /// Every local namespace referencing `digest`, per the blob index; empty
    /// when none do, a missing index entry included.
    pub async fn referencing_namespaces(&self, digest: &Digest) -> Result<Vec<Namespace>, Error> {
        let index = match self.metadata_store.read_blob_index(digest).await {
            Ok(index) => index,
            Err(Error::NotFound) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };

        Ok(index.namespace.into_keys().collect())
    }

    /// The lexicographically-smallest namespace referencing `digest`, excluding
    /// `exclude`; `None` when no other namespace references it.
    pub async fn smallest_referencing_namespace(
        &self,
        digest: &Digest,
        exclude: &str,
    ) -> Result<Option<Namespace>, Error> {
        let index = match self.metadata_store.read_blob_index(digest).await {
            Ok(index) => index,
            Err(Error::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };

        Ok(index
            .namespace
            .into_keys()
            .filter(|key| key != exclude)
            .filter_map(|key| Namespace::new(&key).ok())
            .min())
    }
}
