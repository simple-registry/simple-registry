use std::collections::HashSet;

use angos_oci::{Digest, Namespace, UploadSessionId};

use crate::registry::{
    Error,
    blob_store::BlobStore,
    metadata_store::{BlobIndexOperation, LinkKind, MetadataStore},
};

/// Promote the upload session's staged bytes to the canonical blob path and
/// grant `namespace` its reference. No lock: freshly landed bytes and a fresh
/// `_own` key both sit inside the collector's grace period, so a sweep cannot
/// reclaim them. Promotion is skipped when the bytes already landed (a racer
/// won), per [`BlobStore::complete_upload`]'s contract; the grant is
/// idempotent. Bytes that pre-existed (and may be old) get the guarded grant.
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
            // Old bytes: run the full guarded grant so a mid-flight reclaim
            // is caught; a vanished blob falls back to a fresh promotion.
            if BlobOwnership::new(metadata_store)
                .grant_existing(blob_store, namespace, digest)
                .await?
            {
                return Ok(());
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

pub struct BlobOwnership<'a> {
    metadata_store: &'a MetadataStore,
}

impl<'a> BlobOwnership<'a> {
    pub fn new(metadata_store: &'a MetadataStore) -> Self {
        Self { metadata_store }
    }

    /// Insert `namespace`'s blob ownership reference into the blob index:
    /// one idempotent put, so a retry re-grants harmlessly. Correct on its
    /// own only for freshly written bytes (the collector's grace period
    /// covers them); a grant against pre-existing bytes goes through
    /// [`Self::grant_existing`].
    pub async fn grant(&self, namespace: &Namespace, digest: &Digest) -> Result<(), Error> {
        self.metadata_store
            .update_blob_index(
                namespace,
                digest,
                BlobIndexOperation::Insert(LinkKind::Blob(digest.clone())),
            )
            .await
    }

    /// Grant a reference to bytes that already exist (a mount, a cache fill,
    /// a re-upload of a present blob): the grant lands first, then the
    /// collector check, then a re-probe of the bytes. `false` means the blob
    /// was, or is being, reclaimed; the dangling grant is byteless and
    /// prune's sweep reaps it.
    pub async fn grant_existing(
        &self,
        blob_store: &BlobStore,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<bool, Error> {
        self.grant(namespace, digest).await?;
        if !self.metadata_store.gc_clear(&[digest]).await? {
            return Ok(false);
        }
        match blob_store.size(digest).await {
            Ok(_) => Ok(true),
            Err(Error::BlobUnknown | Error::NotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub async fn can_read(&self, namespace: &Namespace, digest: &Digest) -> Result<bool, Error> {
        // Writers never remove reference entries, so a raw entry is not
        // access: the `_own` key grants directly, anything else only while
        // its backing link still resolves. A stale manifest reference must
        // not resurrect a blob the namespace deleted.
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
    /// when none do (a missing index entry is not an error). Malformed index
    /// keys are skipped rather than failing the enumeration.
    pub async fn referencing_namespaces(&self, digest: &Digest) -> Result<Vec<Namespace>, Error> {
        let index = match self.metadata_store.read_blob_index(digest).await {
            Ok(index) => index,
            Err(Error::NotFound) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };

        Ok(index.namespace.into_keys().collect())
    }

    /// The lexicographically-smallest namespace referencing `digest`, excluding
    /// `exclude`; `None` when no other namespace references it. Takes the
    /// minimum without materialising the full referencing-namespace set.
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
