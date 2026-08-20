//! Single-link primitives: read a link's [`LinkMetadata`], the cache-aware
//! `read_link`, and the cache helpers behind it (gated on `link_cache_ttl`).

#[cfg(test)]
use bytes::Bytes;
use tracing::{instrument, warn};

use angos_oci::Namespace;
use angos_storage::Error as StorageError;

use crate::registry::{
    Error,
    metadata_store::{LinkKind, LinkMetadata, MetadataStore},
    path_builder,
};

/// Cache TTL for revision and referrer records, which never mutate: a year
/// stands in for "no expiry" (deletes invalidate explicitly) while staying
/// safe for the memory backend's deadline arithmetic.
const IMMUTABLE_LINK_CACHE_TTL_SECS: u64 = 365 * 24 * 3600;

impl MetadataStore {
    /// Read the stored [`LinkMetadata`] for `link` within `namespace`. A tag
    /// resolves from its ordered entries and a revision or referrer from its
    /// record (each falling back to the legacy link); every other kind is one
    /// link-file read.
    pub async fn read_link_reference(
        &self,
        namespace: &Namespace,
        link: &LinkKind,
    ) -> Result<LinkMetadata, Error> {
        match link {
            LinkKind::Tag(tag) => return self.resolve_tag(namespace, tag).await,
            LinkKind::Digest(digest) => return self.resolve_revision(namespace, digest).await,
            LinkKind::Referrer { subject, referrer } => {
                return self.resolve_referrer(namespace, subject, referrer).await;
            }
            _ => {}
        }
        let link_path = path_builder::link_path(link, namespace);
        match self.object_store().get(&link_path).await {
            Ok(data) => serde_json::from_slice(&data).map_err(|e| Error::Internal(e.to_string())),
            Err(StorageError::NotFound) => Err(Error::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// Cache-aware link read with no access-time side effect: serve from the
    /// link cache, else read through and populate it.
    #[instrument(skip(self))]
    pub async fn read_link(
        &self,
        namespace: &Namespace,
        link: &LinkKind,
    ) -> Result<LinkMetadata, Error> {
        if let Some(cached) = self.cache_get(namespace, link).await {
            return Ok(cached);
        }
        let data = self.read_link_reference(namespace, link).await?;
        self.cache_put(namespace, link, &data).await;
        Ok(data)
    }

    /// Seed `link` state directly, for tests only; production writes go
    /// through `update_links`. A tag lands as an entry, the shape the write
    /// path produces.
    #[cfg(test)]
    pub async fn write_link_reference(
        &self,
        namespace: &Namespace,
        link: &LinkKind,
        metadata: &LinkMetadata,
    ) -> Result<(), Error> {
        if let LinkKind::Tag(tag) = link {
            return self.write_tag_state(namespace, tag, metadata).await;
        }
        let link_path = path_builder::link_path(link, namespace);
        let serialized = Bytes::from(serde_json::to_vec(metadata)?);
        self.object_store()
            .put(&link_path, serialized)
            .await
            .map_err(Error::from)
    }

    fn cache_key(namespace: &Namespace, link: &LinkKind) -> String {
        format!("link:{namespace}:{link}")
    }

    pub async fn cache_get(&self, namespace: &Namespace, link: &LinkKind) -> Option<LinkMetadata> {
        if self.link_cache_ttl == 0 {
            return None;
        }
        let cache = self.cache.as_ref()?;
        cache
            .retrieve::<LinkMetadata>(&Self::cache_key(namespace, link))
            .await
            .ok()
            .flatten()
    }

    pub async fn cache_put(&self, namespace: &Namespace, link: &LinkKind, metadata: &LinkMetadata) {
        if self.link_cache_ttl == 0 {
            return;
        }
        // A revision or referrer record never mutates, so only an explicit
        // delete invalidates it; a tag re-resolves after the TTL.
        let ttl = match link {
            LinkKind::Digest(_) | LinkKind::Referrer { .. } => IMMUTABLE_LINK_CACHE_TTL_SECS,
            _ => self.link_cache_ttl,
        };
        if let Some(cache) = &self.cache {
            let key = Self::cache_key(namespace, link);
            if let Err(err) = cache.store(&key, metadata, ttl).await {
                warn!("Failed to store link metadata in cache for {namespace}/{link}: {err}");
            }
        }
    }

    pub async fn cache_invalidate(&self, namespace: &Namespace, link: &LinkKind) {
        if let Some(cache) = &self.cache {
            let _ = cache.delete_value(&Self::cache_key(namespace, link)).await;
        }
    }
}
