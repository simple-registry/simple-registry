use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use angos_oci::Namespace;
use angos_storage::ObjectStore;

use crate::{cache::Cache, registry::pagination};

mod access_time;
mod blob_index;
mod catalog;
mod gc;
pub mod link;
mod mutation;

#[cfg(test)]
mod tests;

pub use access_time::AccessEntry;
pub use blob_index::{BlobIndex, BlobIndexOperation, shard::decode_blob_index_shard_namespace};
pub use link::{LinkKind, LinkMetadata, LinkOperation, LinksCommit, LinksTx, ReferencePolicy};

// MetadataStore (concrete implementation)

#[derive(Clone)]
pub struct MetadataStore {
    /// The object store all reads and writes flow through.
    object: Arc<dyn ObjectStore>,
    cache: Option<Arc<Cache>>,
    link_cache_ttl: u64,
    /// Concurrent directory scans a catalog namespace walk keeps in flight.
    namespace_walk_concurrency: usize,
    /// The reclamation grace period: how long fresh blob data and fresh
    /// reference keys are unconditionally live, and how long a collector's
    /// range marker outlives its last refresh. Writers and collectors built
    /// over the same store share the value.
    gc_grace_secs: u64,
    /// Namespaces whose catalog index key this process already ensured; being
    /// wrong only costs one redundant put.
    catalog_indexed: Arc<Mutex<HashSet<Namespace>>>,
}

/// Default reclamation grace period. It only has to exceed the widest
/// adjacent-request gap on a write path plus clock skew, so minutes are
/// comfortable.
pub const DEFAULT_GC_GRACE_SECS: u64 = 300;

pub struct Builder {
    object: Arc<dyn ObjectStore>,
    cache: Option<Arc<Cache>>,
    link_cache_ttl: u64,
    namespace_walk_concurrency: usize,
    gc_grace_secs: u64,
}

impl Builder {
    fn new(object: Arc<dyn ObjectStore>) -> Self {
        Self {
            object,
            cache: None,
            link_cache_ttl: 30,
            namespace_walk_concurrency: pagination::NAMESPACE_WALK_CONCURRENCY,
            gc_grace_secs: DEFAULT_GC_GRACE_SECS,
        }
    }

    /// The reclamation grace period, in seconds. Production deployments run
    /// the default; tests and offline maintenance runs shrink it to exercise
    /// reclamation immediately.
    #[must_use]
    pub fn gc_grace_secs(mut self, secs: u64) -> Self {
        self.gc_grace_secs = secs;
        self
    }

    pub fn cache(mut self, cache: Arc<Cache>) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn link_cache_ttl(mut self, ttl: u64) -> Self {
        self.link_cache_ttl = ttl;
        self
    }

    /// Concurrent directory-scan fan-out for catalog namespace walks.
    #[must_use]
    pub fn namespace_walk_concurrency(mut self, concurrency: usize) -> Self {
        self.namespace_walk_concurrency = concurrency.max(1);
        self
    }

    #[must_use]
    pub fn build(self) -> MetadataStore {
        MetadataStore {
            object: self.object,
            cache: self.cache,
            link_cache_ttl: self.link_cache_ttl,
            namespace_walk_concurrency: self.namespace_walk_concurrency,
            gc_grace_secs: self.gc_grace_secs,
            catalog_indexed: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

impl MetadataStore {
    /// Return a builder over the object store all reads and writes flow
    /// through. `cache` and `link_cache_ttl` are optional fluent setters.
    pub fn builder(object: Arc<dyn ObjectStore>) -> Builder {
        Builder::new(object)
    }

    /// The object store all reads and writes flow through.
    pub fn object_store(&self) -> &Arc<dyn ObjectStore> {
        &self.object
    }

    /// The reclamation grace period, shared by writers and collectors built
    /// over this store.
    pub fn gc_grace_secs(&self) -> u64 {
        self.gc_grace_secs
    }
}
