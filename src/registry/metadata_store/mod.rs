use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use angos_oci::Namespace;
use angos_tx_engine::store::Store;

use crate::{cache::Cache, registry::pagination};

mod access_time;
mod blob_index;
mod catalog;
mod gc;
mod link;

#[cfg(test)]
mod tests;

use access_time::{AccessTimeWriter, FlushHandle};
pub use blob_index::{BlobIndex, BlobIndexOperation, shard::decode_blob_index_shard_namespace};
pub use link::{LinkKind, LinkMetadata, LinkOperation, LinksCommit, LinksTx, ReferencePolicy};

// MetadataStore (concrete implementation)

#[derive(Clone)]
pub struct MetadataStore {
    /// Storage façade owning the object store and transaction executor; all
    /// reads, reads-for-update, and coordinated writes flow through it.
    store: Arc<Store>,
    cache: Option<Arc<Cache>>,
    link_cache_ttl: u64,
    /// Concurrent directory scans a catalog namespace walk keeps in flight.
    namespace_walk_concurrency: usize,
    access_time_writer: Option<AccessTimeWriter>,
    /// The reclamation grace period: how long fresh blob data and fresh
    /// reference keys are unconditionally live, and how long a collector's
    /// range marker outlives its last refresh. Writers and collectors built
    /// over the same store share the value.
    gc_grace_secs: u64,
    /// Namespaces whose catalog index key this process already ensured; being
    /// wrong only costs one redundant put.
    catalog_indexed: Arc<Mutex<HashSet<Namespace>>>,
    // Held for Drop side-effect: signals the flush task to exit when the last clone is dropped.
    _flush_handle: Option<Arc<FlushHandle>>,
}

/// Default reclamation grace period. It only has to exceed the widest
/// adjacent-request gap on a write path plus clock skew, so minutes are
/// comfortable.
pub const DEFAULT_GC_GRACE_SECS: u64 = 300;

pub struct Builder {
    store: Arc<Store>,
    cache: Option<Arc<Cache>>,
    link_cache_ttl: u64,
    access_time_debounce_secs: u64,
    namespace_walk_concurrency: usize,
    gc_grace_secs: u64,
}

impl Builder {
    fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            cache: None,
            link_cache_ttl: 30,
            access_time_debounce_secs: 0,
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

    pub fn access_time_debounce_secs(mut self, secs: u64) -> Self {
        self.access_time_debounce_secs = secs;
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
        let (access_time_writer, flush_handle) =
            access_time::build_writer(&self.store, self.access_time_debounce_secs);

        MetadataStore {
            store: self.store,
            cache: self.cache,
            link_cache_ttl: self.link_cache_ttl,
            namespace_walk_concurrency: self.namespace_walk_concurrency,
            access_time_writer,
            gc_grace_secs: self.gc_grace_secs,
            catalog_indexed: Arc::new(Mutex::new(HashSet::new())),
            _flush_handle: flush_handle,
        }
    }
}

impl MetadataStore {
    /// Return a builder over the storage façade `store` (object store for reads
    /// plus the transaction executor). `cache`, `link_cache_ttl` and
    /// `access_time_debounce_secs` are optional fluent setters.
    pub fn builder(store: Arc<Store>) -> Builder {
        Builder::new(store)
    }

    /// Returns the storage façade used for all reads and coordinated writes.
    pub fn store(&self) -> &Store {
        self.store.as_ref()
    }

    /// The reclamation grace period, shared by writers and collectors built
    /// over this store.
    pub fn gc_grace_secs(&self) -> u64 {
        self.gc_grace_secs
    }

    /// Returns an owned handle to the storage façade, for closures and helpers
    /// that need to capture it across `await` points.
    pub fn store_arc(&self) -> Arc<Store> {
        self.store.clone()
    }
}
