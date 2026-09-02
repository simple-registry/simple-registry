//! The namespace / tag / revision / referrer enumeration endpoints, served
//! from the `v2/cat` index (unscoped) or the scope's `v2/ns` listings.

use std::collections::{BTreeSet, HashMap, HashSet};

use bytes::Bytes;
use futures_util::future::ready;
use futures_util::stream::{self, Stream, StreamExt, TryStreamExt};
use tracing::{debug, instrument, warn};

use angos_oci::{Algorithm, Digest, Namespace, Tag, namespace_belongs_to};
use angos_storage::{Page, paginated};

use crate::registry::keys::NamespaceKeys;
use crate::registry::metadata_store::parse_tag_entry;
use crate::registry::{
    Error,
    metadata_store::{LinkKind, MetadataStore},
    pagination, path_builder,
};

/// Folds a sorted stream of (group, entry-file) pairs into each group's
/// winner: `Some(digest)` live, `None` tombstoned. A sorted listing delivers
/// each group's entries contiguously with the newest ordinal first, so every
/// group resolves from its complete lowest-ordinal set by the same rule as a
/// point read: highest digest wins a same-millisecond tie, and a `set` beats
/// a `del` of the same digest.
#[derive(Default)]
struct WinnerFold {
    states: HashMap<String, Option<Digest>>,
    current: Option<(String, u64, Digest, bool)>,
}

impl WinnerFold {
    fn push(&mut self, group: &str, file: &str) {
        let Some((ord, deletion, digest)) = parse_tag_entry(file) else {
            return;
        };
        self.current = Some(match self.current.take() {
            Some((cur, cur_ord, cur_digest, cur_del)) if cur == group => {
                if ord == cur_ord && (digest > cur_digest || (digest == cur_digest && cur_del)) {
                    (cur, cur_ord, digest, deletion)
                } else {
                    (cur, cur_ord, cur_digest, cur_del)
                }
            }
            previous => {
                if let Some((done, _, digest, deletion)) = previous {
                    self.states.insert(done, (!deletion).then_some(digest));
                }
                (group.to_string(), ord, digest, deletion)
            }
        });
    }

    fn finish(mut self) -> HashMap<String, Option<Digest>> {
        if let Some((done, _, digest, deletion)) = self.current {
            self.states.insert(done, (!deletion).then_some(digest));
        }
        self.states
    }
}

impl MetadataStore {
    /// Lists the namespaces holding manifest content (at least one revision
    /// or live tag); an `_uploads`-only namespace is not a catalog entry and
    /// is discovered through the blob store instead.
    #[instrument(skip(self))]
    pub async fn list_namespaces(
        &self,
        n: u16,
        last: Option<String>,
    ) -> Result<Page<Namespace>, Error> {
        debug!("Fetching {n} namespace(s) with continuation token: {last:?}");

        // The index listing is already in `Namespace` order, so no sort here.
        let namespaces = self.collect_namespaces(None).await?;

        Ok(pagination::paginate_sorted(&namespaces, n, last.as_deref()))
    }

    /// Ensure the namespace's catalog index key exists, deduped by a
    /// process-local set. A failed put is forgotten so a later write retries
    /// it.
    pub async fn ensure_catalog_index(&self, namespace: &Namespace) {
        let inserted = match self.catalog_indexed.lock() {
            Ok(mut set) => set.insert(namespace.clone()),
            Err(poisoned) => poisoned.into_inner().insert(namespace.clone()),
        };
        if !inserted {
            return;
        }
        let key = namespace.catalog_index_path();
        if let Err(e) = self.object_store().put(&key, Bytes::new()).await {
            warn!("failed to write catalog index for '{namespace}': {e}");
            match self.catalog_indexed.lock() {
                Ok(mut set) => {
                    set.remove(namespace);
                }
                Err(poisoned) => {
                    poisoned.into_inner().remove(namespace);
                }
            }
        }
    }

    /// Every indexed namespace name in `v2/cat` key order, without the content
    /// probe [`Self::collect_namespaces`] runs. `scope` reads only that
    /// repository's key range: a prefix's keys are contiguous, so the scan
    /// starts at the scope and stops at the first key past it.
    ///
    /// A key whose namespace was emptied but not yet reaped still lists, so
    /// this serves a caller that tolerates a stale name over paying one probe
    /// per namespace. Callers needing content-checked names use
    /// [`Self::collect_namespaces`].
    #[instrument(skip(self))]
    pub async fn list_indexed_namespaces(
        &self,
        scope: Option<&str>,
    ) -> Result<Vec<Namespace>, Error> {
        let mut namespaces = Vec::new();
        let mut token = None;
        // Keys carry a trailing `!`, so the bare scope sorts below every key
        // in its range and skips everything before it.
        let mut start_after = scope.map(str::to_string);
        loop {
            let page = self
                .object_store()
                .list_after(path_builder::CAT_ROOT, 1000, token, start_after.take())
                .await?;
            for key in &page.items {
                if let Some(scope) = scope
                    && !key.starts_with(scope)
                {
                    // Ordered keys: past the prefix range, nothing else matches.
                    return Ok(namespaces);
                }
                let Some(name) = key.strip_suffix('!') else {
                    continue;
                };
                if scope.is_none_or(|scope| namespace_belongs_to(name, scope))
                    && let Ok(namespace) = Namespace::new(name)
                {
                    namespaces.push(namespace);
                }
            }
            token = page.next_token;
            if token.is_none() {
                return Ok(namespaces);
            }
        }
    }

    /// Enumerates every namespace, unpaginated. `scope` reads the scope's own
    /// `v2/ns` listings, unsorted; `None` serves the `v2/cat` index alone, in
    /// its lexical key order.
    #[instrument(skip(self))]
    pub async fn collect_namespaces(&self, scope: Option<&str>) -> Result<Vec<Namespace>, Error> {
        let Some(scope) = scope else {
            return self.collect_indexed_namespaces().await;
        };

        // A revision record's existence is liveness; a tag counts only when
        // its resolved winner is live, so a namespace holding nothing but
        // tombstones does not surface.
        let listings: [(String, String); 3] = [
            (
                format!("{}/{scope}!tag", path_builder::NS_ROOT),
                format!("{scope}!tag/"),
            ),
            (
                format!("{}/{scope}!rev", path_builder::NS_ROOT),
                format!("{scope}!rev/"),
            ),
            (
                format!("{}/{scope}", path_builder::NS_ROOT),
                format!("{scope}/"),
            ),
        ];
        let mut fold = WinnerFold::default();
        let mut record_names: HashSet<String> = HashSet::new();
        for (root, key_prefix) in &listings {
            let mut token = None;
            loop {
                let page = self.object_store().list(root, 1000, token).await?;
                for item in &page.items {
                    let key = format!("{key_prefix}{item}");
                    let Some((name, marker)) = key.split_once('!') else {
                        continue;
                    };
                    if marker.starts_with("rev/") {
                        record_names.insert(name.to_string());
                    } else if marker.starts_with("tag/") {
                        let Some((group, file)) = key.rsplit_once('/') else {
                            continue;
                        };
                        fold.push(group, file);
                    }
                }
                token = page.next_token;
                if token.is_none() {
                    break;
                }
            }
        }
        let mut namespaces = Vec::new();
        let mut seen: HashSet<Namespace> = HashSet::new();
        let live_tag_names = fold.finish().into_iter().filter_map(|(group, state)| {
            state.is_some().then(|| {
                group
                    .split_once('!')
                    .map(|(name, _)| name.to_string())
                    .unwrap_or(group)
            })
        });
        for name in record_names.into_iter().chain(live_tag_names) {
            let Ok(namespace) = Namespace::new(&name) else {
                continue;
            };
            if seen.insert(namespace.clone()) {
                namespaces.push(namespace);
            }
        }
        Ok(namespaces)
    }

    /// Enumerate the `v2/cat` index in lexical key order, which is
    /// `Namespace` order because the trailing `!` sorts below every namespace
    /// character. Each name is content-checked so a stale key of an emptied
    /// namespace does not list.
    async fn collect_indexed_namespaces(&self) -> Result<Vec<Namespace>, Error> {
        let mut namespaces = Vec::new();
        let mut token = None;
        loop {
            let page = self
                .object_store()
                .list(path_builder::CAT_ROOT, 1000, token)
                .await?;
            let candidates: Vec<Namespace> = page
                .items
                .iter()
                .filter_map(|key| key.strip_suffix('!'))
                .filter_map(|name| Namespace::new(name).ok())
                .collect();
            // One content probe per name, fanned out but ordered so the
            // listing's lexical order survives.
            let probes = candidates.into_iter().map(|namespace| async move {
                match self.has_manifest_content(&namespace).await {
                    Ok(true) => Ok(Some(namespace)),
                    Ok(false) => Ok(None),
                    Err(e) => Err(e),
                }
            });
            let mut probing = stream::iter(probes).buffered(self.namespace_walk_concurrency);
            while let Some(result) = probing.next().await {
                if let Some(namespace) = result? {
                    namespaces.push(namespace);
                }
            }
            drop(probing);
            token = page.next_token;
            if token.is_none() {
                return Ok(namespaces);
            }
        }
    }

    #[instrument(skip(self))]
    pub async fn list_tags(
        &self,
        namespace: &Namespace,
        n: u16,
        last: Option<String>,
    ) -> Result<Page<Tag>, Error> {
        debug!("Listing {n} tag(s) for namespace '{namespace}' starting with last '{last:?}'");

        let mut tags: Vec<Tag> = self.stream_tags(namespace).try_collect().await?;
        tags.sort();

        Ok(pagination::paginate_sorted(&tags, n, last.as_deref()))
    }

    /// Streams every live tag in `namespace`, resolved from its tag entries:
    /// a tombstone winner drops the tag. Malformed names are dropped
    /// silently; scrub reports and removes them.
    pub fn stream_tags(
        &self,
        namespace: &Namespace,
    ) -> impl Stream<Item = Result<Tag, Error>> + Send + '_ {
        let namespace = namespace.clone();
        stream::once(async move {
            let names: BTreeSet<Tag> = self
                .collect_entry_tag_states(&namespace)
                .await?
                .into_iter()
                .filter_map(|(tag, state)| state.is_some().then_some(tag))
                .collect();
            Ok::<_, Error>(stream::iter(names.into_iter().map(Ok)))
        })
        .try_flatten()
    }

    /// Every new-shape tag with its resolved liveness: `Some(target)` live,
    /// `None` tombstoned. One flat listing; bodies are never read.
    async fn collect_entry_tag_states(
        &self,
        namespace: &Namespace,
    ) -> Result<HashMap<Tag, Option<Digest>>, Error> {
        let root = namespace.tag_entries_root();
        let mut fold = WinnerFold::default();
        let mut token = None;
        loop {
            let page = self.object_store().list(&root, 1000, token).await?;
            for key in &page.items {
                let Some((group, file)) = key.split_once('/') else {
                    continue;
                };
                fold.push(group, file);
            }
            token = page.next_token;
            if token.is_none() {
                break;
            }
        }
        Ok(fold
            .finish()
            .into_iter()
            .filter_map(|(group, state)| {
                let tag = Tag::new(group.strip_suffix('!')?).ok()?;
                Some((tag, state))
            })
            .collect())
    }

    /// The `LinkKind::Tag` entries in `namespace` currently pointing at
    /// `digest`, resolved from the tag entries in one listing. The entry
    /// listing bypasses the link cache because this set gates the
    /// digest-delete LWW guard and must not omit a tag re-pointed on another
    /// replica within the cache TTL.
    #[instrument(skip(self))]
    pub async fn find_tags_pointing_at(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<Vec<LinkKind>, Error> {
        Ok(self
            .collect_entry_tag_states(namespace)
            .await?
            .into_iter()
            .filter(|(_, state)| state.as_ref() == Some(digest))
            .map(|(tag, _)| LinkKind::Tag(tag))
            .collect())
    }

    /// Streams `digest`'s candidate referrer manifest digests, unresolved and
    /// unordered. Callers resolve each candidate to a descriptor at registry
    /// altitude, where the blob store holding manifest bodies is in reach.
    pub fn stream_referrer_digests(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> impl Stream<Item = Result<Digest, Error>> + Send + '_ {
        let record_dir = namespace.referrer_record_dir(digest);
        paginated(move |token| {
            let record_dir = record_dir.clone();
            async move {
                let page = self.object_store().list(&record_dir, 1000, token).await?;
                Ok::<_, Error>((page.items, page.next_token))
            }
        })
        .try_filter_map(|key| {
            let referrer = key.split_once('.').and_then(|(algorithm, hash)| {
                let algorithm = algorithm.parse::<Algorithm>().ok()?;
                Digest::with_algorithm(algorithm, hash).ok()
            });
            ready(Ok(referrer))
        })
    }

    /// Whether `namespace` holds any manifest content, by the rule the
    /// catalog listing names a repository with: at least one revision or tag.
    pub async fn has_manifest_content(&self, namespace: &Namespace) -> Result<bool, Error> {
        // A one-key page answers the existence probe.
        let revisions = self.stream_revisions_paged(namespace, 1);
        tokio::pin!(revisions);
        if revisions.next().await.transpose()?.is_some() {
            return Ok(true);
        }

        // Only a tag whose resolved winner is live counts, so a namespace
        // holding nothing but tombstones reads as empty.
        let states = self.collect_entry_tag_states(namespace).await?;
        Ok(states.values().any(Option::is_some))
    }

    pub async fn has_referrers(
        &self,
        namespace: &Namespace,
        subject: &Digest,
    ) -> Result<bool, Error> {
        let dir = namespace.referrer_record_dir(subject);
        let page = self.object_store().list(&dir, 1, None).await?;
        Ok(!page.items.is_empty())
    }

    /// Streams every manifest revision digest in `namespace`, from its
    /// revision records.
    pub fn stream_revisions<'a>(
        &'a self,
        namespace: &'a Namespace,
    ) -> impl Stream<Item = Result<Digest, Error>> + Send + 'a {
        self.stream_revisions_paged(namespace, 1000)
    }

    /// [`Self::stream_revisions`] with a caller-chosen page size, so an
    /// existence probe can ask for one key instead of a full page.
    pub fn stream_revisions_paged<'a>(
        &'a self,
        namespace: &'a Namespace,
        page_size: u16,
    ) -> impl Stream<Item = Result<Digest, Error>> + Send + 'a {
        paginated(move |token| async move {
            let root = namespace.revision_records_root();
            let page = self.object_store().list(&root, page_size, token).await?;
            Ok::<_, Error>((page.items, page.next_token))
        })
        .try_filter_map(|key| {
            // `<algo>/<pfx>/<hash>`
            let mut parts = key.split('/');
            let digest = match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(algorithm), Some(_), Some(hash), None) => algorithm
                    .parse::<Algorithm>()
                    .ok()
                    .and_then(|algorithm| Digest::with_algorithm(algorithm, hash).ok()),
                _ => None,
            };
            ready(Ok(digest))
        })
    }

    pub async fn count_manifests(&self, namespace: &Namespace) -> Result<usize, Error> {
        self.stream_revisions(namespace)
            .try_fold(0, |count, _| async move { Ok(count + 1) })
            .await
    }

    pub async fn count_tags(&self, namespace: &Namespace) -> Result<usize, Error> {
        self.stream_tags(namespace)
            .try_fold(0, |count, _| async move { Ok(count + 1) })
            .await
    }
}
