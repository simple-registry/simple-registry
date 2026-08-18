//! The namespace / tag / revision / referrer catalog: the content-derived
//! enumeration endpoints and the namespace tree-walk they build on.

use std::collections::{BTreeSet, HashMap, HashSet};

use bytes::Bytes;
use futures_util::future::ready;
use futures_util::stream::{self, Stream, StreamExt, TryStreamExt};
use tracing::{debug, instrument, warn};

use angos_oci::{Algorithm, Digest, Namespace, Tag};
use angos_storage::{Page, paginated};

use crate::registry::{
    Error,
    metadata_store::{LinkKind, MetadataStore},
    pagination, path_builder,
};

/// Fan-out for the tag link reads behind [`MetadataStore::find_tags_pointing_at`].
const TAG_LINK_READ_CONCURRENCY: usize = 20;

/// Folds a sorted stream of (group, entry-file) pairs into each group's
/// winner: `Some(digest)` live, `None` tombstoned. A sorted listing delivers
/// each group's entries contiguously with the newest ordinal first, so every
/// group resolves from its complete lowest-ordinal set by the same rule as a
/// point read: highest digest wins the same-millisecond tie, and a `set`
/// beats a `del` of the same digest.
#[derive(Default)]
struct WinnerFold {
    states: HashMap<String, Option<Digest>>,
    current: Option<(String, u64, Digest, bool)>,
}

impl WinnerFold {
    fn push(&mut self, group: &str, file: &str) {
        let Some((ord, deletion, digest)) = path_builder::parse_tag_entry(file) else {
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
    /// Lists the namespaces holding manifest content (a `_manifests` child);
    /// an `_uploads`-only namespace is not a catalog entry and is discovered
    /// through the blob store instead, where upload sessions live.
    #[instrument(skip(self))]
    pub async fn list_namespaces(
        &self,
        n: u16,
        last: Option<String>,
    ) -> Result<Page<Namespace>, Error> {
        debug!("Fetching {n} namespace(s) with continuation token: {last:?}");

        let mut namespaces = self.collect_namespaces(None).await?;
        namespaces.sort();

        Ok(pagination::paginate_sorted(&namespaces, n, last.as_deref()))
    }

    /// Ensure the namespace's catalog index key exists: an empty write-once
    /// put, deduped by a process-local set, so it costs one put per namespace
    /// per process. A failed put is forgotten so a later write retries it.
    pub async fn ensure_catalog_index(&self, namespace: &Namespace) {
        let inserted = match self.catalog_indexed.lock() {
            Ok(mut set) => set.insert(namespace.clone()),
            Err(poisoned) => poisoned.into_inner().insert(namespace.clone()),
        };
        if !inserted {
            return;
        }
        let key = path_builder::catalog_index_path(namespace);
        if let Err(e) = self.store().object_store().put(&key, Bytes::new()).await {
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

    /// Enumerates every namespace, unpaginated and unsorted. `scope` walks one
    /// repository's legacy subtree merged with its scoped `v2/ns` listings;
    /// `None` merges the whole-store legacy walk with the `v2/cat` index.
    #[instrument(skip(self))]
    pub async fn collect_namespaces(&self, scope: Option<&str>) -> Result<Vec<Namespace>, Error> {
        let (root, prefix) = path_builder::namespace_walk_root(scope);

        let mut namespaces = pagination::collect_namespaces_with_marker(
            &root,
            &prefix,
            "_manifests",
            self.namespace_walk_concurrency,
            |path| async move {
                let sub_prefixes = self
                    .store()
                    .object_store()
                    .list_all_children(&path)
                    .await?
                    .sub_prefixes;
                Ok::<_, Error>(sub_prefixes)
            },
        )
        .await?;

        let Some(scope) = scope else {
            self.merge_indexed_namespaces(&mut namespaces).await?;
            return Ok(namespaces);
        };

        // A scoped namespace whose tags or revisions live under `v2/ns/` may
        // hold no `_manifests` marker of its own; merge those in from the
        // scope's own tag and rev roots plus its `/` subtree, so the
        // whole-segment rule is the listed prefix rather than a client-side
        // filter over the full root. A revision record's existence is
        // liveness; a tag counts only when its resolved winner is live, so a
        // namespace holding only tombstones does not resurface.
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
                let page = self.store().object_store().list(root, 1000, token).await?;
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
        let mut seen: HashSet<Namespace> = namespaces.iter().cloned().collect();
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

    /// Merge the `v2/cat` index into `namespaces`: every write lands one key
    /// per namespace (`ensure_catalog_index`), and content predating the
    /// index is covered by the legacy walk or gains its key from the scrub
    /// backfill. A name the walk already found needs no probe; an index-only
    /// name is content-checked so a stale key of an emptied namespace does
    /// not list.
    async fn merge_indexed_namespaces(&self, namespaces: &mut Vec<Namespace>) -> Result<(), Error> {
        let seen: HashSet<Namespace> = namespaces.iter().cloned().collect();
        let mut token = None;
        loop {
            let page = self
                .store()
                .object_store()
                .list(path_builder::CAT_ROOT, 1000, token)
                .await?;
            let candidates: Vec<Namespace> = page
                .items
                .iter()
                .filter_map(|key| key.strip_suffix('!'))
                .filter_map(|name| Namespace::new(name).ok())
                .filter(|namespace| !seen.contains(namespace))
                .collect();
            // One content probe per index-only name; fanned out so a page of
            // namespaces costs one round-trip group, not one per name.
            let probes = candidates.into_iter().map(|namespace| async move {
                match self.has_manifest_content(&namespace).await {
                    Ok(true) => Ok(Some(namespace)),
                    Ok(false) => Ok(None),
                    Err(e) => Err(e),
                }
            });
            let mut probing =
                stream::iter(probes).buffer_unordered(self.namespace_walk_concurrency);
            while let Some(result) = probing.next().await {
                if let Some(namespace) = result? {
                    namespaces.push(namespace);
                }
            }
            drop(probing);
            token = page.next_token;
            if token.is_none() {
                return Ok(());
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

    /// Streams every live tag in `namespace`: the tag-entry states merged
    /// with the legacy tag directories, entries shadowing legacy per name (a
    /// tombstone winner drops the tag even when its legacy link remains).
    /// Malformed names are dropped rather than surfaced as tags (scrub
    /// reports and removes them, so the drop is silent).
    pub fn stream_tags(
        &self,
        namespace: &Namespace,
    ) -> impl Stream<Item = Result<Tag, Error>> + Send + '_ {
        let tags_dir = path_builder::manifest_tags_dir(namespace);
        let namespace = namespace.clone();
        stream::once(async move {
            let tag_dirs = self
                .store()
                .object_store()
                .list_all_children(&tags_dir)
                .await?
                .sub_prefixes;
            let mut names: BTreeSet<Tag> = tag_dirs
                .into_iter()
                .filter_map(|name| Tag::try_from(name).ok())
                .collect();
            for (tag, state) in self.collect_entry_tag_states(&namespace).await? {
                match state {
                    Some(_) => {
                        names.insert(tag);
                    }
                    None => {
                        names.remove(&tag);
                    }
                }
            }
            Ok::<_, Error>(stream::iter(names.into_iter().map(Ok)))
        })
        .try_flatten()
    }

    /// Every new-shape tag with its resolved liveness: `Some(target)` for a
    /// live tag, `None` for a tombstoned one. One flat listing over the
    /// namespace's tag entries; bodies are never read.
    async fn collect_entry_tag_states(
        &self,
        namespace: &Namespace,
    ) -> Result<HashMap<Tag, Option<Digest>>, Error> {
        let root = path_builder::tag_entries_root(namespace);
        let mut fold = WinnerFold::default();
        let mut token = None;
        loop {
            let page = self.store().object_store().list(&root, 1000, token).await?;
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

    /// Lists the RAW tag directory names in `namespace` with NO `Tag`
    /// validation, so tests can observe directories whose names do not
    /// satisfy the `oci::Tag` grammar, which [`Self::list_tags`] silently
    /// drops (production code walks raw keys through scrub's categorizer).
    #[cfg(test)]
    pub async fn list_tag_names(
        &self,
        namespace: &Namespace,
        n: u16,
        last: Option<String>,
    ) -> Result<Page<String>, Error> {
        debug!("Listing {n} tag name(s) for namespace '{namespace}' starting with last '{last:?}'");

        let mut names = self.collect_tag_dir_names(namespace).await?;
        names.sort();

        Ok(pagination::paginate_sorted(&names, n, last.as_deref()))
    }

    /// Enumerates every raw tag directory name under `namespace`'s tags dir,
    /// for [`Self::list_tag_names`]'s no-validation contract.
    #[cfg(test)]
    async fn collect_tag_dir_names(&self, namespace: &Namespace) -> Result<Vec<String>, Error> {
        let tags_dir = path_builder::manifest_tags_dir(namespace);
        let children = self
            .store()
            .object_store()
            .list_all_children(&tags_dir)
            .await?;
        Ok(children.sub_prefixes)
    }

    /// Returns the `LinkKind::Tag` entries in `namespace` that currently point at
    /// `digest`. Reads bypass the link cache, since this set gates the
    /// digest-delete LWW guard and must not omit a tag re-pointed on another
    /// replica within the cache TTL.
    #[instrument(skip(self))]
    pub async fn find_tags_pointing_at(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> Result<Vec<LinkKind>, Error> {
        // New-shape tags answer from one flat listing; only tags that exist
        // solely as unconverted legacy links still need a link read each. A
        // legacy tag whose read fails is skipped rather than matched.
        let states = self.collect_entry_tag_states(namespace).await?;
        let mut tags: Vec<LinkKind> = states
            .iter()
            .filter(|(_, state)| state.as_ref() == Some(digest))
            .map(|(tag, _)| LinkKind::Tag(tag.clone()))
            .collect();

        let tags_dir = path_builder::manifest_tags_dir(namespace);
        let legacy_only: Vec<Tag> = self
            .store()
            .object_store()
            .list_all_children(&tags_dir)
            .await?
            .sub_prefixes
            .into_iter()
            .filter_map(|name| Tag::try_from(name).ok())
            .filter(|tag| !states.contains_key(tag))
            .collect();
        let legacy_matches: Vec<LinkKind> = stream::iter(legacy_only.into_iter().map(Ok))
            .map_ok(|tag: Tag| async move {
                let result = self
                    .read_link_reference(namespace, &LinkKind::Tag(tag.clone()))
                    .await;
                Ok::<_, Error>((tag, result))
            })
            .try_buffer_unordered(TAG_LINK_READ_CONCURRENCY)
            .try_filter_map(|(tag, result)| async move {
                Ok(match result {
                    Ok(metadata) if &metadata.target == digest => Some(LinkKind::Tag(tag)),
                    _ => None,
                })
            })
            .try_collect()
            .await?;
        tags.extend(legacy_matches);
        Ok(tags)
    }

    /// Streams the candidate referrer manifest digests recorded under
    /// `digest`'s referrer records, merged with its legacy referrers
    /// directory, unresolved and unordered. Record pages stream lazily; only
    /// the legacy directory is buffered, and it is not read until the records
    /// are exhausted. Callers resolve each candidate to a descriptor at
    /// registry altitude, where the blob store holding manifest bodies is in
    /// reach.
    pub fn stream_referrer_digests(
        &self,
        namespace: &Namespace,
        digest: &Digest,
    ) -> impl Stream<Item = Result<Digest, Error>> + Send + '_ {
        let record_dir = path_builder::referrer_record_dir(namespace, digest);
        let legacy_dir = path_builder::manifest_referrers_dir(namespace, digest);
        let records = paginated(move |token| {
            let record_dir = record_dir.clone();
            async move {
                let page = self
                    .store()
                    .object_store()
                    .list(&record_dir, 1000, token)
                    .await?;
                Ok::<_, Error>((page.items, page.next_token))
            }
        })
        .try_filter_map(|key| {
            let referrer = key.split_once('.').and_then(|(algorithm, hash)| {
                let algorithm = algorithm.parse::<Algorithm>().ok()?;
                Digest::with_algorithm(algorithm, hash).ok()
            });
            ready(Ok(referrer))
        });
        let legacy = stream::once(async move {
            let mut referrers = Vec::new();
            let mut token = None;
            loop {
                let page = self
                    .store()
                    .object_store()
                    .list(&legacy_dir, 1000, token)
                    .await?;
                for key in &page.items {
                    let mut parts = key.split('/');
                    let (Some(algorithm), Some(hash)) = (parts.next(), parts.next()) else {
                        continue;
                    };
                    let Ok(algorithm) = algorithm.parse::<Algorithm>() else {
                        continue;
                    };
                    let Ok(referrer) = Digest::with_algorithm(algorithm, hash) else {
                        continue;
                    };
                    referrers.push(referrer);
                }
                token = page.next_token;
                if token.is_none() {
                    break;
                }
            }
            Ok::<_, Error>(stream::iter(referrers.into_iter().map(Ok)))
        })
        .try_flatten();
        // Record keys are unique per referrer, so the seen-set only grows
        // with emitted items and dedupes the legacy side against them.
        let mut seen = HashSet::new();
        records.chain(legacy).try_filter_map(move |referrer| {
            ready(Ok(seen.insert(referrer.clone()).then_some(referrer)))
        })
    }

    /// Whether `namespace` holds any manifest content, by the rule the catalog
    /// listing names a repository with: at least one revision or tag. Probes one
    /// entry of each, so a namespace that was never written costs the listings
    /// that find nothing.
    pub async fn has_manifest_content(&self, namespace: &Namespace) -> Result<bool, Error> {
        // A one-key page answers the existence probe; the full page size is
        // for enumeration callers.
        let revisions = self.stream_revisions_paged(namespace, 1);
        tokio::pin!(revisions);
        if revisions.next().await.transpose()?.is_some() {
            return Ok(true);
        }

        let tags_dir = path_builder::manifest_tags_dir(namespace);
        let page = self
            .store()
            .object_store()
            .list_children(&tags_dir, 1, None, None)
            .await?;
        if !page.sub_prefixes.is_empty() {
            return Ok(true);
        }

        // New-shape tags: only a tag whose resolved winner is live counts, so
        // a namespace holding nothing but tombstones reads as empty.
        let states = self.collect_entry_tag_states(namespace).await?;
        Ok(states.values().any(Option::is_some))
    }

    pub async fn has_referrers(
        &self,
        namespace: &Namespace,
        subject: &Digest,
    ) -> Result<bool, Error> {
        for dir in [
            path_builder::referrer_record_dir(namespace, subject),
            path_builder::manifest_referrers_dir(namespace, subject),
        ] {
            let page = self.store().object_store().list(&dir, 1, None).await?;
            if !page.items.is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Streams every manifest revision digest in `namespace`: the new-shape
    /// records merged with the legacy per-algorithm link directories, deduped
    /// (a digest appears in both mid-conversion). Record pages stream lazily;
    /// only the legacy directories are buffered, and they are not listed
    /// until the records are exhausted.
    pub fn stream_revisions<'a>(
        &'a self,
        namespace: &'a Namespace,
    ) -> impl Stream<Item = Result<Digest, Error>> + Send + 'a {
        self.stream_revisions_paged(namespace, 1000)
    }

    /// [`Self::stream_revisions`] with a caller-chosen record page size, so an
    /// existence probe can ask for one key instead of a full page.
    pub fn stream_revisions_paged<'a>(
        &'a self,
        namespace: &'a Namespace,
        page_size: u16,
    ) -> impl Stream<Item = Result<Digest, Error>> + Send + 'a {
        let records = paginated(move |token| async move {
            let root = path_builder::revision_records_root(namespace);
            let page = self
                .store()
                .object_store()
                .list(&root, page_size, token)
                .await?;
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
        });
        let legacy = stream::once(async move {
            let mut digests = Vec::new();
            for algorithm in Algorithm::supported_algorithms() {
                let revisions_dir =
                    path_builder::manifest_revisions_link_root_dir(namespace, algorithm.as_str());
                let mut token = None;
                loop {
                    let page = self
                        .store()
                        .object_store()
                        .list_children(&revisions_dir, 1000, token, None)
                        .await?;
                    for key in page.sub_prefixes {
                        let Ok(digest) = Digest::with_algorithm(*algorithm, key.as_str()) else {
                            continue;
                        };
                        digests.push(digest);
                    }
                    token = page.next_token;
                    if token.is_none() {
                        break;
                    }
                }
            }
            Ok::<_, Error>(stream::iter(digests.into_iter().map(Ok)))
        })
        .try_flatten();
        // Record keys are unique per digest, so the seen-set only grows with
        // emitted items and dedupes the legacy side against them.
        let mut seen = HashSet::new();
        records
            .chain(legacy)
            .try_filter_map(move |digest| ready(Ok(seen.insert(digest.clone()).then_some(digest))))
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

    /// Delete an entire tag directory by prefix. Used by scrub for an invalid
    /// tag name, which cannot form a typed `LinkKind::Tag` for a link delete.
    ///
    /// `tag_name` must be a single path segment: a name containing `/`, `..`, or
    /// `.` could escape the tags directory and delete an unrelated prefix, so it
    /// is rejected rather than deleted.
    pub async fn delete_tag_directory(
        &self,
        namespace: &Namespace,
        tag_name: &str,
    ) -> Result<(), Error> {
        if tag_name.is_empty() || tag_name.contains('/') || tag_name == "." || tag_name == ".." {
            return Err(Error::Internal(format!(
                "unsafe tag directory name: '{tag_name}'"
            )));
        }
        self.store()
            .object_store()
            .delete_prefix(&path_builder::manifest_tag_dir(namespace, tag_name))
            .await
            .map_err(Error::from)
    }

    /// Delete a namespace's entire repository subtree by raw on-disk name,
    /// along with its tag entries, demoted tag history, and atime keys under
    /// `v2/ns/`. Used by
    /// scrub to reclaim a directory whose name fails `Namespace` validation
    /// and so cannot form typed links for a per-link delete.
    pub async fn delete_namespace_directory(&self, name: &str) -> Result<(), Error> {
        let prefix = path_builder::namespace_dir(name)
            .ok_or_else(|| Error::Internal(format!("unsafe namespace directory name: '{name}'")))?;
        self.store().object_store().delete_prefix(&prefix).await?;
        for prefix in [
            format!("{}/{name}!tag", path_builder::NS_ROOT),
            format!("{}/{name}!hist", path_builder::NS_ROOT),
            format!("{}/{name}!rev", path_builder::NS_ROOT),
            format!("{}/{name}!sub", path_builder::NS_ROOT),
            format!("{}/{name}!atime", path_builder::NS_ROOT),
        ] {
            self.store().object_store().delete_prefix(&prefix).await?;
        }
        self.store()
            .object_store()
            .delete(&format!("{}/{name}!", path_builder::CAT_ROOT))
            .await?;
        Ok(())
    }
}
