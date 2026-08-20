//! Link-key validation: one visit per link file replaces the old per-concern
//! walks (manifest link repair, `referenced_by` back-links, blob-index grant
//! reconcile, tag digest links, referrer liveness, the invalid-tag gate, and
//! the orphan-namespace clearing).

use chrono::{DateTime, Utc};
use tracing::{debug, warn};

use angos_oci::{Digest, Manifest, Namespace, Tag};
use angos_storage::Error as StorageError;

use crate::{
    command::{
        maintenance::{
            Error,
            action::{Action, WalkedStore},
            categorize::ParsedLink,
        },
        scrub::validate::Validator,
    },
    registry::{
        Error as RegistryError,
        manifest::link_plan,
        metadata_store::{AccessEntry, LinkKind, LinkMetadata},
        path_builder,
    },
};

/// How long superseded access entries are retained as a rolling audit log.
/// A config knob later.
const ATIME_AUDIT_WINDOW_SECS: u64 = 3600;

impl Validator {
    /// Validate one link file in `namespace_raw`.
    pub async fn validate_link(
        &self,
        key: &str,
        namespace_raw: &str,
        link: ParsedLink,
    ) -> Result<(), Error> {
        let Ok(namespace) = Namespace::new(namespace_raw) else {
            return self.handle_invalid_namespace(namespace_raw).await;
        };

        match link {
            ParsedLink::Tag { name } => self.validate_tag_link(key, &namespace, &name).await,
            ParsedLink::Revision(digest) => {
                self.validate_revision_link(key, &namespace, &digest).await
            }
            ParsedLink::Referrer { subject, referrer } => {
                self.validate_referrer_link(key, &namespace, &subject, &referrer)
                    .await
            }
            ParsedLink::Blob(digest) => {
                self.validate_tracked_link(key, &namespace, LinkKind::Blob(digest))
                    .await
            }
            ParsedLink::Layer(digest) => {
                self.validate_tracked_link(key, &namespace, LinkKind::Layer(digest))
                    .await
            }
            ParsedLink::Config(digest) => {
                self.validate_tracked_link(key, &namespace, LinkKind::Config(digest))
                    .await
            }
            ParsedLink::ManifestIndex { index, child } => {
                self.validate_tracked_link(key, &namespace, LinkKind::Manifest { index, child })
                    .await
            }
        }
    }

    /// A raw namespace directory whose name fails validation can never be
    /// addressed by any angos API; reclaim it by prefix (deduped per name).
    async fn handle_invalid_namespace(&self, namespace_raw: &str) -> Result<(), Error> {
        if !self.claim(format!("invalid-ns:{namespace_raw}")) {
            return Ok(());
        }
        warn!("scrub: reclaiming invalid namespace directory '{namespace_raw}'");
        self.emit(Action::DeleteInvalidNamespace {
            name: namespace_raw.to_string(),
        })
        .await
    }

    /// A tag link: an invalid directory name is deleted; a valid one must
    /// parse, target existing blob bytes, and have its digest revision link.
    /// A healthy link is converted into a tag entry and reclaimed.
    async fn validate_tag_link(
        &self,
        key: &str,
        namespace: &Namespace,
        name: &str,
    ) -> Result<(), Error> {
        let Ok(tag) = Tag::new(name) else {
            return self
                .emit(Action::DeleteInvalidTag {
                    namespace: namespace.clone(),
                    tag: name.to_string(),
                })
                .await;
        };
        let Some(metadata) = self.read_link_body(key).await? else {
            return Ok(());
        };
        self.validate_tag_target(namespace, &tag, metadata.target, metadata.created_at)
            .await?;
        // Convert whether or not the target was healthy: the entry is tag
        // history either way, an unhealthy target's orphan repair tombstones
        // the tag, and a surviving legacy link would re-propose that repair
        // on every walk. A concurrent new-shape write appends a fresher
        // entry that wins resolution regardless, and the conversion's
        // legacy-link delete is grace-gated so an old-shape writer
        // rewriting the link in place is never raced.
        self.emit(Action::ConvertTagLink {
            namespace: namespace.clone(),
            tag,
        })
        .await?;
        Ok(())
    }

    /// One tag's entry directory, validated once per (namespace, tag): the
    /// resolved winner must satisfy the same checks as a legacy tag link.
    /// Both names already passed their grammars at categorization.
    pub async fn validate_tag_entries(
        &self,
        namespace_raw: &str,
        tag_raw: &str,
    ) -> Result<(), Error> {
        if !self.claim(format!("tag-entries:{namespace_raw}:{tag_raw}")) {
            return Ok(());
        }
        let (Ok(namespace), Ok(tag)) = (Namespace::new(namespace_raw), Tag::new(tag_raw)) else {
            return Ok(());
        };
        self.demote_superseded_entries(&namespace, &tag).await?;
        let metadata = match self
            .metadata_store
            .read_link_reference(&namespace, &LinkKind::Tag(tag.clone()))
            .await
        {
            Ok(metadata) => metadata,
            // Tombstoned: entries are history, nothing to check.
            Err(RegistryError::NotFound) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        self.validate_tag_target(&namespace, &tag, metadata.target, metadata.created_at)
            .await
    }

    /// Demote entries superseded by the tag's winner group to the `!hist/`
    /// prefix. The complete lowest-ordinal group is the winner and always
    /// stays, so a same-millisecond tie is never split; only strictly older
    /// entries are candidates, each age-gated so a racing push's fresh entry
    /// is never in scope.
    async fn demote_superseded_entries(
        &self,
        namespace: &Namespace,
        tag: &Tag,
    ) -> Result<(), Error> {
        let dir = path_builder::tag_entry_dir(namespace, tag);
        let mut winner_ord = None;
        let mut token = None;
        loop {
            let page = self
                .metadata_store
                .object_store()
                .list(&dir, 1000, token)
                .await
                .map_err(RegistryError::from)?;
            for name in &page.items {
                let Some((ord, _, _)) = path_builder::parse_tag_entry(name) else {
                    continue;
                };
                // The listing sorts newest first, so the first parseable
                // ordinal is the winner group's.
                let winner = *winner_ord.get_or_insert(ord);
                if ord <= winner {
                    continue;
                }
                if self.younger_than_grace(&format!("{dir}/{name}")).await? {
                    continue;
                }
                self.emit(Action::DemoteTagEntry {
                    namespace: namespace.clone(),
                    tag: tag.clone(),
                    entry_name: name.clone(),
                })
                .await?;
            }
            token = page.next_token;
            if token.is_none() {
                return Ok(());
            }
        }
    }

    /// One tag's access-entry directory, collected once per (namespace, tag).
    pub async fn collect_tag_atime_entries(
        &self,
        namespace_raw: &str,
        tag_raw: &str,
    ) -> Result<(), Error> {
        let (Ok(namespace), Ok(tag)) = (Namespace::new(namespace_raw), Tag::new(tag_raw)) else {
            return Ok(());
        };
        self.collect_atime_entries(
            &path_builder::tag_atime_entry_dir(&namespace, &tag),
            &path_builder::tag_atime_path(&namespace, &tag),
        )
        .await
    }

    /// One revision's access-entry directory, collected once per (namespace,
    /// digest).
    pub async fn collect_revision_atime_entries(
        &self,
        namespace_raw: &str,
        digest: &Digest,
    ) -> Result<(), Error> {
        let Ok(namespace) = Namespace::new(namespace_raw) else {
            return Ok(());
        };
        self.collect_atime_entries(
            &path_builder::revision_atime_entry_dir(&namespace, digest),
            &path_builder::revision_atime_path(&namespace, digest),
        )
        .await
    }

    /// Collect one atime entry directory: the newest decodable entry always
    /// stays (retention needs the last access durably), an undecodable body
    /// is deleted, a superseded entry is deleted once its own ordinal
    /// timestamp is past the audit window, and the legacy single key is
    /// retired (grace-gated) once an entry exists.
    async fn collect_atime_entries(&self, dir: &str, legacy_key: &str) -> Result<(), Error> {
        if !self.claim(format!("atime-entries:{dir}")) {
            return Ok(());
        }
        let window = i64::try_from(ATIME_AUDIT_WINDOW_SECS).unwrap_or(i64::MAX);
        let mut kept_newest = false;
        let mut token = None;
        loop {
            let page = self
                .metadata_store
                .object_store()
                .list(dir, 1000, token)
                .await
                .map_err(RegistryError::from)?;
            for name in &page.items {
                let Some(ord) = path_builder::parse_atime_entry(name) else {
                    continue;
                };
                let key = format!("{dir}/{name}");
                match self.metadata_store.object_store().get(&key).await {
                    Ok(raw) => {
                        if serde_json::from_slice::<AccessEntry>(&raw).is_err() {
                            warn!("scrub: access entry '{key}' does not parse; deleting");
                            self.delete_corrupt(WalkedStore::Metadata, &key).await?;
                            continue;
                        }
                    }
                    Err(StorageError::NotFound) => continue,
                    Err(e) => return Err(RegistryError::from(e).into()),
                }
                if !kept_newest {
                    // The listing sorts newest first: the first decodable
                    // entry is the last access and always stays.
                    kept_newest = true;
                    continue;
                }
                let old = path_builder::tag_ord_ts(ord)
                    .is_some_and(|at| Utc::now().signed_duration_since(at).num_seconds() >= window);
                if old {
                    self.emit(Action::RetireAtimeKey { key }).await?;
                }
            }
            token = page.next_token;
            if token.is_none() {
                break;
            }
        }
        if !kept_newest {
            return Ok(());
        }
        match self.metadata_store.object_store().head(legacy_key).await {
            Ok(_) => {}
            Err(StorageError::NotFound) => return Ok(()),
            Err(e) => return Err(RegistryError::from(e).into()),
        }
        if self.younger_than_grace(legacy_key).await? {
            return Ok(());
        }
        self.emit(Action::RetireAtimeKey {
            key: legacy_key.to_string(),
        })
        .await
    }

    /// The shared tail of both tag shapes: the current target must have blob
    /// bytes (else the orphan manifest is removed) and its digest revision
    /// link (re-issued when missing).
    /// A tag whose winning entry is younger than the grace period is left
    /// alone: the walk can resolve it before a concurrent delete's tombstone
    /// lands and then read the revision after that delete removed it, and
    /// repairing on that interleaving would resurrect a deleted manifest.
    async fn validate_tag_target(
        &self,
        namespace: &Namespace,
        tag: &Tag,
        target: Digest,
        entry_created_at: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        self.ensure_catalog(namespace).await?;
        if let Some(created_at) = entry_created_at {
            let grace = i64::try_from(self.metadata_store.gc_grace_secs()).unwrap_or(i64::MAX);
            if Utc::now().signed_duration_since(created_at).num_seconds() < grace {
                return Ok(());
            }
        }
        match self.blob_store.size(&target).await {
            Ok(_) => {
                self.ensure_link(namespace, &LinkKind::Digest(target.clone()), &target)
                    .await
            }
            Err(RegistryError::BlobUnknown | RegistryError::NotFound) => {
                warn!("scrub: tag '{namespace}:{tag}' targets missing blob '{target}'; removing");
                self.emit(Action::DeleteOrphanManifest {
                    namespace: namespace.clone(),
                    digest: target,
                })
                .await
            }
            Err(e) => Err(e.into()),
        }
    }

    /// A manifest revision link: validated through the shared anchor routine,
    /// then converted into a revision record and reclaimed when healthy.
    async fn validate_revision_link(
        &self,
        key: &str,
        namespace: &Namespace,
        revision: &Digest,
    ) -> Result<(), Error> {
        let Some(metadata) = self.read_link_body(key).await? else {
            return Ok(());
        };
        if metadata.target != *revision {
            // The body targets a different digest than the path addresses;
            // rewrite it to the canonical self-target.
            self.emit(Action::RecreateLink {
                namespace: namespace.clone(),
                link: LinkKind::Digest(revision.clone()),
                target: revision.clone(),
            })
            .await?;
        }
        if self.validate_revision_content(namespace, revision).await? {
            self.emit(Action::ConvertRevisionLink {
                namespace: namespace.clone(),
                digest: revision.clone(),
            })
            .await?;
        }
        Ok(())
    }

    /// A revision record: the same anchor routine as a legacy link, deduped
    /// against it per (namespace, digest). Grammars were checked at
    /// categorization.
    pub async fn validate_revision_record(
        &self,
        namespace_raw: &str,
        revision: &Digest,
    ) -> Result<(), Error> {
        let Ok(namespace) = Namespace::new(namespace_raw) else {
            return self.handle_invalid_namespace(namespace_raw).await;
        };
        self.validate_revision_content(&namespace, revision)
            .await
            .map(|_| ())
    }

    /// The anchor of the derivable state, shared by both revision shapes: one
    /// manifest read drives child-link repair, `referenced_by` back-links,
    /// and blob-index grant reconciliation. Returns whether the revision was
    /// healthy (its manifest blob present). Runs once per (namespace,
    /// revision) per scrub; a repeat visit only re-answers the health probe.
    async fn validate_revision_content(
        &self,
        namespace: &Namespace,
        revision: &Digest,
    ) -> Result<bool, Error> {
        self.ensure_catalog(namespace).await?;
        if !self.claim(format!("revision:{namespace}:{revision}")) {
            return Ok(self.blob_store.size(revision).await.is_ok());
        }

        // A revision younger than the grace period may belong to a push
        // whose later waves are still in flight; deriving repairs from it
        // would race them, so it waits for the next run.
        if self
            .younger_than_grace(&path_builder::revision_record_path(namespace, revision))
            .await?
            || self
                .younger_than_grace(&path_builder::link_path(
                    &LinkKind::Digest(revision.clone()),
                    namespace,
                ))
                .await?
        {
            return Ok(false);
        }

        let content = match self.blob_store.read(revision).await {
            Ok(content) => content,
            Err(RegistryError::BlobUnknown | RegistryError::NotFound) => {
                warn!(
                    "scrub: manifest blob missing for revision '{namespace}@{revision}'; removing revision"
                );
                self.emit(Action::DeleteOrphanManifest {
                    namespace: namespace.clone(),
                    digest: revision.clone(),
                })
                .await?;
                return Ok(false);
            }
            Err(e) => return Err(e.into()),
        };
        let manifest =
            Manifest::from_slice(&content).map_err(|e| RegistryError::manifest_invalid(&e))?;

        // The revision's own grant pins the manifest blob.
        self.ensure_grant(namespace, revision, &LinkKind::Digest(revision.clone()))
            .await?;

        // Only repair references the namespace already holds. A permissive push
        // withholds the link and the grant for a digest the namespace does not
        // own, so re-deriving them from the manifest body would hand it exactly
        // the cross-namespace read access the write path refused.
        // A tracked reference is pinned by its per-referrer entry alone; the
        // legacy link file is advisory and never repaired from a manifest.
        for (link, target) in link_plan::revision_links(&manifest, revision) {
            if !self.holds_reference(namespace, &target, &link).await? {
                debug!(
                    "scrub: '{namespace}' holds no reference to '{target}'; \
                     leaving the link from revision '{revision}' unrepaired"
                );
                continue;
            }
            if link.is_tracked() {
                self.ensure_grant(
                    namespace,
                    &target,
                    &LinkKind::ReferencedBy(revision.clone()),
                )
                .await?;
            } else {
                self.ensure_link(namespace, &link, &target).await?;
                self.ensure_grant(namespace, &target, &link).await?;
            }
        }
        Ok(true)
    }

    /// Whether the revision exists in either shape: its record, or its legacy
    /// link.
    async fn revision_exists(&self, namespace: &Namespace, digest: &Digest) -> Result<bool, Error> {
        let record_key = path_builder::revision_record_path(namespace, digest);
        match self.metadata_store.object_store().head(&record_key).await {
            Ok(_) => return Ok(true),
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(RegistryError::from(e).into()),
        }
        let link_key = path_builder::link_path(&LinkKind::Digest(digest.clone()), namespace);
        Ok(self.read_link_body(&link_key).await?.is_some())
    }

    /// Emit the namespace's catalog index key when it is missing, once per
    /// namespace per run.
    async fn ensure_catalog(&self, namespace: &Namespace) -> Result<(), Error> {
        if !self.claim(format!("catalog:{namespace}")) {
            return Ok(());
        }
        let key = path_builder::catalog_index_path(namespace);
        match self.metadata_store.object_store().head(&key).await {
            Ok(_) => Ok(()),
            Err(StorageError::NotFound) => {
                self.emit(Action::EnsureCatalogIndex {
                    namespace: namespace.clone(),
                })
                .await
            }
            Err(e) => Err(RegistryError::from(e).into()),
        }
    }

    /// Whether `namespace` already holds `target`. Writers never remove
    /// reference keys or tracked link files, so raw existence is not
    /// ownership: the namespace's own blob-index key counts directly, any
    /// other entry (and the link itself) only while the metadata store's
    /// `reference_backed` vouches for it, else a manifest
    /// delete's stale leftovers would mint back the access the write path
    /// refused. Losing every backed reference for one the namespace did own
    /// leaves the manifest unrepaired (and unpullable) rather than guessing
    /// in favour of access.
    async fn holds_reference(
        &self,
        namespace: &Namespace,
        target: &Digest,
        link: &LinkKind,
    ) -> Result<bool, Error> {
        match self
            .metadata_store
            .read_blob_index_namespace(namespace, target)
            .await
        {
            Ok(links) => {
                if links.contains(&LinkKind::Blob(target.clone())) {
                    return Ok(true);
                }
                for entry in &links {
                    if self
                        .metadata_store
                        .reference_backed(namespace, entry, target)
                        .await?
                    {
                        return Ok(true);
                    }
                }
            }
            Err(RegistryError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        let backed = self
            .metadata_store
            .reference_backed(namespace, link, target)
            .await?;
        Ok(backed)
    }

    /// A referrer link is live only while its referrer manifest is a current
    /// revision; a live legacy link converts into a referrer record.
    async fn validate_referrer_link(
        &self,
        key: &str,
        namespace: &Namespace,
        subject: &Digest,
        referrer: &Digest,
    ) -> Result<(), Error> {
        if self.read_link_body(key).await?.is_none() {
            return Ok(());
        }
        if self.revision_exists(namespace, referrer).await? {
            return self
                .emit(Action::ConvertReferrerLink {
                    namespace: namespace.clone(),
                    subject: subject.clone(),
                    referrer: referrer.clone(),
                })
                .await;
        }
        self.remove_dead_referrer(namespace, subject, referrer)
            .await
    }

    /// A referrer record is live only while its referrer manifest is a
    /// current revision. Grammars were checked at categorization.
    pub async fn validate_referrer_record(
        &self,
        namespace_raw: &str,
        subject: &Digest,
        referrer: &Digest,
    ) -> Result<(), Error> {
        let Ok(namespace) = Namespace::new(namespace_raw) else {
            return self.handle_invalid_namespace(namespace_raw).await;
        };
        let key = path_builder::referrer_record_path(&namespace, subject, referrer);
        match self.metadata_store.object_store().head(&key).await {
            Ok(_) => {}
            Err(StorageError::NotFound) => return Ok(()),
            Err(e) => return Err(RegistryError::from(e).into()),
        }
        // A young record may precede its referrer's revision inside a push,
        // or follow a delete whose tombstoning the walk raced; either way
        // pruning waits out the grace period.
        if self.younger_than_grace(&key).await? {
            return Ok(());
        }
        if self.revision_exists(&namespace, referrer).await? {
            return Ok(());
        }
        self.remove_dead_referrer(&namespace, subject, referrer)
            .await
    }

    /// The shared removal tail of both referrer shapes: confirm the referrer
    /// manifest is durably gone, then emit the orphan-referrer deletion.
    async fn remove_dead_referrer(
        &self,
        namespace: &Namespace,
        subject: &Digest,
        referrer: &Digest,
    ) -> Result<(), Error> {
        let reverify = move || async move { Ok(!self.revision_exists(namespace, referrer).await?) };
        if !self.confirm_repair(reverify).await? {
            return Ok(());
        }
        self.emit(Action::DeleteOrphanReferrer {
            namespace: namespace.clone(),
            subject: subject.clone(),
            referrer: referrer.clone(),
        })
        .await
    }

    /// A blob/layer/config/index-child link file: prune `referenced_by`
    /// entries whose revision is gone, re-home each live referrer's pin to
    /// its per-referrer reference entry, and once every live pin is covered
    /// and every dead one pruned, retire the file (the executor re-checks
    /// its age before deleting).
    async fn validate_tracked_link(
        &self,
        key: &str,
        namespace: &Namespace,
        link: LinkKind,
    ) -> Result<(), Error> {
        let Some(metadata) = self.read_link_body(key).await? else {
            return Ok(());
        };
        // A young link file may carry the back-link of a push whose revision
        // record is still in flight; pruning and retirement both wait out
        // the grace period.
        if self.younger_than_grace(key).await? {
            return Ok(());
        }
        let blob = match &link {
            LinkKind::Manifest { child, .. } => child.clone(),
            LinkKind::Blob(digest) | LinkKind::Layer(digest) | LinkKind::Config(digest) => {
                digest.clone()
            }
            // Dispatch never routes other kinds here.
            _ => return Ok(()),
        };
        let mut retire = true;
        for referrer in &metadata.referenced_by {
            if self.revision_exists(namespace, referrer).await? {
                // A live pin must exist as a per-referrer entry before the
                // file may go.
                if !self
                    .ensure_grant(namespace, &blob, &LinkKind::ReferencedBy(referrer.clone()))
                    .await?
                {
                    retire = false;
                }
                continue;
            }
            let reverify = move || async move {
                let Some(current) = self.read_link_body(key).await? else {
                    return Ok(false);
                };
                Ok(current.referenced_by.contains(referrer)
                    && !self.revision_exists(namespace, referrer).await?)
            };
            if !self.confirm_repair(reverify).await? {
                retire = false;
                continue;
            }
            self.emit(Action::RemoveReferrer {
                namespace: namespace.clone(),
                link: link.clone(),
                referrer: referrer.clone(),
            })
            .await?;
        }
        if retire {
            self.emit(Action::RetireTrackedLink {
                namespace: namespace.clone(),
                link,
            })
            .await?;
        }
        Ok(())
    }

    /// Read and parse the link body at `key`. `None` when the key vanished
    /// concurrently or its content was unreadable garbage (deleted here).
    async fn read_link_body(&self, key: &str) -> Result<Option<LinkMetadata>, Error> {
        let raw = match self.metadata_store.object_store().get(key).await {
            Ok(raw) => raw,
            Err(StorageError::NotFound) => return Ok(None),
            Err(e) => return Err(RegistryError::from(e).into()),
        };
        match serde_json::from_slice::<LinkMetadata>(&raw) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(e) => {
                warn!("scrub: link '{key}' does not parse as link metadata ({e}); deleting");
                self.delete_corrupt(WalkedStore::Metadata, key).await?;
                Ok(None)
            }
        }
    }

    /// Recreate `link -> expected` when it is confirmed missing or
    /// mistargeted (absorbed from the old `link_repair::ensure_link`). Any
    /// other read error propagates: a repair write must not be based on a
    /// read that never succeeded, and an unreadable link is deleted when its
    /// own key is visited.
    async fn ensure_link(
        &self,
        namespace: &Namespace,
        link: &LinkKind,
        expected: &Digest,
    ) -> Result<(), Error> {
        // A revision lives as a record or a legacy link; either satisfies.
        if matches!(link, LinkKind::Digest(_)) && self.revision_exists(namespace, expected).await? {
            return Ok(());
        }
        let link_key = path_builder::link_path(link, namespace);
        if let Some(metadata) = self.read_link_body(&link_key).await?
            && &metadata.target == expected
        {
            return Ok(());
        }
        let link_key = &link_key;
        let reverify = move || async move {
            Ok(self
                .read_link_body(link_key)
                .await?
                .is_none_or(|current| &current.target != expected))
        };
        if !self.confirm_repair(reverify).await? {
            return Ok(());
        }
        self.emit(Action::RecreateLink {
            namespace: namespace.clone(),
            link: link.clone(),
            target: expected.clone(),
        })
        .await
    }

    /// Emit a grant for `link` on `blob` unless the index already records it,
    /// and only for bytes that still exist (absorbed from the old
    /// `BlobIndexChecker`). Returns whether the entry is accounted for:
    /// already recorded, or its grant emitted this run.
    async fn ensure_grant(
        &self,
        namespace: &Namespace,
        blob: &Digest,
        link: &LinkKind,
    ) -> Result<bool, Error> {
        match self
            .metadata_store
            .read_blob_index_namespace(namespace, blob)
            .await
        {
            Ok(links) if links.contains(link) => return Ok(true),
            Ok(_) | Err(RegistryError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        match self.blob_store.size(blob).await {
            Ok(_) => {}
            Err(RegistryError::BlobUnknown | RegistryError::NotFound) => {
                // A manifest referencing missing bytes is a broken-manifest
                // problem; granting it would churn against the blob GC.
                return Ok(false);
            }
            Err(e) => return Err(e.into()),
        }
        let reverify = move || async move {
            match self
                .metadata_store
                .read_blob_index_namespace(namespace, blob)
                .await
            {
                Ok(links) => Ok(!links.contains(link)),
                Err(RegistryError::NotFound) => Ok(true),
                Err(e) => Err(e.into()),
            }
        };
        if !self.confirm_repair(reverify).await? {
            return Ok(false);
        }
        self.emit(Action::GrantBlobIndexLink {
            namespace: namespace.clone(),
            blob: blob.clone(),
            link: link.clone(),
        })
        .await?;
        Ok(true)
    }
}
