//! Link-key validation: one visit per link file replaces the old per-concern
//! walks (manifest link repair, blob-index grant reconcile, tag digest links,
//! referrer liveness, the invalid-tag gate, and the orphan-namespace
//! clearing), plus the migration of a link object superseded by the
//! blob-index entry naming its referrer.

use tracing::{debug, warn};

use angos_oci::{Digest, Manifest, Namespace, Tag};
use angos_tx_engine::StorageError;

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
        metadata_store::{LinkKind, LinkMetadata},
        path_builder,
    },
};

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
            // The ownership grant is still written and is its own record, so
            // there is nothing here to repair or reclaim.
            ParsedLink::Blob(_) => Ok(()),
            ParsedLink::Layer(digest) | ParsedLink::Config(digest) => {
                self.migrate_superseded_link(key, &namespace, &digest).await
            }
            ParsedLink::ManifestIndex { child, .. } => {
                self.migrate_superseded_link(key, &namespace, &child).await
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
        let target = metadata.target;

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

    /// A manifest revision link: the anchor of the derivable state. One
    /// manifest read drives child-link repair, `referenced_by` back-links,
    /// and blob-index grant reconciliation.
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

        let content = match self.blob_store.read(revision).await {
            Ok(content) => content,
            Err(RegistryError::BlobUnknown | RegistryError::NotFound) => {
                warn!(
                    "scrub: manifest blob missing for revision '{namespace}@{revision}'; removing revision"
                );
                return self
                    .emit(Action::DeleteOrphanManifest {
                        namespace: namespace.clone(),
                        digest: revision.clone(),
                    })
                    .await;
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
        for (link, target) in link_plan::revision_links(&manifest, revision) {
            if !self.holds_reference(namespace, &target, &link).await? {
                debug!(
                    "scrub: '{namespace}' holds no reference to '{target}'; \
                     leaving the link from revision '{revision}' unrepaired"
                );
                continue;
            }
            // A tracked reference has no link object: the shard entry naming
            // this revision is the whole record, so the grant is the repair.
            if link.is_tracked() {
                self.ensure_grant(namespace, &target, &LinkKind::Digest(revision.clone()))
                    .await?;
                continue;
            }
            self.ensure_link(namespace, &link, &target).await?;
            self.ensure_grant(namespace, &target, &link).await?;
        }
        Ok(())
    }

    /// Whether `namespace` already holds `target`: a live blob-index entry for
    /// the digest, or this link already on disk. The blob index is what
    /// authorizes a cross-namespace read, and a withheld reference leaves
    /// neither behind, so this is what separates repairing a namespace's own
    /// state from minting access it never had. Losing both for a reference it
    /// did own leaves the manifest unrepaired (and unpullable) rather than
    /// guessing in favour of access.
    ///
    /// A tracked reference has only the entry now, the link object having gone
    /// with the layout change, so a lost shard is not recoverable from a
    /// manifest body: an owned reference and one a permissive push withheld
    /// look the same, and the conservative reading wins. Re-pushing the
    /// manifest restores it.
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
            Ok(links) if !links.is_empty() => return Ok(true),
            Ok(_) | Err(RegistryError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        let link_key = path_builder::link_path(link, namespace);
        Ok(self.read_link_body(&link_key).await?.is_some())
    }

    /// A referrer link is live only while its referrer manifest is a current
    /// revision.
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
        let revision_key = path_builder::link_path(&LinkKind::Digest(referrer.clone()), namespace);
        if self.read_link_body(&revision_key).await?.is_some() {
            return Ok(());
        }
        let evidence = [key.to_string(), revision_key.clone()];
        let revision_key = &revision_key;
        let reverify = move || async move {
            Ok(self.read_link_body(key).await?.is_some()
                && self.read_link_body(revision_key).await?.is_none())
        };
        if !self.confirm_repair(&evidence, reverify).await? {
            return Ok(());
        }
        self.emit(Action::DeleteOrphanReferrer {
            namespace: namespace.clone(),
            subject: subject.clone(),
            referrer: referrer.clone(),
        })
        .await
    }

    /// Migrate a link object that predates the blob-index entry naming its
    /// referrer, then reclaim it.
    ///
    /// A tracked reference lives in the entry now, so the object is not
    /// maintained: each referrer whose revision is still present is re-issued
    /// as an entry against `target`, and the object is then deleted. The shard
    /// pass drops the paired entry it backed once the object is gone, so the
    /// old shape leaves nothing behind.
    ///
    /// A referrer whose revision has gone is simply not migrated: it is the
    /// dangling back-link the old layout needed a repair to prune.
    async fn migrate_superseded_link(
        &self,
        key: &str,
        namespace: &Namespace,
        target: &Digest,
    ) -> Result<(), Error> {
        let Some(metadata) = self.read_link_body(key).await? else {
            return Ok(());
        };
        // Every revision consulted is evidence: one still being written has no
        // revision link yet, so its reference would not be migrated and the
        // reclaim has to wait rather than drop it.
        let mut evidence = vec![key.to_string()];
        for referrer in &metadata.referenced_by {
            let revision_key =
                path_builder::link_path(&LinkKind::Digest(referrer.clone()), namespace);
            if self.read_link_body(&revision_key).await?.is_some() {
                self.ensure_grant(namespace, target, &LinkKind::Digest(referrer.clone()))
                    .await?;
            }
            evidence.push(revision_key);
        }

        let reverify = move || async move { Ok(self.read_link_body(key).await?.is_some()) };
        if !self.confirm_repair(&evidence, reverify).await? {
            return Ok(());
        }
        self.emit(Action::DeleteSupersededLink {
            store: WalkedStore::Metadata,
            key: key.to_string(),
        })
        .await
    }

    /// Read and parse the link body at `key`. `None` when the key vanished
    /// concurrently or its content was unreadable garbage (deleted here).
    async fn read_link_body(&self, key: &str) -> Result<Option<LinkMetadata>, Error> {
        let raw = match self.metadata_store.store().object_store().get(key).await {
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
        let link_key = path_builder::link_path(link, namespace);
        if let Some(metadata) = self.read_link_body(&link_key).await?
            && &metadata.target == expected
        {
            return Ok(());
        }
        let evidence = [link_key.clone()];
        let link_key = &link_key;
        let reverify = move || async move {
            Ok(self
                .read_link_body(link_key)
                .await?
                .is_none_or(|current| &current.target != expected))
        };
        if !self.confirm_repair(&evidence, reverify).await? {
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
    /// `BlobIndexChecker`).
    async fn ensure_grant(
        &self,
        namespace: &Namespace,
        blob: &Digest,
        link: &LinkKind,
    ) -> Result<(), Error> {
        match self
            .metadata_store
            .read_blob_index_namespace(namespace, blob)
            .await
        {
            Ok(links) if links.contains(link) => return Ok(()),
            Ok(_) | Err(RegistryError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        match self.blob_store.size(blob).await {
            Ok(_) => {}
            Err(RegistryError::BlobUnknown | RegistryError::NotFound) => {
                // A manifest referencing missing bytes is a broken-manifest
                // problem; granting it would churn against the blob GC.
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        let evidence = [path_builder::blob_index_shard_path(blob, namespace)];
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
        if !self.confirm_repair(&evidence, reverify).await? {
            return Ok(());
        }
        self.emit(Action::GrantBlobIndexLink {
            namespace: namespace.clone(),
            blob: blob.clone(),
            link: link.clone(),
        })
        .await
    }
}
