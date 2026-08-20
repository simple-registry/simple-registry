//! The `angos migrate` maintenance command: rewrites pre-JSON bare-digest link
//! files as [`LinkMetadata`] JSON and backfills a served manifest link's
//! `media_type` from the manifest body.
//!
//! A registry seeded from a raw `distribution` layout holds link files that are
//! a bare digest string, which the serving paths cannot parse, so such a link
//! only resolves, rewrites and deletes once migrated. The sweep leaves
//! already-JSON and unrecognisable files untouched and is idempotent, so a
//! partial run can simply be re-run.

use std::{str, sync::Arc};

use argh::FromArgs;
use bytes::Bytes;
use futures_util::TryStreamExt;
use tracing::{debug, info, warn};

use angos_oci::{Digest, Manifest, MediaType};
use angos_storage::{Error as StorageError, ObjectStore};

use crate::{
    command::bootstrap,
    configuration::Configuration,
    registry::{self, blob_store::BlobStore, metadata_store::LinkMetadata, path_builder},
};

mod error;

pub use error::Error;

/// A link file's on-disk form, decided by trying to parse its raw bytes.
enum LinkForm {
    /// Already the current JSON `LinkMetadata`; may still need a `media_type` backfill.
    Current(Box<LinkMetadata>),
    /// A pre-JSON `distribution` link: a bare digest string to rebuild from.
    Legacy(Digest),
    /// Neither JSON nor a bare digest: left untouched and reported.
    Unrecognized,
}

/// Tally of what a run saw, logged as its summary.
#[derive(Default)]
struct Report {
    scanned: u64,
    current: u64,
    migrated: u64,
    backfilled: u64,
    unrecognized: u64,
    vanished: u64,
    failed: u64,
}

/// What a scan decided for one link: its counter and its log line.
enum Plan {
    /// Already current, or a served manifest whose body could not be read.
    Current,
    /// A pre-JSON bare-digest link, rebuilt as JSON against this target.
    Migrated(Digest),
    /// A current JSON link gaining the media type it lacked.
    Backfilled,
    /// Neither JSON nor a bare digest.
    Unrecognized,
    /// Deleted between the listing and the rewrite.
    Vanished,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(
    subcommand,
    name = "migrate",
    description = "Convert pre-JSON bare-digest link metadata to the current JSON format"
)]
pub struct Options {
    #[argh(switch, short = 'd')]
    /// display only, no actual changes applied
    pub dry_run: bool,
}

/// Classify a link file's raw bytes: `LinkMetadata` JSON is current, a bare
/// digest string is a legacy `distribution` link, and anything else must not be
/// rewritten.
fn classify(raw: &[u8]) -> LinkForm {
    if let Ok(metadata) = serde_json::from_slice::<LinkMetadata>(raw) {
        return LinkForm::Current(Box::new(metadata));
    }
    match str::from_utf8(raw)
        .ok()
        .and_then(|text| Digest::try_from(text.trim()).ok())
    {
        Some(target) => LinkForm::Legacy(target),
        None => LinkForm::Unrecognized,
    }
}

/// Whether a link key is a tag or revision manifest link, the ones served with
/// a `Content-Type`. Referrer and index back-links live under `_manifests/` too
/// but are never served as manifests, so they carry no `media_type`.
fn serves_manifest(key: &str) -> bool {
    key.contains("/_manifests/tags/") || key.contains("/_manifests/revisions/")
}

/// The media type for a served-manifest link's target, read from its stored
/// body. `None` for a non-manifest link or an unreadable body, in which case the
/// serving path recovers it on each read.
async fn link_media_type(blob_store: &BlobStore, key: &str, target: &Digest) -> Option<MediaType> {
    if !serves_manifest(key) {
        return None;
    }
    match blob_store.read(target).await {
        Ok(body) => Some(Manifest::from_slice(&body).as_ref().map_or_else(
            |_| MediaType::oci_manifest(),
            Manifest::described_media_type,
        )),
        Err(error) => {
            warn!(
                "Cannot read manifest {target} for link {key} to recover its media type: {error}"
            );
            None
        }
    }
}

/// Whether a current JSON link is a served manifest still missing its media type.
fn needs_backfill(key: &str, metadata: &LinkMetadata) -> bool {
    metadata.media_type.is_none() && serves_manifest(key)
}

/// Rewrite one link as a plain read-classify-write. Nothing rewrites legacy
/// links concurrently (a push writes tag entries and revision records, not these
/// keys), so the unguarded overwrite cannot revert a live write.
async fn rewrite_link(
    store: &Arc<dyn ObjectStore>,
    blob_store: &BlobStore,
    key: &str,
) -> Result<Plan, Error> {
    let body = match store.get(key).await {
        Ok(body) => body,
        Err(StorageError::NotFound) => return Ok(Plan::Vanished),
        Err(e) => return Err(registry::Error::from(e).into()),
    };
    let (metadata, plan) = match classify(&body) {
        LinkForm::Unrecognized => return Ok(Plan::Unrecognized),
        LinkForm::Legacy(target) => {
            let media_type = link_media_type(blob_store, key, &target).await;
            (
                LinkMetadata::without_timestamp(target.clone()).with_media_type(media_type),
                Plan::Migrated(target),
            )
        }
        LinkForm::Current(metadata) if needs_backfill(key, &metadata) => {
            match link_media_type(blob_store, key, &metadata.target).await {
                Some(media_type) => (
                    (*metadata).with_media_type(Some(media_type)),
                    Plan::Backfilled,
                ),
                None => return Ok(Plan::Current),
            }
        }
        LinkForm::Current(_) => return Ok(Plan::Current),
    };
    let body = Bytes::from(serde_json::to_vec(&metadata).map_err(registry::Error::from)?);
    store.put(key, body).await.map_err(registry::Error::from)?;
    Ok(plan)
}

/// Walk every link object and rewrite each bare-digest file as JSON.
pub async fn run(options: &Options, config: &Configuration) -> Result<(), Error> {
    let bootstrap::MaintenanceContext {
        blob_store,
        metadata_store,
        ..
    } = bootstrap::maintenance_context(config).await?;

    if options.dry_run {
        info!("Dry-run mode: scanning links without rewriting them");
    }

    let report = migrate_links(metadata_store.object_store(), &blob_store, options.dry_run).await?;

    log_summary(&report, options.dry_run);
    Ok(())
}

/// Walk every link object under the repositories root, streaming the keys so no
/// more than one listing page is held in memory.
async fn migrate_links(
    store: &Arc<dyn ObjectStore>,
    blob_store: &BlobStore,
    dry_run: bool,
) -> Result<Report, Error> {
    let root = path_builder::REPOS_ROOT;
    let mut report = Report::default();
    let mut keys = store.list_all(root).map_err(registry::Error::from);
    while let Some(key) = keys.try_next().await? {
        // `list_all` yields keys relative to `root`; rebuild the full key before
        // touching the object.
        if key.ends_with("/link") {
            let full_key = format!("{root}/{key}");
            // One defective object is counted rather than stranding a sweep
            // that is re-runnable and idempotent.
            if let Err(error) =
                migrate_one(store, blob_store, &full_key, dry_run, &mut report).await
            {
                report.failed += 1;
                warn!("Cannot migrate link {full_key}: {error}");
            }
        }
    }
    Ok(report)
}

/// Migrate one link file and record its outcome in `report`.
async fn migrate_one(
    store: &Arc<dyn ObjectStore>,
    blob_store: &BlobStore,
    key: &str,
    dry_run: bool,
    report: &mut Report,
) -> Result<(), Error> {
    report.scanned += 1;
    let plan = if dry_run {
        // A dry run writes nothing, so classifying the link is enough to say
        // what a real run would do.
        let raw = store.get(key).await.map_err(registry::Error::from)?;
        match classify(&raw) {
            LinkForm::Unrecognized => Plan::Unrecognized,
            LinkForm::Legacy(target) => Plan::Migrated(target),
            LinkForm::Current(metadata) if needs_backfill(key, &metadata) => Plan::Backfilled,
            LinkForm::Current(_) => Plan::Current,
        }
    } else {
        rewrite_link(store, blob_store, key).await?
    };
    record(&plan, key, dry_run, report);
    Ok(())
}

/// Count one link's outcome and log what was done to it.
fn record(plan: &Plan, key: &str, dry_run: bool, report: &mut Report) {
    match plan {
        Plan::Current => report.current += 1,
        Plan::Migrated(target) => {
            report.migrated += 1;
            if dry_run {
                info!("Would migrate legacy link {key} -> {target}");
            } else {
                debug!("Migrated legacy link {key} -> {target}");
            }
        }
        Plan::Backfilled => {
            report.backfilled += 1;
            if dry_run {
                info!("Would backfill media type for link {key}");
            } else {
                debug!("Backfilled media type for link {key}");
            }
        }
        Plan::Unrecognized => {
            report.unrecognized += 1;
            warn!("Link {key} is neither JSON nor a bare digest; leaving it untouched");
        }
        Plan::Vanished => {
            report.vanished += 1;
            debug!("Link {key} was deleted before it could be rewritten; skipping");
        }
    }
}

fn log_summary(report: &Report, dry_run: bool) {
    let verb = if dry_run { "would migrate" } else { "migrated" };
    let backfill_verb = if dry_run {
        "would backfill"
    } else {
        "backfilled"
    };
    info!(
        "Link migration complete: scanned {}, {verb} {}, {backfill_verb} media type on {}, already current {}, unrecognized {}, deleted mid-run {}, failed {}",
        report.scanned,
        report.migrated,
        report.backfilled,
        report.current,
        report.unrecognized,
        report.vanished,
        report.failed
    );
    if report.failed > 0 {
        warn!(
            "{} link file(s) could not be read or rewritten and were skipped; \
             re-run migrate once the cause is resolved",
            report.failed
        );
    }
    if report.unrecognized > 0 {
        warn!(
            "{} link file(s) were neither JSON nor a bare digest and were left untouched; \
             inspect them manually",
            report.unrecognized
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use angos_oci::{Namespace, Tag};
    use angos_storage::{
        Error as StorageError, ObjectStore,
        test_util::{HookedStore, StoreHook, StoreOp},
    };

    use crate::command::migrate::*;
    use crate::registry::{
        metadata_store::LinkKind,
        test_utils::{
            FSRegistryTestCase, RegistryTestCase, metadata_store_over_cached, put_link_raw,
        },
    };

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

    fn digest() -> Digest {
        Digest::sha256(HASH).unwrap()
    }

    /// Stores a minimal manifest body in the blob store, returning its digest.
    async fn seed_manifest_blob(blob_store: &BlobStore) -> Digest {
        let body = format!(r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}"}}"#).into_bytes();
        let target = Digest::sha256_of_bytes(&body);
        blob_store
            .put_blob(&target, Bytes::from(body))
            .await
            .unwrap();
        target
    }

    #[test]
    fn classify_recognizes_current_json_link() {
        let metadata = LinkMetadata::without_timestamp(digest());
        let json = serde_json::to_vec(&metadata).unwrap();
        assert!(matches!(classify(&json), LinkForm::Current(_)));
    }

    #[test]
    fn serves_manifest_matches_tag_and_revision_links_only() {
        assert!(serves_manifest(
            "v2/repositories/ns/_manifests/tags/v1/current/link"
        ));
        assert!(serves_manifest(&format!(
            "v2/repositories/ns/_manifests/revisions/sha256/{HASH}/link"
        )));
        assert!(!serves_manifest(&format!(
            "v2/repositories/ns/_layers/sha256/{HASH}/link"
        )));
        assert!(!serves_manifest(&format!(
            "v2/repositories/ns/_manifests/referrers/sha256/{HASH}/sha256/{HASH}/link"
        )));
    }

    #[test]
    fn classify_recognizes_bare_digest_as_legacy() {
        let raw = format!("sha256:{HASH}");
        match classify(raw.as_bytes()) {
            LinkForm::Legacy(target) => assert_eq!(target, digest()),
            _ => panic!("bare digest should classify as legacy"),
        }
    }

    #[test]
    fn classify_tolerates_trailing_whitespace_on_bare_digest() {
        let raw = format!("sha256:{HASH}\n");
        assert!(matches!(classify(raw.as_bytes()), LinkForm::Legacy(_)));
    }

    #[test]
    fn classify_rejects_garbage_as_unrecognized() {
        assert!(matches!(classify(b"not a digest"), LinkForm::Unrecognized));
        assert!(matches!(classify(&[0xff, 0xfe]), LinkForm::Unrecognized));
        assert!(matches!(classify(b""), LinkForm::Unrecognized));
    }

    #[tokio::test]
    async fn migrate_rewrites_bare_digest_link_as_readable_json() {
        let test_case = FSRegistryTestCase::new();
        let metadata_store = test_case.metadata_store();
        let blob_store = test_case.blob_store();
        let namespace = Namespace::new("migrate-repo").unwrap();
        let link = LinkKind::Tag(Tag::new("latest").unwrap());
        let target = seed_manifest_blob(&blob_store).await;

        // Seed a pre-JSON bare-digest link, which the serving path cannot read.
        put_link_raw(
            metadata_store.object_store(),
            &namespace,
            &link,
            target.to_string().as_bytes(),
        )
        .await;
        assert!(
            metadata_store.read_link(&namespace, &link).await.is_err(),
            "bare-digest link should not parse before migration"
        );

        let report = migrate_links(metadata_store.object_store(), &blob_store, false)
            .await
            .unwrap();
        assert_eq!(report.migrated, 1);
        assert_eq!(report.scanned, 1);

        let migrated = metadata_store.read_link(&namespace, &link).await.unwrap();
        assert_eq!(migrated.target, target);
        assert!(
            migrated.created_at.is_none(),
            "a migrated legacy link must never win last-writer-wins"
        );
        assert_eq!(
            migrated.media_type,
            Some(MediaType::new(OCI_MANIFEST).unwrap()),
            "a migrated tag link must recover its media type from the body"
        );
    }

    /// A body that will not parse still gets a `Content-Type`, the OCI image
    /// manifest type, rather than being left typeless.
    #[tokio::test]
    async fn migrate_types_an_unparseable_manifest_body_as_an_image_manifest() {
        let test_case = FSRegistryTestCase::new();
        let metadata_store = test_case.metadata_store();
        let blob_store = test_case.blob_store();
        let namespace = Namespace::new("migrate-repo").unwrap();
        let link = LinkKind::Tag(Tag::new("latest").unwrap());
        let body = Bytes::from_static(b"not a manifest");
        let target = Digest::sha256_of_bytes(&body);
        blob_store.put_blob(&target, body).await.unwrap();

        put_link_raw(
            metadata_store.object_store(),
            &namespace,
            &link,
            target.to_string().as_bytes(),
        )
        .await;

        let report = migrate_links(metadata_store.object_store(), &blob_store, false)
            .await
            .unwrap();
        assert_eq!(report.migrated, 1);

        let migrated = metadata_store.read_link(&namespace, &link).await.unwrap();
        assert_eq!(migrated.media_type, Some(MediaType::oci_manifest()));
    }

    #[tokio::test]
    async fn migrate_backfills_media_type_on_a_media_typeless_json_link() {
        let test_case = FSRegistryTestCase::new();
        let metadata_store = test_case.metadata_store();
        let blob_store = test_case.blob_store();
        let namespace = Namespace::new("migrate-repo").unwrap();
        let link = LinkKind::Tag(Tag::new("latest").unwrap());
        let target = seed_manifest_blob(&blob_store).await;

        // A JSON tag link carrying no media type.
        let metadata = LinkMetadata::without_timestamp(target.clone());
        put_link_raw(
            metadata_store.object_store(),
            &namespace,
            &link,
            &serde_json::to_vec(&metadata).unwrap(),
        )
        .await;

        let report = migrate_links(metadata_store.object_store(), &blob_store, false)
            .await
            .unwrap();
        assert_eq!(report.migrated, 0);
        assert_eq!(report.backfilled, 1);

        let backfilled = metadata_store.read_link(&namespace, &link).await.unwrap();
        assert_eq!(
            backfilled.media_type,
            Some(MediaType::new(OCI_MANIFEST).unwrap())
        );
    }

    #[tokio::test]
    async fn migrate_leaves_non_manifest_links_without_media_type() {
        let test_case = FSRegistryTestCase::new();
        let metadata_store = test_case.metadata_store();
        let blob_store = test_case.blob_store();
        let namespace = Namespace::new("migrate-repo").unwrap();
        let link = LinkKind::Layer(digest());

        put_link_raw(
            metadata_store.object_store(),
            &namespace,
            &link,
            digest().to_string().as_bytes(),
        )
        .await;

        let report = migrate_links(metadata_store.object_store(), &blob_store, false)
            .await
            .unwrap();
        assert_eq!(report.migrated, 1);

        let migrated = metadata_store.read_link(&namespace, &link).await.unwrap();
        assert!(
            migrated.media_type.is_none(),
            "a layer link is not a served manifest and needs no media type"
        );
    }

    #[tokio::test]
    async fn migrate_is_idempotent_and_leaves_current_links_untouched() {
        let test_case = FSRegistryTestCase::new();
        let metadata_store = test_case.metadata_store();
        let blob_store = test_case.blob_store();
        let namespace = Namespace::new("migrate-repo").unwrap();
        let link = LinkKind::Tag(Tag::new("latest").unwrap());
        let target = seed_manifest_blob(&blob_store).await;

        put_link_raw(
            metadata_store.object_store(),
            &namespace,
            &link,
            target.to_string().as_bytes(),
        )
        .await;

        migrate_links(metadata_store.object_store(), &blob_store, false)
            .await
            .unwrap();

        // A second pass finds the link already current and rewrites nothing.
        let report = migrate_links(metadata_store.object_store(), &blob_store, false)
            .await
            .unwrap();
        assert_eq!(report.migrated, 0);
        assert_eq!(report.backfilled, 0);
        assert_eq!(report.current, 1);
    }

    /// Fails every read of `key`, standing in for an unreadable link object.
    struct FailReadsOf {
        key: String,
    }

    #[async_trait::async_trait]
    impl StoreHook for FailReadsOf {
        async fn before(&self, op: StoreOp<'_>) -> Result<(), StorageError> {
            match op {
                StoreOp::Get { key } if key == self.key => {
                    Err(StorageError::Backend("unreadable".to_string()))
                }
                _ => Ok(()),
            }
        }
    }

    /// One defective object must not strand the sweep: the run completes, the
    /// healthy link is still migrated, and the failure is counted.
    #[tokio::test]
    async fn an_unreadable_link_is_counted_and_the_run_continues() {
        let test_case = FSRegistryTestCase::new();
        let blob_store = test_case.blob_store();
        let namespace = Namespace::new("migrate-repo").unwrap();
        let broken = LinkKind::Tag(Tag::new("broken").unwrap());
        let healthy = LinkKind::Tag(Tag::new("healthy").unwrap());

        for link in [&broken, &healthy] {
            put_link_raw(
                test_case.metadata_store().object_store(),
                &namespace,
                link,
                digest().to_string().as_bytes(),
            )
            .await;
        }

        let inner: Arc<dyn ObjectStore> = test_case.metadata_store().object_store().clone();
        let hooked: Arc<dyn ObjectStore> = Arc::new(HookedStore::new(
            inner,
            FailReadsOf {
                key: path_builder::link_path(&broken, &namespace),
            },
        ));
        let metadata_store = metadata_store_over_cached(hooked, 0);

        let report = migrate_links(metadata_store.object_store(), &blob_store, false)
            .await
            .expect("one unreadable link must not fail the run");

        assert_eq!(report.failed, 1, "the unreadable link must be counted");
        assert_eq!(report.migrated, 1, "the healthy link must still migrate");
        assert!(
            metadata_store.read_link(&namespace, &healthy).await.is_ok(),
            "the healthy link must be readable after the run"
        );
    }

    #[tokio::test]
    async fn dry_run_reports_without_rewriting() {
        let test_case = FSRegistryTestCase::new();
        let metadata_store = test_case.metadata_store();
        let blob_store = test_case.blob_store();
        let namespace = Namespace::new("migrate-repo").unwrap();
        let link = LinkKind::Tag(Tag::new("latest").unwrap());

        put_link_raw(
            metadata_store.object_store(),
            &namespace,
            &link,
            digest().to_string().as_bytes(),
        )
        .await;

        let report = migrate_links(metadata_store.object_store(), &blob_store, true)
            .await
            .unwrap();
        assert_eq!(report.migrated, 1);
        assert!(
            metadata_store.read_link(&namespace, &link).await.is_err(),
            "dry run must not rewrite the link"
        );
    }
}
