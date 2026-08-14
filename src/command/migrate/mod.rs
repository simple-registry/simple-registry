//! The `angos migrate` maintenance command: converts pre-JSON link metadata
//! into the current JSON [`LinkMetadata`] format and backfills a served
//! manifest link's `media_type`.
//!
//! Registries seeded from a raw upstream `distribution` on-disk layout hold
//! link files that are a bare digest string rather than JSON. The serving
//! paths parse link files as JSON only, so such a link no longer resolves,
//! cannot be rewritten (a read-modify-write reads it first), and cannot be
//! deleted through the API until it is migrated. This command walks every link
//! object once and rewrites each bare-digest file as JSON, leaving already-JSON
//! links and unrecognisable files untouched.
//!
//! It also recovers the `media_type` of every tag and revision link that lacks
//! one (a bare-digest link, or one an earlier migrate rewrote without it) from
//! the manifest body, so a manifest HEAD/GET always carries the `Content-Type`
//! the OCI spec requires. It is idempotent, so a partially completed run can
//! simply be re-run.

use std::str;

use argh::FromArgs;
use bytes::Bytes;
use futures_util::TryStreamExt;
use tracing::{debug, info, warn};

use angos_oci::{Digest, Manifest, MediaType};
use angos_tx_engine::{
    error::Error as TxError, executor::DEFAULT_RETRY_BUDGET, store::Store, transaction::Mutation,
};

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

/// What a scan decided for one link, which is both the counter it belongs to
/// and what the log line says.
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

/// Classify a link file's raw bytes. JSON that deserialises to `LinkMetadata`
/// is current; otherwise a bare digest string is a legacy `distribution` link,
/// and anything else is unrecognised and must not be rewritten.
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

/// Whether a link key is a tag or revision manifest link, the links served with
/// a `Content-Type`. Referrer and index back-links also live under `_manifests/`
/// but are never served as manifests, so they carry no `media_type`.
fn serves_manifest(key: &str) -> bool {
    key.contains("/_manifests/tags/") || key.contains("/_manifests/revisions/")
}

/// The media type for a served-manifest link's target, recovered from its stored
/// body: its own `mediaType`, else the one its shape implies, so a manifest GET
/// never lacks the `Content-Type` the OCI spec requires. `None` for a
/// non-manifest link (layer, config, referrer, index) or an unreadable body, in
/// which case the serving path recovers it on each read.
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

/// Whether a current JSON link is a served manifest still missing its media
/// type, the one case a rewrite has to recover.
fn needs_backfill(key: &str, metadata: &LinkMetadata) -> bool {
    metadata.media_type.is_none() && serves_manifest(key)
}

/// Rewrite one link inside a transaction whose read set is the link itself, so
/// the body the decision was made from is the body being replaced. A tag push
/// landing in between loses the etag precondition on a CAS backend and waits on
/// the key's lock on a lock-coordinated one, instead of being silently reverted
/// to its pre-push target.
async fn rewrite_link(store: &Store, blob_store: &BlobStore, key: &str) -> Result<Plan, Error> {
    let (_, plan) = store
        .update_with_payload(
            &[key.to_string()],
            |bodies| async move {
                let Some(body) = bodies.first().and_then(Option::as_ref) else {
                    return Ok((Vec::new(), Plan::Vanished));
                };
                let (metadata, plan) = match classify(body) {
                    LinkForm::Unrecognized => return Ok((Vec::new(), Plan::Unrecognized)),
                    LinkForm::Legacy(target) => {
                        let media_type = link_media_type(blob_store, key, &target).await;
                        (
                            LinkMetadata::without_timestamp(target.clone())
                                .with_media_type(media_type),
                            Plan::Migrated(target),
                        )
                    }
                    LinkForm::Current(metadata) if needs_backfill(key, &metadata) => {
                        match link_media_type(blob_store, key, &metadata.target).await {
                            Some(media_type) => (
                                (*metadata).with_media_type(Some(media_type)),
                                Plan::Backfilled,
                            ),
                            None => return Ok((Vec::new(), Plan::Current)),
                        }
                    }
                    LinkForm::Current(_) => return Ok((Vec::new(), Plan::Current)),
                };
                let body = Bytes::from(serde_json::to_vec(&metadata).map_err(TxError::Serde)?);
                Ok((
                    vec![Mutation::Put {
                        key: key.to_string(),
                        body,
                        expected: None,
                    }],
                    plan,
                ))
            },
            DEFAULT_RETRY_BUDGET,
        )
        .await
        .map_err(registry::Error::from)?;
    Ok(plan)
}

/// Walk every link object and rewrite each bare-digest file as JSON. Supersedes
/// the removed runtime fallback that parsed bare-digest links on every read.
pub async fn run(options: &Options, config: &Configuration) -> Result<(), Error> {
    let bootstrap::MaintenanceContext {
        blob_store,
        metadata_store,
        ..
    } = bootstrap::maintenance_context(config).await?;

    if options.dry_run {
        info!("Dry-run mode: scanning links without rewriting them");
    }

    let report = migrate_links(metadata_store.store(), &blob_store, options.dry_run).await?;

    log_summary(&report, options.dry_run);
    Ok(())
}

/// Walk every link object under the repositories root, rewriting each
/// bare-digest file as JSON and backfilling a missing manifest media type.
/// Streams the keys so it never holds more than one listing page in memory.
async fn migrate_links(
    store: &Store,
    blob_store: &BlobStore,
    dry_run: bool,
) -> Result<Report, Error> {
    let root = path_builder::REPOS_ROOT;
    let mut report = Report::default();
    let mut keys = store
        .object_store()
        .list_all(root)
        .map_err(registry::Error::from);
    while let Some(key) = keys.try_next().await? {
        // `list_all` yields keys relative to `root`; rebuild the full key before
        // touching the object.
        if key.ends_with("/link") {
            let full_key = format!("{root}/{key}");
            // Mirrors scrub: one defective object is warned and counted rather
            // than stranding a sweep that is re-runnable and idempotent.
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

/// Read one link file, rewriting a bare-digest legacy link as JSON and
/// backfilling a served-manifest link's missing media type from the body.
async fn migrate_one(
    store: &Store,
    blob_store: &BlobStore,
    key: &str,
    dry_run: bool,
    report: &mut Report,
) -> Result<(), Error> {
    report.scanned += 1;
    let plan = if dry_run {
        // A dry run writes nothing, so it needs neither a transaction nor the
        // manifest body: classifying the link is enough to say what a real run
        // would do.
        let raw = store
            .object_store()
            .get(key)
            .await
            .map_err(registry::Error::from)?;
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
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

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

        // Seed a pre-JSON bare-digest link, the format the serving path no
        // longer reads.
        put_link_raw(
            metadata_store.store(),
            &namespace,
            &link,
            target.to_string().as_bytes(),
        )
        .await;
        assert!(
            metadata_store.read_link(&namespace, &link).await.is_err(),
            "bare-digest link should not parse before migration"
        );

        let report = migrate_links(metadata_store.store(), &blob_store, false)
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

    /// A body that will not parse still gets a `Content-Type`: the OCI image
    /// manifest type, rather than a link left typeless.
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
            metadata_store.store(),
            &namespace,
            &link,
            target.to_string().as_bytes(),
        )
        .await;

        let report = migrate_links(metadata_store.store(), &blob_store, false)
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

        // A JSON tag link that an earlier migrate rewrote without a media type.
        let metadata = LinkMetadata::without_timestamp(target.clone());
        put_link_raw(
            metadata_store.store(),
            &namespace,
            &link,
            &serde_json::to_vec(&metadata).unwrap(),
        )
        .await;

        let report = migrate_links(metadata_store.store(), &blob_store, false)
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
            metadata_store.store(),
            &namespace,
            &link,
            digest().to_string().as_bytes(),
        )
        .await;

        let report = migrate_links(metadata_store.store(), &blob_store, false)
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
            metadata_store.store(),
            &namespace,
            &link,
            target.to_string().as_bytes(),
        )
        .await;

        migrate_links(metadata_store.store(), &blob_store, false)
            .await
            .unwrap();

        // A second pass finds the link already current and rewrites nothing.
        let report = migrate_links(metadata_store.store(), &blob_store, false)
            .await
            .unwrap();
        assert_eq!(report.migrated, 0);
        assert_eq!(report.backfilled, 0);
        assert_eq!(report.current, 1);
    }

    /// Fails every read of `key`, standing in for a permanently unreadable
    /// link object.
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
                test_case.metadata_store().store(),
                &namespace,
                link,
                digest().to_string().as_bytes(),
            )
            .await;
        }

        let inner: Arc<dyn ObjectStore> = test_case.metadata_store().store().object_store().clone();
        let hooked: Arc<dyn ObjectStore> = Arc::new(HookedStore::new(
            inner,
            FailReadsOf {
                key: path_builder::link_path(&broken, &namespace),
            },
        ));
        let metadata_store = metadata_store_over_cached(hooked, 0);

        let report = migrate_links(metadata_store.store(), &blob_store, false)
            .await
            .expect("one unreadable link must not fail the run");

        assert_eq!(report.failed, 1, "the unreadable link must be counted");
        assert_eq!(report.migrated, 1, "the healthy link must still migrate");
        assert!(
            metadata_store.read_link(&namespace, &healthy).await.is_ok(),
            "the healthy link must be readable after the run"
        );
    }

    /// Writes `body` to `key` the first time the locked executor re-reads that
    /// key to verify its read fingerprint, which is the instant a concurrent
    /// tag push would land: after migrate captured the body it decided from,
    /// before migrate's own write.
    struct PushOnVerifyingRead {
        inner: Arc<dyn ObjectStore>,
        key: String,
        body: Bytes,
        reads: AtomicUsize,
        injected: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl StoreHook for PushOnVerifyingRead {
        async fn before(&self, op: StoreOp<'_>) -> Result<(), StorageError> {
            if let StoreOp::Get { key } = op
                && key == self.key
                && self.reads.fetch_add(1, Ordering::SeqCst) == 1
            {
                self.inner.put(&self.key, self.body.clone()).await?;
                self.injected.store(true, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    /// A tag push landing between migrate's read and its write must survive.
    /// The unlocked read-modify-write this replaced put the pre-push target
    /// back, silently losing the push.
    #[tokio::test]
    async fn a_push_landing_mid_rewrite_is_not_reverted() {
        let test_case = FSRegistryTestCase::new();
        let blob_store = test_case.blob_store();
        let namespace = Namespace::new("migrate-repo").unwrap();
        let link = LinkKind::Tag(Tag::new("latest").unwrap());
        let key = path_builder::link_path(&link, &namespace);
        let pushed = Digest::sha256_of_bytes(b"the tag push that must survive");

        // The push writes a current JSON link, exactly as a real push would.
        let pushed_body = Bytes::from(
            serde_json::to_vec(&LinkMetadata::without_timestamp(pushed.clone())).unwrap(),
        );
        let injected = Arc::new(AtomicBool::new(false));
        let inner: Arc<dyn ObjectStore> = test_case.metadata_store().store().object_store().clone();
        let hooked: Arc<dyn ObjectStore> = Arc::new(HookedStore::new(
            inner.clone(),
            PushOnVerifyingRead {
                inner,
                key: key.clone(),
                body: pushed_body,
                reads: AtomicUsize::new(0),
                injected: injected.clone(),
            },
        ));
        let metadata_store = metadata_store_over_cached(hooked, 0);

        // Seed the legacy bare-digest link migrate is about to rewrite.
        put_link_raw(
            metadata_store.store(),
            &namespace,
            &link,
            digest().to_string().as_bytes(),
        )
        .await;

        rewrite_link(metadata_store.store(), &blob_store, &key)
            .await
            .expect("a link changing mid-rewrite must not fail the run");

        // Without this the test passes vacuously: an unlocked read-modify-write
        // never re-reads, so the push would never be injected at all.
        assert!(
            injected.load(Ordering::SeqCst),
            "the rewrite must re-read the link under the lock, which is where the push lands"
        );
        let final_link = metadata_store.read_link(&namespace, &link).await.unwrap();
        assert_eq!(
            final_link.target, pushed,
            "the pushed target must survive; migrate must not restore the pre-push one"
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
            metadata_store.store(),
            &namespace,
            &link,
            digest().to_string().as_bytes(),
        )
        .await;

        let report = migrate_links(metadata_store.store(), &blob_store, true)
            .await
            .unwrap();
        assert_eq!(report.migrated, 1);
        assert!(
            metadata_store.read_link(&namespace, &link).await.is_err(),
            "dry run must not rewrite the link"
        );
    }
}
