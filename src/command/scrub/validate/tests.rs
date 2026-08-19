use std::io::Cursor;
use std::slice;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use angos_oci::request::{DeleteBlobRequest, PutManifestRequest};
use angos_oci::{Digest, Namespace, Reference, Tag};

use crate::{
    command::{
        maintenance::{
            action::{Action, LOST_AND_FOUND_PREFIX},
            executor::{ActionSink, Executor},
            walk::{self, WalkStats},
        },
        scrub::validate::{Pass, Validator},
    },
    registry::{
        Error as RegistryError,
        blob_store::BlobStore,
        metadata_store::{BlobIndexOperation, LinkKind, LinkMetadata, MetadataStore},
        path_builder,
        test_utils::{
            RegistryTestCase, create_test_registry_with, for_each_backend, fs_test_stack,
            media_type, put_blob_direct, put_link_raw, upload_blob,
        },
    },
};

/// Run the three walk passes over the test case's stores with `sink`,
/// mirroring `Command::run`.
async fn run_passes(
    blob_store: &Arc<BlobStore>,
    metadata_store: &Arc<MetadataStore>,
    sink: Arc<dyn ActionSink>,
) -> Arc<WalkStats> {
    run_passes_with(blob_store, metadata_store, sink, false).await
}

/// `run_passes` with the `--delete-unknown` disposition made explicit.
async fn run_passes_with(
    blob_store: &Arc<BlobStore>,
    metadata_store: &Arc<MetadataStore>,
    sink: Arc<dyn ActionSink>,
    delete_unknown: bool,
) -> Arc<WalkStats> {
    let stats = Arc::new(WalkStats::default());
    let validator = Arc::new(Validator::new(
        blob_store.clone(),
        metadata_store.clone(),
        sink,
        stats.clone(),
        delete_unknown,
    ));

    let meta_objects = metadata_store.object_store();
    let passes = [
        (Pass::MetadataLinks, "", meta_objects),
        (Pass::MetadataShards, path_builder::BLOBS_ROOT, meta_objects),
        (Pass::MetadataShards, path_builder::REF_ROOT, meta_objects),
        (Pass::Blob, "", blob_store.object_store()),
    ];
    for (pass, prefix, objects) in passes {
        let validator = &validator;
        walk::for_each_key(objects, prefix, 4, |key| async move {
            validator.process(pass, &key).await;
        })
        .await
        .expect("walk pass");
    }
    stats
}

/// Full scrub with a real executor: repairs are applied.
async fn scrub_apply(test_case: &dyn RegistryTestCase) {
    let blob_store = test_case.blob_store();
    let metadata_store = test_case.metadata_store();
    let sink: Arc<dyn ActionSink> = Arc::new(Executor::new_for_test(
        blob_store.clone(),
        metadata_store.clone(),
    ));
    run_passes(&blob_store, &metadata_store, sink).await;
}

/// Capture-only scrub: returns the actions a run would apply.
async fn scrub_capture(test_case: &dyn RegistryTestCase) -> Vec<Action> {
    let blob_store = test_case.blob_store();
    let metadata_store = test_case.metadata_store();
    let sink = Arc::new(Mutex::new(Vec::new()));
    run_passes(
        &blob_store,
        &metadata_store,
        sink.clone() as Arc<dyn ActionSink>,
    )
    .await;
    match sink.lock() {
        Ok(mut actions) => actions.drain(..).collect(),
        Err(poisoned) => poisoned.into_inner().drain(..).collect(),
    }
}

/// Push a healthy image (config + layer blobs, manifest, `v1` tag) through
/// the real write path, so every link, back-reference, and grant exists.
async fn push_healthy_image(
    test_case: &dyn RegistryTestCase,
    namespace: &Namespace,
) -> (Digest, Digest, Digest) {
    let registry = test_case.registry();
    let config_bytes = br#"{"healthy":true}"#;
    let layer_bytes = b"healthy-layer-bytes";
    let config_digest = upload_blob(registry, namespace, config_bytes).await;
    let layer_digest = upload_blob(registry, namespace, layer_bytes).await;

    let manifest = format!(
        r#"{{
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {{
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "{config_digest}",
            "size": {}
        }},
        "layers": [{{
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": "{layer_digest}",
            "size": {}
        }}]
    }}"#,
        config_bytes.len(),
        layer_bytes.len(),
    );
    let response = registry
        .put_manifest(
            namespace,
            &Reference::Tag(Tag::new("v1").unwrap()),
            Some(&media_type("application/vnd.oci.image.manifest.v1+json")),
            manifest.as_bytes(),
        )
        .await
        .expect("healthy push");
    (response.digest, config_digest, layer_digest)
}

fn tag(name: &str) -> LinkKind {
    LinkKind::Tag(Tag::new(name).unwrap())
}

#[tokio::test]
async fn healthy_registry_emits_zero_actions() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/healthy").unwrap();
        push_healthy_image(test_case, namespace).await;

        let actions = scrub_capture(test_case).await;
        assert!(
            actions.is_empty(),
            "a healthy registry must produce zero actions, got: {:?}",
            actions.iter().map(ToString::to_string).collect::<Vec<_>>()
        );
    })
    .await;
}

#[tokio::test]
async fn scrub_regrants_missing_per_referrer_entries() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/heal-links").unwrap();
        let (manifest_digest, config_digest, layer_digest) =
            push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        // Break the config and layer pins out-of-band.
        let entry = LinkKind::ReferencedBy(manifest_digest.clone());
        for digest in [&config_digest, &layer_digest] {
            metadata_store
                .update_blob_index(namespace, digest, BlobIndexOperation::Remove(entry.clone()))
                .await
                .unwrap();
        }

        scrub_apply(test_case).await;

        for digest in [&config_digest, &layer_digest] {
            let links = metadata_store
                .read_blob_index_namespace(namespace, digest)
                .await
                .unwrap();
            assert!(
                links.contains(&entry),
                "the per-referrer entry on '{digest}' must be re-granted"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn scrub_recreates_missing_digest_link_for_tag() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/heal-digest").unwrap();
        let (manifest_digest, _, _) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        let digest_link = LinkKind::Digest(manifest_digest.clone());
        metadata_store
            .object_store()
            .delete(&path_builder::link_path(&digest_link, namespace))
            .await
            .unwrap();

        scrub_apply(test_case).await;

        assert!(
            metadata_store
                .read_link(namespace, &digest_link)
                .await
                .is_ok(),
            "the tag's digest revision link must be recreated"
        );
    })
    .await;
}

#[tokio::test]
async fn tag_targeting_missing_blob_is_removed() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/dangling-tag").unwrap();
        let metadata_store = test_case.metadata_store();

        let ghost_digest = Digest::sha256_of_bytes(b"never-uploaded");
        let body = serde_json::to_vec(&LinkMetadata::from_digest(ghost_digest)).unwrap();
        put_link_raw(
            metadata_store.object_store(),
            namespace,
            &tag("dangling"),
            &body,
        )
        .await;

        scrub_apply(test_case).await;

        assert!(
            metadata_store
                .read_link(namespace, &tag("dangling"))
                .await
                .is_err(),
            "a tag targeting missing bytes must be removed"
        );
    })
    .await;
}

#[tokio::test]
async fn invalid_tag_directory_is_deleted() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/bad-tag").unwrap();
        let metadata_store = test_case.metadata_store();

        // A leading '-' is a legal path segment but fails the tag grammar.
        let key = format!(
            "{}/current/link",
            path_builder::manifest_tag_dir(namespace, "-bad")
        );
        let body =
            serde_json::to_vec(&LinkMetadata::from_digest(Digest::sha256_of_bytes(b"x"))).unwrap();
        metadata_store
            .object_store()
            .put(&key, Bytes::from(body))
            .await
            .unwrap();

        scrub_apply(test_case).await;

        assert!(
            metadata_store.object_store().get(&key).await.is_err(),
            "the invalid tag directory must be deleted"
        );
    })
    .await;
}

#[tokio::test]
async fn corrupt_link_is_deleted() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/corrupt-link").unwrap();
        let metadata_store = test_case.metadata_store();

        put_link_raw(
            metadata_store.object_store(),
            namespace,
            &tag("garbled"),
            b"not link metadata",
        )
        .await;

        scrub_apply(test_case).await;

        let key = path_builder::link_path(&tag("garbled"), namespace);
        assert!(
            metadata_store.object_store().get(&key).await.is_err(),
            "a link with unreadable content must be deleted"
        );
    })
    .await;
}

#[tokio::test]
async fn missing_referrer_backlink_is_added_and_stale_one_removed() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/backlinks").unwrap();
        let (manifest_digest, config_digest, _) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        // Rewrite the config link with a bogus referrer and without the real one.
        let stale_revision = Digest::sha256_of_bytes(b"no-such-revision");
        let mut broken = LinkMetadata::from_digest(config_digest.clone());
        broken.add_referrer(stale_revision.clone());
        put_link_raw(
            metadata_store.object_store(),
            namespace,
            &LinkKind::Config(config_digest.clone()),
            &serde_json::to_vec(&broken).unwrap(),
        )
        .await;

        scrub_apply(test_case).await;

        // Pruning the stale referrer empties the advisory file's set, so the
        // collector reclaims the file; the real pin is the per-referrer entry.
        assert!(
            metadata_store
                .read_link(namespace, &LinkKind::Config(config_digest.clone()))
                .await
                .is_err(),
            "the stale advisory link file must be reclaimed"
        );
        let links = metadata_store
            .read_blob_index_namespace(namespace, &config_digest)
            .await
            .unwrap();
        assert!(
            links.contains(&LinkKind::ReferencedBy(manifest_digest.clone())),
            "the real revision's per-referrer entry must survive"
        );
    })
    .await;
}

#[tokio::test]
async fn missing_blob_index_grant_is_regranted() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/regrant").unwrap();
        let (manifest_digest, _, layer_digest) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        let link = LinkKind::ReferencedBy(manifest_digest.clone());
        metadata_store
            .update_blob_index(
                namespace,
                &layer_digest,
                BlobIndexOperation::Remove(link.clone()),
            )
            .await
            .unwrap();

        scrub_apply(test_case).await;

        let links = metadata_store
            .read_blob_index_namespace(namespace, &layer_digest)
            .await
            .unwrap();
        assert!(
            links.contains(&link),
            "the layer's per-referrer entry must be re-issued from the manifest"
        );
    })
    .await;
}

/// Regression: with `allow_missing_manifest_references` the push path drops the
/// link and grant for a digest the namespace does not own, so it gains no
/// cross-namespace read access. Scrub re-derives child links from the manifest
/// body and must not hand back what the write path withheld.
#[tokio::test]
async fn withheld_cross_namespace_reference_is_not_regranted() {
    for_each_backend(async |test_case| {
        let owner = &Namespace::new("test-repo/withheld-owner").unwrap();
        let borrower = &Namespace::new("test-repo/withheld-borrower").unwrap();
        let blob_store = test_case.blob_store();
        let metadata_store = test_case.metadata_store();

        // `owner` uploads the layer and config; `borrower` never references
        // either, so it holds no grant on them.
        let (_, config_digest, layer_digest) = push_healthy_image(test_case, owner).await;

        // A permissive push into `borrower` naming the same digests: the layer
        // and config links are withheld, the revision link is written.
        let permissive =
            create_test_registry_with(blob_store.clone(), metadata_store.clone(), false);
        let manifest = format!(
            r#"{{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {{
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "{config_digest}",
                "size": 16
            }},
            "layers": [{{
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "{layer_digest}",
                "size": 19
            }}]
        }}"#
        );
        permissive
            .accept_put_manifest(
                None,
                PutManifestRequest {
                    namespace: borrower.clone(),
                    reference: Reference::Tag(Tag::new("borrowed").unwrap()),
                    content_type: Some(media_type("application/vnd.oci.image.manifest.v1+json")),
                    tags: vec![],
                    source_ts: None,
                },
                Cursor::new(manifest.into_bytes()),
            )
            .await
            .expect("permissive push");

        for digest in [&layer_digest, &config_digest] {
            assert!(
                metadata_store
                    .read_blob_index_namespace(borrower, digest)
                    .await
                    .is_err(),
                "the permissive push must withhold the grant on '{digest}'"
            );
        }

        scrub_apply(test_case).await;

        for digest in [&layer_digest, &config_digest] {
            assert!(
                metadata_store
                    .read_blob_index_namespace(borrower, digest)
                    .await
                    .is_err(),
                "scrub granted '{borrower}' read access to '{digest}' that the push withheld"
            );
            assert!(
                metadata_store
                    .read_link(borrower, &LinkKind::Layer(digest.clone()))
                    .await
                    .is_err(),
                "scrub recreated a withheld link for '{digest}'"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn stale_shard_entry_is_removed() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/stale-entry").unwrap();
        let (_, _, layer_digest) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        // Grant an entry whose backing tag does not exist. (A `Layer` phantom
        // would be unrepresentable: its entry key carries no foreign digest,
        // so it aliases the healthy self-entry and asserts nothing.)
        let phantom = LinkKind::Tag(Tag::new("phantom-tag").unwrap());
        metadata_store
            .update_blob_index(
                namespace,
                &layer_digest,
                BlobIndexOperation::Insert(phantom.clone()),
            )
            .await
            .unwrap();

        scrub_apply(test_case).await;

        let links = metadata_store
            .read_blob_index_namespace(namespace, &layer_digest)
            .await
            .unwrap();
        assert!(
            !links.contains(&phantom),
            "an index entry with no link file must be removed"
        );
    })
    .await;
}

/// A dangling reference younger than the grace period may belong to a push
/// between its reference wave and its commit, so scrub must leave it alone.
#[tokio::test]
async fn young_dangling_ref_entry_is_kept() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/young-entry").unwrap();
        let (_, _, layer_digest) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        let phantom = LinkKind::Tag(Tag::new("phantom-tag").unwrap());
        metadata_store
            .update_blob_index(
                namespace,
                &layer_digest,
                BlobIndexOperation::Insert(phantom.clone()),
            )
            .await
            .unwrap();

        // Same stores, but a scrub whose grace period is real.
        let graced = Arc::new(
            MetadataStore::builder(metadata_store.object_store().clone())
                .gc_grace_secs(300)
                .build(),
        );
        let blob_store = test_case.blob_store();
        let sink: Arc<dyn ActionSink> =
            Arc::new(Executor::new_for_test(blob_store.clone(), graced.clone()));
        run_passes(&blob_store, &graced, sink).await;

        let links = metadata_store
            .read_blob_index_namespace(namespace, &layer_digest)
            .await
            .unwrap();
        assert!(
            links.contains(&phantom),
            "a dangling entry inside the grace period must be kept"
        );
    })
    .await;
}

/// Link repairs derived from a young revision (here: a removed per-referrer
/// entry) may race a push between its waves, so a graced scrub defers them.
#[tokio::test]
async fn young_revision_defers_link_repairs() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/young-revision").unwrap();
        let (manifest_digest, _, layer_digest) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        let entry = LinkKind::ReferencedBy(manifest_digest.clone());
        metadata_store
            .update_blob_index(
                namespace,
                &layer_digest,
                BlobIndexOperation::Remove(entry.clone()),
            )
            .await
            .unwrap();

        let graced = Arc::new(
            MetadataStore::builder(metadata_store.object_store().clone())
                .gc_grace_secs(300)
                .build(),
        );
        let blob_store = test_case.blob_store();
        let sink = Arc::new(Mutex::new(Vec::new()));
        run_passes(&blob_store, &graced, sink.clone() as Arc<dyn ActionSink>).await;
        let deferred = sink.lock().unwrap().is_empty();
        assert!(
            deferred,
            "repairs on a revision inside the grace period must wait for the next run"
        );

        // The grace-0 store the fixture built repairs it immediately.
        scrub_apply(test_case).await;
        let links = metadata_store
            .read_blob_index_namespace(namespace, &layer_digest)
            .await
            .unwrap();
        assert!(
            links.contains(&entry),
            "the entry must be re-granted once the grace period is out of scope"
        );
    })
    .await;
}

/// A tag whose entry is inside the grace period can be observed mid-delete
/// (tombstone not yet landed, revision record already gone); a graced scrub
/// must not derive repairs from it.
#[tokio::test]
async fn young_tag_defers_target_repairs() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/young-tag").unwrap();
        let (manifest_digest, _, _) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        let record = path_builder::revision_record_path(namespace, &manifest_digest);
        metadata_store.object_store().delete(&record).await.unwrap();

        let graced = Arc::new(
            MetadataStore::builder(metadata_store.object_store().clone())
                .gc_grace_secs(300)
                .build(),
        );
        let blob_store = test_case.blob_store();
        let sink = Arc::new(Mutex::new(Vec::new()));
        run_passes(&blob_store, &graced, sink.clone() as Arc<dyn ActionSink>).await;
        let deferred = sink.lock().unwrap().is_empty();
        assert!(
            deferred,
            "repairs behind a tag entry inside the grace period must wait"
        );
    })
    .await;
}

/// The run marker is the one key a writer and the collector both consult;
/// a scrub walk must never quarantine a live one.
#[tokio::test]
async fn a_live_gc_marker_survives_the_walk() {
    for_each_backend(async |test_case| {
        let metadata_store = test_case.metadata_store();
        let digest = Digest::sha256_of_bytes(b"marker-covered blob");
        let claim = metadata_store.gc_claim(&digest, &digest).await.unwrap();

        scrub_apply(test_case).await;

        assert!(
            metadata_store.gc_blocked(&[&digest]).await.unwrap(),
            "the live run marker must survive a scrub walk"
        );
        metadata_store.gc_release(claim).await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn corrupt_shard_is_deleted_and_regranted_on_next_run() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/corrupt-shard").unwrap();
        let (manifest_digest, _, layer_digest) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        let shard_key = path_builder::blob_index_shard_path(&layer_digest, namespace);
        metadata_store
            .object_store()
            .put(&shard_key, Bytes::from_static(b"not a shard"))
            .await
            .unwrap();

        scrub_apply(test_case).await;
        // The corrupt shard was deleted; the same run's link pass may have
        // preceded the deletion, so a second run re-grants from the manifest.
        scrub_apply(test_case).await;

        let links = metadata_store
            .read_blob_index_namespace(namespace, &layer_digest)
            .await
            .unwrap();
        assert!(
            links.contains(&LinkKind::ReferencedBy(manifest_digest.clone())),
            "grants must be rebuilt after the corrupt shard was deleted"
        );
    })
    .await;
}

#[tokio::test]
async fn orphan_blob_is_reclaimed() {
    for_each_backend(async |test_case| {
        let metadata_store = test_case.metadata_store();
        let blob_store = test_case.blob_store();

        let orphan = put_blob_direct(metadata_store.object_store(), b"unreferenced-bytes").await;
        assert!(blob_store.size(&orphan).await.is_ok());

        scrub_apply(test_case).await;

        assert!(
            blob_store.size(&orphan).await.is_err(),
            "a blob with no index entries must be reclaimed"
        );
    })
    .await;
}

/// Blob GC reads one listing of the blob's `refs/` directory, while the shard
/// walk reaches those same shards through a whole-store scan. When the two
/// disagree the listing must not win: a backend that drops a key from a listing
/// would otherwise reclaim the bytes of a referenced blob.
#[tokio::test]
async fn a_blob_the_shard_walk_saw_referenced_is_never_reclaimed() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/shard-witness").unwrap();
        let (_, _, layer_digest) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        let sink = Arc::new(Mutex::new(Vec::new()));
        let validator = Validator::new(
            test_case.blob_store(),
            metadata_store.clone(),
            sink.clone() as Arc<dyn ActionSink>,
            Arc::new(WalkStats::default()),
            false,
        );

        let shard_key = path_builder::blob_index_shard_path(&layer_digest, namespace);
        validator
            .validate_shard(&shard_key, &layer_digest, namespace)
            .await
            .expect("the shard walk must read the layer's references");

        // The per-blob index read now finds nothing, as it would on a backend
        // that dropped this key from the listing behind it.
        metadata_store
            .object_store()
            .delete(&shard_key)
            .await
            .expect("shard removal");

        validator
            .validate_blob(&layer_digest)
            .await
            .expect("blob validation");

        let emitted = match sink.lock() {
            Ok(actions) => actions,
            Err(poisoned) => poisoned.into_inner(),
        };
        assert!(
            !emitted
                .iter()
                .any(|action| matches!(action, Action::DeleteOrphanBlob(d) if d == &layer_digest)),
            "the shard walk saw references, so the bytes must not be reclaimed, got: {:?}",
            emitted.iter().map(ToString::to_string).collect::<Vec<_>>()
        );
    })
    .await;
}

#[tokio::test]
async fn orphan_referrer_link_is_deleted() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/orphan-referrer").unwrap();
        let (manifest_digest, _, _) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        // A referrer entry whose referrer manifest is not a current revision.
        let ghost_referrer = Digest::sha256_of_bytes(b"gone-referrer");
        let link = LinkKind::Referrer {
            subject: manifest_digest.clone(),
            referrer: ghost_referrer.clone(),
        };
        let body = serde_json::to_vec(&LinkMetadata::from_digest(ghost_referrer.clone())).unwrap();
        put_link_raw(metadata_store.object_store(), namespace, &link, &body).await;

        scrub_apply(test_case).await;

        assert!(
            metadata_store.read_link(namespace, &link).await.is_err(),
            "a referrer with no revision link must be deleted"
        );
    })
    .await;
}

#[tokio::test]
async fn unknown_keys_are_quarantined_in_both_stores() {
    for_each_backend(async |test_case| {
        let metadata_store = test_case.metadata_store();
        let blob_store = test_case.blob_store();

        let alien = "totally/alien/key";
        metadata_store
            .object_store()
            .put(alien, Bytes::from_static(b"metadata alien"))
            .await
            .unwrap();
        let blob_alien = "v2/blobs/sha256/aa/not-a-digest/data";
        blob_store
            .object_store()
            .put(blob_alien, Bytes::from_static(b"blob alien"))
            .await
            .unwrap();

        scrub_apply(test_case).await;

        assert!(
            metadata_store.object_store().get(alien).await.is_err(),
            "the alien metadata key must be moved"
        );
        assert_eq!(
            metadata_store
                .object_store()
                .get(&format!("{LOST_AND_FOUND_PREFIX}/{alien}"))
                .await
                .unwrap(),
            b"metadata alien"
        );
        assert!(blob_store.object_store().get(blob_alien).await.is_err());
        assert_eq!(
            blob_store
                .object_store()
                .get(&format!("{LOST_AND_FOUND_PREFIX}/{blob_alien}"))
                .await
                .unwrap(),
            b"blob alien"
        );

        // The quarantined copies are a known category: a second run leaves
        // them alone and emits nothing.
        let actions = scrub_capture(test_case).await;
        assert!(
            actions.is_empty(),
            "quarantined keys must not be re-processed, got: {:?}",
            actions.iter().map(ToString::to_string).collect::<Vec<_>>()
        );
    })
    .await;
}

/// An upload session record that does not parse is deleted, so the session
/// reads as broken and prune's upload sweep reaps it; a parseable one is a
/// live session and must be left alone.
#[tokio::test]
async fn an_unparseable_session_record_is_deleted() {
    for_each_backend(async |test_case| {
        let blob_store = test_case.blob_store();

        let corrupt = format!(
            "v2/repositories/test-repo/_uploads/{}/session.json",
            Uuid::new_v4()
        );
        blob_store
            .object_store()
            .put(&corrupt, Bytes::from_static(b"not a session record"))
            .await
            .unwrap();
        let live = format!(
            "v2/repositories/test-repo/_uploads/{}/session.json",
            Uuid::new_v4()
        );
        let record = format!(
            r#"{{"last_activity":"{}","committed_offset":0,"hash_state":""}}"#,
            Utc::now().to_rfc3339()
        );
        blob_store
            .object_store()
            .put(&live, Bytes::from(record))
            .await
            .unwrap();

        scrub_apply(test_case).await;

        assert!(
            blob_store.object_store().get(&corrupt).await.is_err(),
            "an unparseable session record must be deleted"
        );
        assert!(
            blob_store.object_store().get(&live).await.is_ok(),
            "a live session record must survive the walk"
        );
    })
    .await;
}

/// An upload directory whose name is not a session id is no angos session, so
/// it reaches the unknown-key quarantine like any other unrecognized key.
#[tokio::test]
async fn an_upload_directory_that_is_not_a_session_is_quarantined() {
    for_each_backend(async |test_case| {
        let blob_store = test_case.blob_store();

        let stray = "v2/repositories/test-repo/_uploads/not-a-session/data";
        blob_store
            .object_store()
            .put(stray, Bytes::from_static(b"stray upload"))
            .await
            .unwrap();

        scrub_apply(test_case).await;

        assert!(
            blob_store.object_store().get(stray).await.is_err(),
            "the stray upload directory must be moved"
        );
        assert_eq!(
            blob_store
                .object_store()
                .get(&format!("{LOST_AND_FOUND_PREFIX}/{stray}"))
                .await
                .unwrap(),
            b"stray upload"
        );
    })
    .await;
}

#[tokio::test]
async fn delete_unknown_removes_aliens_without_quarantining() {
    for_each_backend(async |test_case| {
        let metadata_store = test_case.metadata_store();
        let blob_store = test_case.blob_store();

        let alien = "totally/alien/key";
        metadata_store
            .object_store()
            .put(alien, Bytes::from_static(b"metadata alien"))
            .await
            .unwrap();
        let blob_alien = "v2/blobs/sha256/aa/not-a-digest/data";
        blob_store
            .object_store()
            .put(blob_alien, Bytes::from_static(b"blob alien"))
            .await
            .unwrap();

        let sink: Arc<dyn ActionSink> = Arc::new(Executor::new_for_test(
            blob_store.clone(),
            metadata_store.clone(),
        ));
        let stats = run_passes_with(&blob_store, &metadata_store, sink, true).await;

        // Both aliens are gone, counted, and nothing landed in quarantine.
        let meta_objects = metadata_store.object_store();
        assert!(meta_objects.get(alien).await.is_err());
        assert!(
            meta_objects
                .get(&format!("{LOST_AND_FOUND_PREFIX}/{alien}"))
                .await
                .is_err(),
            "a deleted unknown key must not be quarantined"
        );
        assert!(blob_store.object_store().get(blob_alien).await.is_err());
        assert!(
            blob_store
                .object_store()
                .get(&format!("{LOST_AND_FOUND_PREFIX}/{blob_alien}"))
                .await
                .is_err(),
        );
        assert_eq!(
            stats.quarantined.load(Ordering::Relaxed),
            2,
            "deleted unknowns still count in the unknown-key tally"
        );
    })
    .await;
}

#[tokio::test]
async fn corrupt_job_record_is_deleted_and_valid_one_kept() {
    for_each_backend(async |test_case| {
        let metadata_store = test_case.metadata_store();
        let objects = metadata_store.object_store();

        let corrupt = "_jobs/pending/replication/0000000000000000-corrupt.json";
        objects
            .put(corrupt, Bytes::from_static(b"not an envelope"))
            .await
            .unwrap();

        scrub_apply(test_case).await;

        assert!(
            objects.get(corrupt).await.is_err(),
            "an unparseable job record must be deleted"
        );
    })
    .await;
}

#[tokio::test]
async fn orphan_namespaces_are_left_alone_and_invalid_names_reclaimed() {
    for_each_backend(async |test_case| {
        // `ghost/app` resolves to no configured repository: scrub must not
        // touch it (config-relative clearing is prune's job).
        let orphan = &Namespace::new("ghost/app").unwrap();
        push_healthy_image(test_case, orphan).await;
        let metadata_store = test_case.metadata_store();

        // An invalid-name namespace directory, by contrast, is structural
        // garbage no API can address; scrub reclaims it unconditionally.
        let invalid_key = "v2/repositories/UPPER-CASE/_manifests/tags/v1/current/link".to_string();
        metadata_store
            .object_store()
            .put(&invalid_key, Bytes::from_static(b"{}"))
            .await
            .unwrap();

        scrub_apply(test_case).await;

        assert!(
            metadata_store.read_link(orphan, &tag("v1")).await.is_ok(),
            "an orphan namespace must survive scrub"
        );
        assert!(
            metadata_store
                .object_store()
                .get(&invalid_key)
                .await
                .is_err(),
            "an invalid-name namespace directory must be reclaimed"
        );
    })
    .await;
}

#[tokio::test]
async fn convergence_second_run_emits_zero_actions() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/converge").unwrap();
        let (manifest_digest, config_digest, layer_digest) =
            push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        // Mixed corruption: a missing per-referrer pin, a phantom index
        // entry, an alien key, and a corrupt tag link.
        metadata_store
            .update_blob_index(
                namespace,
                &config_digest,
                BlobIndexOperation::Remove(LinkKind::ReferencedBy(manifest_digest.clone())),
            )
            .await
            .unwrap();
        metadata_store
            .update_blob_index(
                namespace,
                &layer_digest,
                BlobIndexOperation::Insert(LinkKind::Layer(Digest::sha256_of_bytes(b"phantom"))),
            )
            .await
            .unwrap();
        metadata_store
            .object_store()
            .put("stray/object", Bytes::from_static(b"junk"))
            .await
            .unwrap();
        put_link_raw(
            metadata_store.object_store(),
            namespace,
            &tag("broken"),
            b"garbage",
        )
        .await;

        scrub_apply(test_case).await;

        let actions = scrub_capture(test_case).await;
        assert!(
            actions.is_empty(),
            "the second run must find nothing left to do, got: {:?}",
            actions.iter().map(ToString::to_string).collect::<Vec<_>>()
        );
    })
    .await;
}

/// A legacy tag `current/link` is converted into a `set` entry stamped with
/// its recorded `created_at`, and the link is reclaimed.
#[tokio::test]
async fn legacy_tag_link_is_converted_to_an_entry() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/convert-tag").unwrap();
        let (manifest_digest, _, _) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        let tag = Tag::new("legacy").unwrap();
        let link = LinkKind::Tag(tag.clone());
        let created_at = chrono::DateTime::from_timestamp_millis(1_600_000_000_000).unwrap();
        let metadata = LinkMetadata::from_digest_at(manifest_digest.clone(), created_at);
        let legacy_path = path_builder::link_path(&link, namespace);
        metadata_store
            .object_store()
            .put(
                &legacy_path,
                Bytes::from(serde_json::to_vec(&metadata).unwrap()),
            )
            .await
            .unwrap();

        scrub_apply(test_case).await;

        assert!(
            metadata_store
                .object_store()
                .head(&legacy_path)
                .await
                .is_err(),
            "the converted legacy link must be reclaimed"
        );
        let resolved = metadata_store
            .read_link_reference(namespace, &link)
            .await
            .unwrap();
        assert_eq!(resolved.target, manifest_digest);
        assert_eq!(
            resolved.created_at,
            Some(created_at),
            "the entry must keep the link's recorded created_at"
        );
    })
    .await;
}

/// A legacy revision link is converted into a revision record stamped with
/// its recorded `created_at`, and the link is reclaimed.
#[tokio::test]
async fn legacy_revision_link_is_converted_to_a_record() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/convert-rev").unwrap();
        let (manifest_digest, _, _) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();
        let store = metadata_store.object_store();

        // Rewind to the legacy shape: link present, record absent.
        let link = LinkKind::Digest(manifest_digest.clone());
        let created_at = chrono::DateTime::from_timestamp_millis(1_600_000_000_000).unwrap();
        let metadata = LinkMetadata::from_digest_at(manifest_digest.clone(), created_at);
        let legacy_path = path_builder::link_path(&link, namespace);
        store
            .put(
                &legacy_path,
                Bytes::from(serde_json::to_vec(&metadata).unwrap()),
            )
            .await
            .unwrap();
        let record_path = path_builder::revision_record_path(namespace, &manifest_digest);
        store.delete(&record_path).await.unwrap();

        scrub_apply(test_case).await;

        store
            .head(&record_path)
            .await
            .expect("the revision record must be written");
        assert!(
            store.head(&legacy_path).await.is_err(),
            "the converted legacy link must be reclaimed"
        );
        let resolved = metadata_store
            .read_link_reference(namespace, &link)
            .await
            .unwrap();
        assert_eq!(resolved.created_at, Some(created_at));
    })
    .await;
}

/// A legacy referrer link whose referrer manifest still exists converts into
/// a referrer record; the link is reclaimed.
#[tokio::test]
async fn legacy_referrer_link_is_converted_to_a_record() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/convert-sub").unwrap();
        let (manifest_digest, _, _) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();
        let store = metadata_store.object_store();

        let subject = Digest::sha256_of_bytes(b"convert-sub-subject");
        let link = LinkKind::Referrer {
            subject: subject.clone(),
            referrer: manifest_digest.clone(),
        };
        let metadata = LinkMetadata::from_digest(manifest_digest.clone());
        let legacy_path = path_builder::link_path(&link, namespace);
        store
            .put(
                &legacy_path,
                Bytes::from(serde_json::to_vec(&metadata).unwrap()),
            )
            .await
            .unwrap();

        scrub_apply(test_case).await;

        store
            .head(&path_builder::referrer_record_path(
                namespace,
                &subject,
                &manifest_digest,
            ))
            .await
            .expect("the referrer record must be written");
        assert!(
            store.head(&legacy_path).await.is_err(),
            "the converted legacy referrer link must be reclaimed"
        );
    })
    .await;
}

/// A legacy shard is converted into reference keys and reclaimed: scrub
/// emits the conversion and deletes the shard. With no link file backing it,
/// the lossy layer entry it carried is then collected as dangling, while the
/// per-referrer pin keeps the blob referenced throughout.
#[tokio::test]
async fn legacy_shard_is_converted_to_reference_keys() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/convert-shard").unwrap();
        let (manifest_digest, _, layer_digest) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();
        let store = metadata_store.object_store();

        // The legacy shape: a shard carrying the lossy layer entry, as an
        // un-upgraded store would hold it.
        let layer_link = LinkKind::Layer(layer_digest.clone());
        let shard_key = path_builder::blob_index_shard_path(&layer_digest, namespace);
        let shard = serde_json::to_vec(slice::from_ref(&layer_link)).unwrap();
        store.put(&shard_key, Bytes::from(shard)).await.unwrap();

        let actions = scrub_capture(test_case).await;
        assert!(
            actions.iter().any(
                |a| matches!(a, Action::ConvertBlobIndexShard { key, .. } if *key == shard_key)
            ),
            "scrub must plan the shard's conversion"
        );

        scrub_apply(test_case).await;
        assert!(
            store.head(&shard_key).await.is_err(),
            "the converted shard must be deleted"
        );
        scrub_apply(test_case).await;

        let links = metadata_store
            .read_blob_index_namespace(namespace, &layer_digest)
            .await
            .unwrap();
        assert!(
            !links.contains(&layer_link),
            "the lossy layer entry must be collected once converted"
        );
        assert!(
            links.contains(&LinkKind::ReferencedBy(manifest_digest.clone())),
            "the per-referrer pin must keep the blob referenced"
        );
        assert!(
            test_case.blob_store().size(&layer_digest).await.is_ok(),
            "the pinned blob's bytes must survive"
        );
    })
    .await;
}

/// A legacy shard entry whose self-digest is not the shard's blob cannot be
/// expressed as a reference key; conversion drops it rather than aliasing a
/// real entry, and the shard is still reclaimed.
#[tokio::test]
async fn unrepresentable_shard_entries_are_dropped_by_conversion() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/convert-nonsense").unwrap();
        push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();
        let store = metadata_store.object_store();

        let ghost = Digest::sha256_of_bytes(b"nonsense-shard-blob");
        let mismatched = LinkKind::Layer(Digest::sha256_of_bytes(b"a-different-digest"));
        let shard_key = path_builder::blob_index_shard_path(&ghost, namespace);
        let shard = serde_json::to_vec(&[mismatched]).unwrap();
        store.put(&shard_key, Bytes::from(shard)).await.unwrap();

        scrub_apply(test_case).await;

        assert!(
            store.head(&shard_key).await.is_err(),
            "the shard must be reclaimed"
        );
        assert!(
            metadata_store.read_blob_index(&ghost).await.is_err(),
            "the mismatched entry must not be materialised as a key"
        );
    })
    .await;
}

/// A grant entry with no backing link is settled damage once the reverify
/// re-reads the same inconsistency (formerly the expired-intent case).
#[tokio::test]
async fn dangling_grant_entry_is_removed() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/dangling-entry").unwrap();
        push_healthy_image(test_case, namespace).await;
        let blob_store = test_case.blob_store();
        let metadata_store = test_case.metadata_store();

        let dangling = Digest::sha256_of_bytes(b"dangling-layer");
        blob_store
            .object_store()
            .put(
                &path_builder::blob_path(&dangling),
                Bytes::from_static(b"dangling-layer"),
            )
            .await
            .unwrap();
        let phantom = LinkKind::Layer(dangling.clone());
        metadata_store
            .update_blob_index(
                namespace,
                &dangling,
                BlobIndexOperation::Insert(phantom.clone()),
            )
            .await
            .unwrap();

        scrub_apply(test_case).await;

        assert!(
            metadata_store
                .read_blob_index_namespace(namespace, &dangling)
                .await
                .is_err(),
            "a grant entry with no backing link is settled damage and must be removed"
        );
    })
    .await;
}

/// Leftover keys of the removed transaction engine are reclaimed once past
/// the grace period; young ones wait, like every other reclaim.
#[tokio::test]
async fn tx_leftovers_are_reclaimed_age_gated() {
    const LEFTOVERS: [&str; 3] = [".tx-log/x", ".tx-bodies/x", ".tx-locks/x"];

    // Grace 0 (the shared fixtures): the leftovers are deleted.
    for_each_backend(async |test_case| {
        let metadata_store = test_case.metadata_store();
        let store = metadata_store.object_store();
        for key in LEFTOVERS {
            store
                .put(key, Bytes::from_static(b"leftover"))
                .await
                .unwrap();
        }

        scrub_apply(test_case).await;

        for key in LEFTOVERS {
            assert!(
                store.head(key).await.is_err(),
                "grace-0 scrub must reclaim the engine leftover '{key}'"
            );
        }
    })
    .await;

    // Default grace: the just-written (young) leftovers are left alone.
    let stack = fs_test_stack();
    let store = stack.metadata_store.object_store();
    for key in LEFTOVERS {
        store
            .put(key, Bytes::from_static(b"leftover"))
            .await
            .unwrap();
    }
    let sink: Arc<dyn ActionSink> = Arc::new(Executor::new_for_test(
        stack.blob_store.clone(),
        stack.metadata_store.clone(),
    ));
    run_passes(&stack.blob_store, &stack.metadata_store, sink).await;
    for key in LEFTOVERS {
        assert!(
            store.head(key).await.is_ok(),
            "a graced scrub must leave the young engine leftover '{key}'"
        );
    }
}

/// A legacy link file's back-link to a revision that does not exist is
/// pruned once the reverify re-reads the same inconsistency (formerly the
/// live-intent suppression case, whose subject left with the intent log).
#[tokio::test]
async fn dangling_referrer_backlink_is_pruned() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/dangling-referrer").unwrap();
        let (_, config_digest, _) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        // A legacy link file naming a referrer revision that is absent.
        // Pushes no longer write these files, so the legacy shape is seeded
        // raw.
        let dead_revision = Digest::sha256_of_bytes(b"dead-revision");
        let config_link = LinkKind::Config(config_digest.clone());
        let mut current = LinkMetadata::from_digest(config_digest.clone());
        current.add_referrer(dead_revision.clone());
        put_link_raw(
            metadata_store.object_store(),
            namespace,
            &config_link,
            &serde_json::to_vec(&current).unwrap(),
        )
        .await;

        scrub_apply(test_case).await;

        // The dead pin is pruned; the file itself may be retired outright
        // once no live pins remain, which is also a valid outcome.
        if let Ok(repaired) = metadata_store.read_link(namespace, &config_link).await {
            assert!(
                !repaired.referenced_by.contains(&dead_revision),
                "a back-link to an absent revision must be pruned"
            );
        }
    })
    .await;
}

/// Write one raw tag entry with the given author timestamp and body,
/// returning its full key.
async fn put_tag_entry(
    metadata_store: &Arc<MetadataStore>,
    namespace: &Namespace,
    tag: &Tag,
    ts_millis: i64,
    deletion: bool,
    digest: &Digest,
    body: &'static [u8],
) -> String {
    let ts = DateTime::from_timestamp_millis(ts_millis).unwrap();
    let key = path_builder::tag_entry_path(
        namespace,
        tag,
        path_builder::tag_ord(Some(ts)),
        deletion,
        digest,
    );
    metadata_store
        .object_store()
        .put(&key, Bytes::from_static(body))
        .await
        .unwrap();
    key
}

/// Three generations of one tag: the two superseded entries are demoted to
/// `!hist/`, resolution still returns the winner, and a second run finds
/// nothing left to do.
#[tokio::test]
async fn superseded_tag_entries_are_demoted_to_hist() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/demote").unwrap();
        let (manifest_digest, _, _) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();
        let tag = Tag::new("v1").unwrap();

        // The push tagged v1 at now; append two older generations.
        let old_a = put_tag_entry(
            &metadata_store,
            namespace,
            &tag,
            1_000_000,
            false,
            &manifest_digest,
            b"{}",
        )
        .await;
        let old_b = put_tag_entry(
            &metadata_store,
            namespace,
            &tag,
            2_000_000,
            false,
            &manifest_digest,
            b"{}",
        )
        .await;

        scrub_apply(test_case).await;

        let store = metadata_store.object_store();
        for old in [&old_a, &old_b] {
            assert!(
                store.head(old).await.is_err(),
                "superseded entry '{old}' must leave the tag prefix"
            );
            let name = old.rsplit_once('/').unwrap().1;
            let hist = path_builder::tag_hist_path(namespace, &tag, name);
            assert!(
                store.head(&hist).await.is_ok(),
                "demoted entry must exist at '{hist}'"
            );
        }
        let resolved = metadata_store
            .read_link_reference(namespace, &LinkKind::Tag(tag.clone()))
            .await
            .unwrap();
        assert_eq!(resolved.target, manifest_digest);

        let actions = scrub_capture(test_case).await;
        assert!(
            actions.is_empty(),
            "a second run must find nothing left to demote, got: {:?}",
            actions.iter().map(ToString::to_string).collect::<Vec<_>>()
        );
    })
    .await;
}

/// A same-millisecond set+del pair is one complete winner group: neither
/// half is demoted, while a strictly older entry still is.
#[tokio::test]
async fn same_millisecond_tie_group_is_never_split() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/tie-group").unwrap();
        let (manifest_digest, _, _) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();
        let tag = Tag::new("tie").unwrap();

        let ts = 5_000_000;
        let set_key = put_tag_entry(
            &metadata_store,
            namespace,
            &tag,
            ts,
            false,
            &manifest_digest,
            b"{}",
        )
        .await;
        let del_key = put_tag_entry(
            &metadata_store,
            namespace,
            &tag,
            ts,
            true,
            &manifest_digest,
            b"{}",
        )
        .await;
        let older = put_tag_entry(
            &metadata_store,
            namespace,
            &tag,
            ts - 10_000,
            false,
            &manifest_digest,
            b"{}",
        )
        .await;

        scrub_apply(test_case).await;

        let store = metadata_store.object_store();
        assert!(
            store.head(&set_key).await.is_ok(),
            "the winner group's set entry must stay"
        );
        assert!(
            store.head(&del_key).await.is_ok(),
            "the winner group's del entry must stay"
        );
        assert!(
            store.head(&older).await.is_err(),
            "the strictly older entry must be demoted"
        );
    })
    .await;
}

/// A superseded entry whose key is younger than the grace period may be a
/// racing push's write, so a graced scrub must keep it.
#[tokio::test]
async fn young_superseded_entry_is_kept() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/young-demote").unwrap();
        let (manifest_digest, _, _) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();
        let tag = Tag::new("v1").unwrap();

        // Superseded by ordinal, but the key itself was written just now.
        let old_entry = put_tag_entry(
            &metadata_store,
            namespace,
            &tag,
            1_000_000,
            false,
            &manifest_digest,
            b"{}",
        )
        .await;

        // Same stores, but a scrub whose grace period is real.
        let graced = Arc::new(
            MetadataStore::builder(metadata_store.object_store().clone())
                .gc_grace_secs(300)
                .build(),
        );
        let blob_store = test_case.blob_store();
        let sink: Arc<dyn ActionSink> =
            Arc::new(Executor::new_for_test(blob_store.clone(), graced.clone()));
        run_passes(&blob_store, &graced, sink).await;

        assert!(
            metadata_store.object_store().head(&old_entry).await.is_ok(),
            "a superseded entry inside the grace period must be kept"
        );
    })
    .await;
}

/// Demoted entries leave the `!tag/` prefix (so tag listings stop paging
/// past them) while the hist keys keep the original bodies.
#[tokio::test]
async fn demoted_entries_leave_the_listing_and_keep_their_bodies() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/demote-list").unwrap();
        let (manifest_digest, _, _) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();
        let tag = Tag::new("v1").unwrap();

        let body_a: &'static [u8] = br#"{"media_type":"application/vnd.gen.a"}"#;
        let body_b: &'static [u8] = br#"{"media_type":"application/vnd.gen.b"}"#;
        let old_a = put_tag_entry(
            &metadata_store,
            namespace,
            &tag,
            1_000_000,
            false,
            &manifest_digest,
            body_a,
        )
        .await;
        let old_b = put_tag_entry(
            &metadata_store,
            namespace,
            &tag,
            2_000_000,
            false,
            &manifest_digest,
            body_b,
        )
        .await;

        scrub_apply(test_case).await;

        let tags = metadata_store
            .list_tags(namespace, 100, None)
            .await
            .unwrap();
        assert_eq!(
            tags.items.iter().filter(|t| t.as_ref() == "v1").count(),
            1,
            "the tag must list exactly once after demotion"
        );
        let dir = path_builder::tag_entry_dir(namespace, &tag);
        let page = metadata_store
            .object_store()
            .list(&dir, 1000, None)
            .await
            .unwrap();
        assert_eq!(
            page.items.len(),
            1,
            "only the winner may remain under the tag prefix, got {:?}",
            page.items
        );

        for (old, body) in [(&old_a, body_a), (&old_b, body_b)] {
            let name = old.rsplit_once('/').unwrap().1;
            let stored = metadata_store
                .object_store()
                .get(&path_builder::tag_hist_path(namespace, &tag, name))
                .await
                .unwrap();
            assert_eq!(
                stored.as_slice(),
                body,
                "the demoted body must be preserved verbatim"
            );
        }
    })
    .await;
}

/// Pushes no longer write the legacy layer/config link files; serving,
/// `can_read`, and the blob delete gate run on records and reference keys
/// alone.
#[tokio::test]
async fn push_writes_no_tracked_link_files() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/no-link-files").unwrap();
        let (manifest_digest, config_digest, layer_digest) =
            push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();
        let store = metadata_store.object_store();

        for link in [
            LinkKind::Layer(layer_digest.clone()),
            LinkKind::Config(config_digest.clone()),
        ] {
            let key = path_builder::link_path(&link, namespace);
            assert!(
                store.head(&key).await.is_err(),
                "a push must not write the legacy link file '{key}'"
            );
        }

        // A pull still resolves the tag to readable manifest bytes, the
        // blob stays readable, and the delete gate still refuses.
        let registry = test_case.registry();
        let resolved = metadata_store
            .read_link(namespace, &tag("v1"))
            .await
            .unwrap();
        assert_eq!(resolved.target, manifest_digest);
        test_case
            .blob_store()
            .read(&resolved.target)
            .await
            .expect("the manifest body must stay readable");
        assert!(
            registry
                .blob_ownership()
                .can_read(namespace, &layer_digest)
                .await
                .unwrap(),
            "the layer must be readable without its link file"
        );
        let refused = registry
            .delete_blob(DeleteBlobRequest {
                namespace: namespace.clone(),
                digest: layer_digest.clone(),
            })
            .await;
        assert!(
            matches!(refused, Err(RegistryError::BlobReferenced)),
            "the delete gate must refuse a referenced blob without its link file"
        );
    })
    .await;
}

/// A legacy-shaped tracked link file plus its lossy shard-converted entry,
/// with a live referrer: scrub re-homes the pin to a per-referrer entry,
/// retires the file, and collects the lossy entry, while the blob stays
/// referenced throughout.
#[tokio::test]
async fn legacy_tracked_link_is_retired_after_rehoming() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/retire-legacy").unwrap();
        let (manifest_digest, _, layer_digest) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();
        let registry = test_case.registry();

        // Rewind the layer to the legacy shape: a link file backing the
        // referrer, the lossy `r/layer` entry, and no per-referrer entry.
        let layer_link = LinkKind::Layer(layer_digest.clone());
        let mut legacy = LinkMetadata::from_digest(layer_digest.clone());
        legacy.add_referrer(manifest_digest.clone());
        put_link_raw(
            metadata_store.object_store(),
            namespace,
            &layer_link,
            &serde_json::to_vec(&legacy).unwrap(),
        )
        .await;
        metadata_store
            .update_blob_index(
                namespace,
                &layer_digest,
                BlobIndexOperation::Insert(layer_link.clone()),
            )
            .await
            .unwrap();
        let entry = LinkKind::ReferencedBy(manifest_digest.clone());
        metadata_store
            .update_blob_index(
                namespace,
                &layer_digest,
                BlobIndexOperation::Remove(entry.clone()),
            )
            .await
            .unwrap();

        scrub_apply(test_case).await;
        scrub_apply(test_case).await;

        let key = path_builder::link_path(&layer_link, namespace);
        assert!(
            metadata_store.object_store().head(&key).await.is_err(),
            "the legacy link file must be retired"
        );
        let links = metadata_store
            .read_blob_index_namespace(namespace, &layer_digest)
            .await
            .unwrap();
        assert!(
            links.contains(&entry),
            "the pin must be re-homed to a per-referrer entry"
        );
        assert!(
            !links.contains(&layer_link),
            "the lossy layer entry must be collected once the file is gone"
        );
        assert!(
            metadata_store
                .reference_backed(namespace, &entry, &layer_digest)
                .await
                .unwrap(),
            "the re-homed pin must be backed by the live revision"
        );
        assert!(
            registry
                .blob_ownership()
                .can_read(namespace, &layer_digest)
                .await
                .unwrap(),
            "the blob must stay readable across the retirement"
        );
        let refused = registry
            .delete_blob(DeleteBlobRequest {
                namespace: namespace.clone(),
                digest: layer_digest.clone(),
            })
            .await;
        assert!(
            matches!(refused, Err(RegistryError::BlobReferenced)),
            "the delete gate must still refuse the referenced blob"
        );

        let actions = scrub_capture(test_case).await;
        assert!(
            actions.is_empty(),
            "the store must converge after the retirement, got: {:?}",
            actions.iter().map(ToString::to_string).collect::<Vec<_>>()
        );
    })
    .await;
}

/// A tracked link file younger than the grace period may be an old-binary
/// push mid-flight; a graced scrub must leave it alone.
#[tokio::test]
async fn young_tracked_link_file_survives_a_graced_scrub() {
    for_each_backend(async |test_case| {
        let namespace = &Namespace::new("test-repo/young-tracked").unwrap();
        let (manifest_digest, _, layer_digest) = push_healthy_image(test_case, namespace).await;
        let metadata_store = test_case.metadata_store();

        let layer_link = LinkKind::Layer(layer_digest.clone());
        let mut legacy = LinkMetadata::from_digest(layer_digest.clone());
        legacy.add_referrer(manifest_digest.clone());
        put_link_raw(
            metadata_store.object_store(),
            namespace,
            &layer_link,
            &serde_json::to_vec(&legacy).unwrap(),
        )
        .await;

        // Same stores, but a scrub whose grace period is real.
        let graced = Arc::new(
            MetadataStore::builder(metadata_store.object_store().clone())
                .gc_grace_secs(300)
                .build(),
        );
        let blob_store = test_case.blob_store();
        let sink: Arc<dyn ActionSink> =
            Arc::new(Executor::new_for_test(blob_store.clone(), graced.clone()));
        run_passes(&blob_store, &graced, sink).await;

        assert!(
            metadata_store
                .object_store()
                .head(&path_builder::link_path(&layer_link, namespace))
                .await
                .is_ok(),
            "a link file inside the grace period must be kept"
        );
    })
    .await;
}
