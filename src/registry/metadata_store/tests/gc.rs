use bytes::Bytes;

use angos_oci::{Digest, Namespace};

use crate::command::maintenance::action::Action;
use crate::command::maintenance::executor::{ActionSink, Executor};
use crate::registry::{
    metadata_store::{BlobIndexOperation, LinkKind},
    path_builder,
    test_utils::{FSRegistryTestCase, RegistryTestCase},
};

async fn seed_blob(case: &FSRegistryTestCase, content: &[u8]) -> Digest {
    let digest = Digest::sha256_of_bytes(content);
    case.blob_store()
        .object_store()
        .put(
            &path_builder::blob_path(&digest),
            Bytes::copy_from_slice(content),
        )
        .await
        .unwrap();
    digest
}

/// The collector never reclaims a referenced blob: an ownership key pins it
/// unconditionally, and only once every reference is gone does the marker
/// protocol delete the bytes and the stale keys.
#[tokio::test]
async fn collector_never_reclaims_a_referenced_blob() {
    let case = FSRegistryTestCase::new();
    let store = case.metadata_store();
    let namespace = Namespace::new("gc-referenced").unwrap();
    let digest = seed_blob(&case, b"gc-referenced-bytes").await;
    store
        .update_blob_index(
            &namespace,
            &digest,
            BlobIndexOperation::Insert(LinkKind::Blob(digest.clone())),
        )
        .await
        .unwrap();

    let executor = Executor::new_for_test(case.blob_store(), store.clone());
    executor
        .apply(Action::DeleteOrphanBlob(digest.clone()))
        .await
        .unwrap();
    assert!(
        case.blob_store().read(&digest).await.is_ok(),
        "an owned blob must never be reclaimed"
    );

    store
        .revoke_blob_ownership(&namespace, &digest)
        .await
        .unwrap();
    executor
        .apply(Action::DeleteOrphanBlob(digest.clone()))
        .await
        .unwrap();
    assert!(
        case.blob_store().read(&digest).await.is_err(),
        "an unreferenced blob past the grace must be reclaimed"
    );
    assert!(
        store.read_blob_index(&digest).await.is_err(),
        "the reclaimed blob's reference keys must be swept"
    );
}

/// A writer that has just written its reference keys backs off while an
/// unexpired collector run covers one of its blobs: the push errors instead
/// of committing over a possible reclaim, and both sides aborting is safe.
#[tokio::test]
async fn a_push_backs_off_while_a_collector_run_covers_its_blob() {
    let case = FSRegistryTestCase::new();
    let store = case.metadata_store();
    let digest = seed_blob(&case, b"gc-covered-bytes").await;

    let claim = store.gc_claim(&digest, &digest).await.unwrap();
    assert!(
        store.gc_blocked(&[&digest]).await.unwrap(),
        "an unexpired run covering the digest must block a writer"
    );

    store.gc_release(claim).await.unwrap();
    assert!(
        !store.gc_blocked(&[&digest]).await.unwrap(),
        "a released run must unblock writers"
    );
}

/// A mount (or any grant against pre-existing bytes) racing a sweep never
/// hands out a reference to reclaimed bytes: the guarded grant re-probes the
/// blob after the collector check and reports the blob gone.
#[tokio::test]
async fn a_guarded_grant_never_returns_a_reclaimed_blob() {
    let case = FSRegistryTestCase::new();
    let registry = case.registry();
    let store = case.metadata_store();
    let namespace = Namespace::new("gc-mount").unwrap();
    let digest = seed_blob(&case, b"gc-mount-bytes").await;

    // The sweep wins the race: the bytes are gone by the time the grant
    // re-probes them.
    case.blob_store().delete_blob(&digest).await.unwrap();
    let granted = registry
        .blob_ownership()
        .grant_existing(&case.blob_store(), &namespace, &digest)
        .await
        .unwrap();
    assert!(!granted, "a reclaimed blob must never be granted");

    // A crash between waves leaves partial state; every prefix of the wave
    // order reads consistently. Wave A only: reference keys with no revision.
    let torn = Namespace::new("gc-torn").unwrap();
    let orphan = seed_blob(&case, b"gc-torn-bytes").await;
    store
        .update_blob_index(
            &torn,
            &orphan,
            BlobIndexOperation::Insert(LinkKind::Blob(orphan.clone())),
        )
        .await
        .unwrap();
    assert!(
        store
            .read_link_reference(&torn, &LinkKind::Digest(orphan.clone()))
            .await
            .is_err(),
        "reference keys alone must not make a manifest resolvable"
    );
}

/// A crash between waves leaves only legal states: after wave C a revision
/// with no tag (the push-by-digest state), after wave A nothing resolvable.
/// Emulated by rewinding a completed push one wave at a time.
#[tokio::test]
async fn a_push_interrupted_between_waves_reads_consistently() {
    let case = FSRegistryTestCase::new();
    let registry = case.registry();
    let store = case.metadata_store();
    let namespace = Namespace::new("test-repo/torn-push").unwrap();

    let config_digest =
        crate::registry::test_utils::upload_blob(registry, &namespace, br#"{"torn":true}"#).await;
    let media_type =
        angos_oci::MediaType::new("application/vnd.oci.image.manifest.v1+json").unwrap();
    let content = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": media_type,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest.to_string(),
            "size": 13
        },
        "layers": []
    }))
    .unwrap();
    let digest = registry
        .put_manifest(
            &namespace,
            &angos_oci::Reference::Tag(angos_oci::Tag::new("latest").unwrap()),
            Some(&media_type),
            &content,
        )
        .await
        .unwrap()
        .digest;

    // Rewind wave D: the tag entry is gone, the revision stays resolvable.
    store
        .store()
        .object_store()
        .delete_prefix(&path_builder::tag_entry_dir(
            &namespace,
            &angos_oci::Tag::new("latest").unwrap(),
        ))
        .await
        .unwrap();
    assert!(
        store
            .read_link_reference(
                &namespace,
                &LinkKind::Tag(angos_oci::Tag::new("latest").unwrap())
            )
            .await
            .is_err(),
        "without its wave-D entry the tag must read as absent"
    );
    assert!(
        store
            .read_link_reference(&namespace, &LinkKind::Digest(digest.clone()))
            .await
            .is_ok(),
        "the wave-C revision must stay resolvable: the legal push-by-digest state"
    );

    // Rewind wave C: nothing resolves, only over-approximated references
    // remain for the collector.
    store
        .store()
        .object_store()
        .delete(&path_builder::revision_record_path(&namespace, &digest))
        .await
        .unwrap();
    assert!(
        store
            .read_link_reference(&namespace, &LinkKind::Digest(digest))
            .await
            .is_err(),
        "without its record the revision must read as absent"
    );
}
