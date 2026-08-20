use bytes::Bytes;

use angos_oci::{Digest, MediaType, Namespace, Reference, Tag, UploadSessionId};

use crate::command::maintenance::action::Action;
use crate::command::maintenance::executor::{ActionSink, Executor};
use crate::registry::keys::{DigestKeys, NamespaceKeys};
use crate::registry::{
    Error,
    blob_ownership::{GrantOutcome, promote_and_grant},
    metadata_store::{BlobIndexOperation, LinkKind},
    test_utils::{FSRegistryTestCase, RegistryTestCase, upload_blob},
};

async fn seed_blob(case: &FSRegistryTestCase, content: &[u8]) -> Digest {
    let digest = Digest::sha256_of_bytes(content);
    case.blob_store()
        .object_store()
        .put(&digest.blob_path(), Bytes::copy_from_slice(content))
        .await
        .unwrap();
    digest
}

/// An ownership key pins a blob unconditionally; only once it is revoked
/// does the collector delete the bytes and the stale reference keys.
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

/// An unexpired run covering a digest blocks writers, and releasing it
/// unblocks them.
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

/// A guarded grant against still-present bytes fails closed under a covering
/// run rather than handing out bytes the collector may be deleting.
#[tokio::test]
async fn a_guarded_grant_fails_closed_while_a_run_covers_present_bytes() {
    let case = FSRegistryTestCase::new();
    let store = case.metadata_store();
    let namespace = Namespace::new("gc-blocked-grant").unwrap();
    let digest = seed_blob(&case, b"gc-blocked-grant-bytes").await;

    let claim = store.gc_claim(&digest, &digest).await.unwrap();
    let outcome = case
        .registry()
        .blob_ownership()
        .grant_existing(&case.blob_store(), &namespace, &digest)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        GrantOutcome::ReclaimBlocked,
        "present bytes under a covering run must report the reclaim"
    );

    let result = promote_and_grant(
        &case.blob_store(),
        store.as_ref(),
        &namespace,
        &UploadSessionId::generate(),
        &digest,
        22,
    )
    .await;
    assert!(
        matches!(result, Err(Error::ReclamationInProgress(_))),
        "promotion over a covering run must fail closed with a retryable conflict, got {result:?}"
    );
    store.gc_release(claim).await.unwrap();
}

/// A grant racing a sweep re-probes the blob after the collector check, so
/// it never hands out a reference to reclaimed bytes.
#[tokio::test]
async fn a_guarded_grant_never_returns_a_reclaimed_blob() {
    let case = FSRegistryTestCase::new();
    let registry = case.registry();
    let namespace = Namespace::new("gc-mount").unwrap();
    let digest = seed_blob(&case, b"gc-mount-bytes").await;

    // The sweep wins the race.
    case.blob_store().delete_blob(&digest).await.unwrap();
    let outcome = registry
        .blob_ownership()
        .grant_existing(&case.blob_store(), &namespace, &digest)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        GrantOutcome::BytesAbsent,
        "a reclaimed blob must never be granted"
    );
}

/// A crash between waves leaves only legal states, emulated by rewinding a
/// completed push one wave at a time.
#[tokio::test]
async fn a_push_interrupted_between_waves_reads_consistently() {
    let case = FSRegistryTestCase::new();
    let registry = case.registry();
    let store = case.metadata_store();
    let namespace = Namespace::new("test-repo/torn-push").unwrap();

    let config_digest = upload_blob(registry, &namespace, br#"{"torn":true}"#).await;
    let media_type = MediaType::new("application/vnd.oci.image.manifest.v1+json").unwrap();
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
            &Reference::Tag(Tag::new("latest").unwrap()),
            Some(&media_type),
            &content,
        )
        .await
        .unwrap()
        .digest;

    // Rewind wave D.
    store
        .object_store()
        .delete_prefix(&namespace.tag_entry_dir(&Tag::new("latest").unwrap()))
        .await
        .unwrap();
    assert!(
        store
            .read_link_reference(&namespace, &LinkKind::Tag(Tag::new("latest").unwrap()))
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

    // Rewind wave C.
    store
        .object_store()
        .delete(&namespace.revision_record_path(&digest))
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

/// The writer half of the marker protocol through the public push path: a
/// push referencing a covered blob fails with the reclamation conflict, and a
/// retry after the run's release succeeds.
#[tokio::test]
async fn a_manifest_push_fails_closed_while_a_run_covers_its_blob() {
    let case = FSRegistryTestCase::new();
    let registry = case.registry();
    let store = case.metadata_store();
    let namespace = Namespace::new("gc-writer-push").unwrap();

    let config_digest = upload_blob(registry, &namespace, br#"{"gc":true}"#).await;
    let media_type = MediaType::new("application/vnd.oci.image.manifest.v1+json").unwrap();
    let content = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": media_type,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest.to_string(),
            "size": 11
        },
        "layers": []
    }))
    .unwrap();
    let reference = Reference::Tag(Tag::new("latest").unwrap());

    let claim = store
        .gc_claim(&config_digest, &config_digest)
        .await
        .unwrap();
    let error = registry
        .put_manifest(&namespace, &reference, Some(&media_type), &content)
        .await
        .err();
    assert!(
        matches!(error, Some(Error::ReclamationInProgress(_))),
        "a push referencing a covered blob must fail closed with the reclamation conflict, got {error:?}"
    );

    store.gc_release(claim).await.unwrap();
    registry
        .put_manifest(&namespace, &reference, Some(&media_type), &content)
        .await
        .expect("a retry after the run's release must succeed");
}
