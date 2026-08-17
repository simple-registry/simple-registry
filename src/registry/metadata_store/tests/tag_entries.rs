use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use tempfile::TempDir;

use angos_oci::{Digest, Namespace, Tag};
use angos_storage::{ObjectStore, fs::Backend as StorageFsBackend};

use crate::registry::metadata_store::tests::test_config;
use crate::registry::{
    Error,
    metadata_store::{LinkKind, LinkMetadata, LinkOperation, ReferencePolicy},
    path_builder,
    test_utils::metadata_store_over_cached,
};

fn entry_ms(ts: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(ts.timestamp_millis()).unwrap()
}

/// Two processes pushing the same tag concurrently write disjoint entry keys:
/// neither write is lost, and both resolve to the same deterministic winner
/// (equal timestamps tie-break on the higher digest).
#[tokio::test]
async fn concurrent_same_tag_pushes_from_two_processes_lose_nothing() {
    let dir = TempDir::new().unwrap();
    let store_for = || {
        let backend: Arc<dyn ObjectStore> = Arc::new(
            StorageFsBackend::builder(dir.path())
                .sync_to_disk(false)
                .build(),
        );
        metadata_store_over_cached(backend, 0)
    };
    let a = store_for();
    let b = store_for();
    let namespace = Namespace::new("two-writers").unwrap();
    let link = LinkKind::Tag(Tag::new("latest").unwrap());
    let ts = entry_ms(Utc::now());
    let digest_a = Digest::sha256_of_bytes(b"writer-a");
    let digest_b = Digest::sha256_of_bytes(b"writer-b");

    let ops_a = [LinkOperation::create(link.clone(), digest_a.clone())];
    let ops_b = [LinkOperation::create(link.clone(), digest_b.clone())];
    let (ra, rb) = tokio::join!(
        a.store_manifest(&namespace, &ops_a, Some(ts), ReferencePolicy::Trusted),
        b.store_manifest(&namespace, &ops_b, Some(ts), ReferencePolicy::Trusted),
    );
    ra.unwrap();
    rb.unwrap();

    let entries = a
        .store()
        .object_store()
        .list(
            &path_builder::tag_entry_dir(&namespace, &Tag::new("latest").unwrap()),
            10,
            None,
        )
        .await
        .unwrap();
    assert_eq!(entries.items.len(), 2, "neither concurrent write is lost");

    let winner = std::cmp::max(digest_a.clone(), digest_b.clone());
    for store in [&a, &b] {
        let resolved = store.read_link_reference(&namespace, &link).await.unwrap();
        assert_eq!(
            resolved.target, winner,
            "both processes must resolve the same deterministic winner"
        );
    }
}

/// A tag with no entries answers from its legacy `current/link`; a tombstone
/// entry then shadows the legacy link without touching it.
#[tokio::test]
async fn legacy_link_answers_until_a_tombstone_shadows_it() {
    let config = test_config();
    let backend = config.to_backend(false, None).unwrap();
    let namespace = Namespace::new("legacy-tag-fallback").unwrap();
    let tag = Tag::new("v1").unwrap();
    let link = LinkKind::Tag(tag.clone());
    let target = Digest::sha256_of_bytes(b"legacy-manifest");

    let legacy_path = path_builder::link_path(&link, &namespace);
    let metadata = LinkMetadata::from_digest_at(target.clone(), entry_ms(Utc::now()));
    backend
        .store()
        .object_store()
        .put(
            &legacy_path,
            Bytes::from(serde_json::to_vec(&metadata).unwrap()),
        )
        .await
        .unwrap();

    let resolved = backend
        .read_link_reference(&namespace, &link)
        .await
        .unwrap();
    assert_eq!(resolved.target, target, "the legacy link must answer");
    let tags = backend.list_tags(&namespace, 10, None).await.unwrap().items;
    assert!(tags.contains(&tag), "the legacy tag must list");

    backend
        .delete_links(&namespace, &[LinkOperation::delete(link.clone())], None)
        .await
        .unwrap();

    let result = backend.read_link_reference(&namespace, &link).await;
    assert!(
        matches!(result, Err(Error::NotFound)),
        "the tombstone must shadow the legacy link, got: {result:?}"
    );
    backend
        .store()
        .object_store()
        .head(&legacy_path)
        .await
        .expect("writers never touch the legacy link; scrub reclaims it");
    let tags = backend.list_tags(&namespace, 10, None).await.unwrap().items;
    assert!(!tags.contains(&tag), "a tombstoned tag must not list");
}
