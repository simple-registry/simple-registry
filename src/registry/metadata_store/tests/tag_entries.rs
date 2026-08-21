use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use tempfile::TempDir;

use angos_oci::{Digest, MediaType, Namespace, Tag};
use angos_storage::{ObjectStore, fs::Backend as StorageFsBackend};

use crate::registry::keys::NamespaceKeys;
use crate::registry::metadata_store::tag_ord;
use crate::registry::metadata_store::tests::test_config;
use crate::registry::{
    Error,
    metadata_store::{
        LinkKind, LinkMetadata, LinkOperation, MetadataStore, ReferencePolicy,
        link::tag::TagEntryBody,
    },
    path_builder,
    test_utils::metadata_store_over_cached,
};

fn entry_ms(ts: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(ts.timestamp_millis()).unwrap()
}

/// Two processes pushing the same tag write disjoint entry keys, so neither
/// write is lost and both resolve the same winner (equal timestamps
/// tie-break on the higher digest).
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
        .object_store()
        .list(
            &namespace.tag_entry_dir(&Tag::new("latest").unwrap()),
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
    let backend = config.to_backend(None).unwrap();
    let namespace = Namespace::new("legacy-tag-fallback").unwrap();
    let tag = Tag::new("v1").unwrap();
    let link = LinkKind::Tag(tag.clone());
    let target = Digest::sha256_of_bytes(b"legacy-manifest");

    let legacy_path = path_builder::link_path(&link, &namespace).unwrap();
    let metadata = LinkMetadata::from_digest_at(target.clone(), entry_ms(Utc::now()));
    backend
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
        .object_store()
        .head(&legacy_path)
        .await
        .expect("writers never touch the legacy link; scrub reclaims it");
    let tags = backend.list_tags(&namespace, 10, None).await.unwrap().items;
    assert!(!tags.contains(&tag), "a tombstoned tag must not list");
}

/// Under a nonzero grace the conversion writes the entry but leaves a young
/// legacy link for a later run, so an old-binary writer rewriting that link
/// mid-upgrade loses nothing.
#[tokio::test]
async fn a_young_legacy_tag_link_survives_conversion_under_grace() {
    let dir = TempDir::new().unwrap();
    let backend: Arc<dyn ObjectStore> = Arc::new(
        StorageFsBackend::builder(dir.path())
            .sync_to_disk(false)
            .build(),
    );
    let store = MetadataStore::builder(backend)
        .link_cache_ttl(0)
        .gc_grace_secs(300)
        .build();
    let namespace = Namespace::new("legacy-tag-convert-grace").unwrap();
    let tag = Tag::new("v1").unwrap();
    let link = LinkKind::Tag(tag.clone());
    let target = Digest::sha256_of_bytes(b"legacy-manifest-under-grace");

    let legacy_path = path_builder::link_path(&link, &namespace).unwrap();
    let metadata = LinkMetadata::from_digest_at(target.clone(), entry_ms(Utc::now()));
    store
        .object_store()
        .put(
            &legacy_path,
            Bytes::from(serde_json::to_vec(&metadata).unwrap()),
        )
        .await
        .unwrap();

    store
        .convert_legacy_tag_link(&namespace, &tag)
        .await
        .unwrap();

    let resolved = store.read_link_reference(&namespace, &link).await.unwrap();
    assert_eq!(resolved.target, target, "the converted entry must resolve");
    store
        .object_store()
        .head(&legacy_path)
        .await
        .expect("a link younger than the grace period must survive the conversion's delete");
}

fn fs_store(dir: &TempDir) -> Arc<MetadataStore> {
    let backend: Arc<dyn ObjectStore> = Arc::new(
        StorageFsBackend::builder(dir.path())
            .sync_to_disk(false)
            .build(),
    );
    metadata_store_over_cached(backend, 0)
}

/// A tag delete's tombstone copies the superseded winner's descriptor fields
/// (media type, size, filtered annotations), which tag history serves later.
#[tokio::test]
async fn a_tombstone_copies_the_prior_winners_descriptor_fields() {
    let dir = TempDir::new().unwrap();
    let store = fs_store(&dir);
    let namespace = Namespace::new("tombstone-descriptor").unwrap();
    let tag = Tag::new("v1").unwrap();
    let link = LinkKind::Tag(tag.clone());
    let target = Digest::sha256_of_bytes(b"descriptor-manifest");
    let media_type = MediaType::new("application/vnd.oci.image.manifest.v1+json").unwrap();
    let annotations = BTreeMap::from([
        (
            "org.opencontainers.distribution.internal".to_string(),
            "reserved".to_string(),
        ),
        ("com.example.team".to_string(), "kept".to_string()),
    ]);

    store
        .store_manifest(
            &namespace,
            &[LinkOperation::create_with_media_type(
                link.clone(),
                target.clone(),
                Some(media_type.clone()),
                Some(42),
                Some(annotations),
            )],
            None,
            ReferencePolicy::Trusted,
        )
        .await
        .unwrap();
    store
        .delete_links(&namespace, &[LinkOperation::delete(link.clone())], None)
        .await
        .unwrap();

    let entry_dir = namespace.tag_entry_dir(&tag);
    let entries = store
        .object_store()
        .list(&entry_dir, 10, None)
        .await
        .unwrap();
    let tombstone = entries
        .items
        .iter()
        .find(|name| name.contains(".del."))
        .expect("the delete must append a tombstone entry");
    let body = store
        .object_store()
        .get(&format!("{entry_dir}/{tombstone}"))
        .await
        .unwrap();
    let parsed: TagEntryBody = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.media_type, Some(media_type));
    assert_eq!(parsed.size, Some(42));
    assert_eq!(
        parsed.annotations,
        Some(BTreeMap::from([(
            "com.example.team".to_string(),
            "kept".to_string()
        )])),
        "the tombstone carries the prior entry's filtered annotations"
    );
}

/// An entry body carrying only `media_type` parses with the other descriptor
/// fields absent, and the tag still resolves.
#[tokio::test]
async fn an_old_shape_entry_body_still_resolves() {
    let dir = TempDir::new().unwrap();
    let store = fs_store(&dir);
    let namespace = Namespace::new("old-shape-entry").unwrap();
    let tag = Tag::new("v1").unwrap();
    let link = LinkKind::Tag(tag.clone());
    let target = Digest::sha256_of_bytes(b"old-shape-manifest");
    let ts = entry_ms(Utc::now());

    let key = namespace.tag_entry_path(&tag, tag_ord(Some(ts)), false, &target);
    store
        .object_store()
        .put(
            &key,
            Bytes::from_static(br#"{"media_type":"application/vnd.oci.image.manifest.v1+json"}"#),
        )
        .await
        .unwrap();

    let resolved = store.read_link_reference(&namespace, &link).await.unwrap();
    assert_eq!(resolved.target, target);
    assert_eq!(resolved.created_at, Some(ts));

    let body = store
        .read_tag_winner_body(&namespace, &tag, &resolved)
        .await
        .unwrap();
    assert_eq!(
        body.media_type,
        Some(MediaType::new("application/vnd.oci.image.manifest.v1+json").unwrap())
    );
    assert_eq!(body.size, None);
    assert_eq!(body.annotations, None);
}
