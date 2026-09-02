use std::str::FromStr;

use bytes::Bytes;
use chrono::{DateTime, Duration as ChronoDuration, Utc};

use angos_oci::{Digest, Namespace, Tag};

use crate::registry::keys::NamespaceKeys;
use crate::registry::metadata_store::tests::{test_backend, test_config};
use crate::registry::metadata_store::{AccessEntry, LinkKind, LinkOperation, MetadataStore};
use crate::registry::metadata_store::{
    access_time::{atime_client_suffix, atime_entry_name},
    tag_ord,
};

async fn stored_atime(
    backend: &MetadataStore,
    namespace: &Namespace,
    link: &LinkKind,
) -> Option<DateTime<Utc>> {
    let LinkKind::Tag(tag) = link else {
        panic!("stored_atime expects a tag link");
    };
    backend.read_tag_access_time(namespace, tag).await.unwrap()
}

/// Plant one access entry at `at` as a raw put, the way a sibling replica's
/// stamp would land.
async fn put_entry_at(backend: &MetadataStore, dir: &str, client: &str, at: DateTime<Utc>) {
    let name = atime_entry_name(tag_ord(Some(at)), &atime_client_suffix(client));
    let body = serde_json::to_vec(&AccessEntry {
        client: client.to_string(),
        at,
    })
    .unwrap();
    backend
        .object_store()
        .put(&format!("{dir}/{name}"), Bytes::from(body))
        .await
        .unwrap();
}

async fn create_tag(backend: &MetadataStore, namespace: &Namespace, tag: &LinkKind, hash: &str) {
    let ops = vec![LinkOperation::Create {
        link: tag.clone(),
        target: Digest::from_str(hash).unwrap(),
        referrer: None,
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(namespace, &ops).await.unwrap();
}

/// The entry body carries the acting client, and the newest entry wins the
/// read over a backdated one.
#[tokio::test]
async fn a_pull_stamps_an_entry_carrying_the_client_and_newest_wins() {
    let config = test_config();
    let backend = test_backend(&config);
    let namespace = Namespace::new("audit-entry-ns").unwrap();
    let tag_name = Tag::new("v1").unwrap();
    let tag = LinkKind::Tag(tag_name.clone());
    create_tag(
        &backend,
        &namespace,
        &tag,
        "sha256:ad01a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
    )
    .await;

    let meta = backend
        .read_link_recording_access(&namespace, &tag, "alice")
        .await
        .unwrap();
    assert!(
        meta.accessed_at.is_some(),
        "the returned metadata carries the fresh stamp"
    );

    let dir = namespace.tag_atime_entry_dir(&tag_name);
    let page = backend.object_store().list(&dir, 10, None).await.unwrap();
    assert_eq!(page.items.len(), 1, "one pull appends one entry");
    let raw = backend
        .object_store()
        .get(&format!("{dir}/{}", page.items[0]))
        .await
        .unwrap();
    let entry: AccessEntry = serde_json::from_slice(&raw).unwrap();
    assert_eq!(entry.client, "alice", "the body must carry the actor");

    put_entry_at(&backend, &dir, "bob", Utc::now() - ChronoDuration::hours(3)).await;
    let read = backend
        .read_tag_access_time(&namespace, &tag_name)
        .await
        .unwrap()
        .unwrap();
    assert!(
        Utc::now().signed_duration_since(read) < ChronoDuration::minutes(5),
        "the newest entry must win the read, not the backdated one"
    );
}

/// Distinct clients stamping the same millisecond coexist through the entry
/// name's suffix.
#[tokio::test]
async fn each_pull_appends_one_entry_per_client() {
    let config = test_config();
    let backend = test_backend(&config);
    let namespace = Namespace::new("audit-per-pull-ns").unwrap();
    let tag_name = Tag::new("v1").unwrap();
    let tag = LinkKind::Tag(tag_name.clone());
    create_tag(
        &backend,
        &namespace,
        &tag,
        "sha256:ad02b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
    )
    .await;

    for client in ["alice", "bob"] {
        backend
            .read_link_recording_access(&namespace, &tag, client)
            .await
            .unwrap();
    }

    let dir = namespace.tag_atime_entry_dir(&tag_name);
    let page = backend.object_store().list(&dir, 10, None).await.unwrap();
    assert_eq!(page.items.len(), 2, "each client's pull is its own entry");
}

/// Concurrent stamps are appends, so they never contend.
#[tokio::test]
async fn concurrent_stamps_never_contend() {
    let config = test_config();
    let backend = test_backend(&config);
    let namespace = Namespace::new("audit-stamp-race").unwrap();
    let digest =
        Digest::from_str("sha256:ad04b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1")
            .unwrap();
    let tag = LinkKind::Tag(Tag::new("v1").unwrap());
    create_tag(
        &backend,
        &namespace,
        &tag,
        "sha256:ad04b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
    )
    .await;

    let mut handles = Vec::new();
    for _ in 0..10 {
        let backend = backend.clone();
        let namespace = namespace.clone();
        let tag = tag.clone();
        handles.push(tokio::spawn(async move {
            backend
                .read_link_recording_access(&namespace, &tag, "racer")
                .await
        }));
    }
    for handle in handles {
        let meta = handle.await.unwrap().unwrap();
        assert_eq!(meta.target, digest);
    }

    let raw = stored_atime(&backend, &namespace, &tag).await;
    assert!(raw.is_some(), "the racing stamps must have landed");
}
