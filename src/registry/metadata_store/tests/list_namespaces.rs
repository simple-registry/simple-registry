use bytes::Bytes;

use angos_oci::{Namespace, Tag, UploadSessionId};

use crate::registry::keys::NamespaceKeys;
use crate::registry::{
    metadata_store::{LinkKind, LinkOperation},
    test_utils::{self, FSRegistryTestCase, RegistryTestCase, for_each_backend, put_link_raw},
};

/// A namespace lists exactly while it holds at least one revision or tag, and
/// disappears once all are deleted with no scrub or rebuild in between.
#[tokio::test]
async fn list_namespaces_is_derived_from_content() {
    for_each_backend(async |test_case| {
        let registry = test_case.registry();
        let metadata_store = test_case.metadata_store();
        let namespace = &Namespace::new("derived-catalog/repo").unwrap();

        let (digest, _) = test_utils::create_test_blob(registry, namespace, b"content").await;

        let listed = metadata_store
            .list_namespaces(1000, None)
            .await
            .unwrap()
            .items;
        assert!(
            listed.contains(namespace),
            "a namespace with content must appear in the catalog; got: {listed:?}"
        );

        metadata_store
            .update_links(
                namespace,
                &[
                    LinkOperation::delete(LinkKind::Tag(Tag::new("latest").unwrap())),
                    LinkOperation::delete(LinkKind::Layer(digest.clone())),
                ],
            )
            .await
            .unwrap();

        let listed = metadata_store
            .list_namespaces(1000, None)
            .await
            .unwrap()
            .items;
        assert!(
            !listed.contains(namespace),
            "a namespace whose revisions and tags were all deleted must \
             disappear from the catalog; got: {listed:?}"
        );
    })
    .await;
}

/// A namespace holding only an in-progress upload is not a catalog entry.
#[tokio::test]
async fn list_namespaces_excludes_upload_only_namespace() {
    for_each_backend(async |test_case| {
        let metadata_store = test_case.metadata_store();
        let namespace = Namespace::new("upload-only/repo").unwrap();
        let session_id = UploadSessionId::generate();

        let upload_data_path = namespace.upload_path(&session_id);
        metadata_store
            .object_store()
            .put(&upload_data_path, Bytes::from_static(b"partial"))
            .await
            .unwrap();

        let listed = metadata_store
            .list_namespaces(1000, None)
            .await
            .unwrap()
            .items;
        assert!(
            !listed.contains(&namespace),
            "a namespace with only an _uploads artifact must not appear in the \
             catalog; got: {listed:?}"
        );
    })
    .await;
}

/// `collect_upload_namespaces` keys off `_uploads` and `list_namespaces` off
/// `_manifests`, so each surfaces what the other omits.
#[tokio::test]
async fn collect_upload_namespaces_keys_off_uploads_not_manifests() {
    for_each_backend(async |test_case| {
        let registry = test_case.registry();
        let metadata_store = test_case.metadata_store();
        let blob_store = test_case.blob_store();

        let manifest_only = &Namespace::new("upload-marker/manifest-only").unwrap();
        let upload_only = &Namespace::new("upload-marker/upload-only").unwrap();
        let mixed = &Namespace::new("upload-marker/mixed").unwrap();

        test_utils::create_test_blob(registry, manifest_only, b"manifest-only").await;

        blob_store
            .create_upload(upload_only, &UploadSessionId::generate(), None)
            .await
            .unwrap();

        test_utils::create_test_blob(registry, mixed, b"mixed").await;
        blob_store
            .create_upload(mixed, &UploadSessionId::generate(), None)
            .await
            .unwrap();

        let upload_listed = blob_store.collect_upload_namespaces(None).await.unwrap();
        assert!(
            upload_listed.contains(upload_only),
            "an upload-only namespace must appear in collect_upload_namespaces; got: {upload_listed:?}"
        );
        assert!(
            upload_listed.contains(mixed),
            "a namespace with an upload must appear in collect_upload_namespaces; got: {upload_listed:?}"
        );
        assert!(
            !upload_listed.contains(manifest_only),
            "a manifest-only namespace must not appear in collect_upload_namespaces; got: {upload_listed:?}"
        );

        let manifest_listed = metadata_store.list_namespaces(1000, None).await.unwrap().items;
        assert!(
            manifest_listed.contains(manifest_only),
            "a manifest-only namespace must appear in the catalog; got: {manifest_listed:?}"
        );
        assert!(
            manifest_listed.contains(mixed),
            "a namespace with content must appear in the catalog; got: {manifest_listed:?}"
        );
        assert!(
            !manifest_listed.contains(upload_only),
            "an upload-only namespace must not appear in the catalog; got: {manifest_listed:?}"
        );

    })
    .await;
}

/// The catalog is served from the `v2/cat/` index alone, so a namespace
/// existing only as a raw legacy tree does not list until the backfill writes
/// its index key: the documented migration contract.
#[tokio::test]
async fn legacy_only_namespace_lists_after_index_backfill() {
    for_each_backend(async |test_case| {
        let metadata_store = test_case.metadata_store();
        let namespace = Namespace::new("legacy-only/repo").unwrap();

        // A raw legacy tag link, bypassing the write path that indexes.
        let digest = angos_oci::Digest::sha256_of_bytes(b"legacy-only-content");
        let link = LinkKind::Tag(Tag::new("v1").unwrap());
        put_link_raw(
            metadata_store.object_store(),
            &namespace,
            &link,
            digest.to_string().as_bytes(),
        )
        .await;

        let listed = metadata_store
            .list_namespaces(1000, None)
            .await
            .unwrap()
            .items;
        assert!(
            !listed.contains(&namespace),
            "a legacy-only namespace must not list before the index backfill; got: {listed:?}"
        );

        metadata_store.ensure_catalog_index(&namespace).await;

        let listed = metadata_store
            .list_namespaces(1000, None)
            .await
            .unwrap()
            .items;
        assert!(
            listed.contains(&namespace),
            "a legacy-only namespace must list once its index key is backfilled; got: {listed:?}"
        );
    })
    .await;
}

/// On FS the catalog index key's `!` terminator keeps `a`'s leaf beside
/// `a/b`'s directory, so nested repositories coexist.
#[tokio::test]
async fn nested_namespaces_coexist_in_the_catalog_on_fs() {
    let case = FSRegistryTestCase::new();
    let store = case.metadata_store();
    for (i, name) in ["cat-nest", "cat-nest/b"].iter().enumerate() {
        let namespace = Namespace::new(name).unwrap();
        let digest = angos_oci::Digest::sha256_of_bytes(format!("nested-{i}").as_bytes());
        store
            .update_links(
                &namespace,
                &[LinkOperation::create(
                    LinkKind::Digest(digest.clone()),
                    digest,
                )],
            )
            .await
            .unwrap();
        store
            .object_store()
            .head(&namespace.catalog_index_path())
            .await
            .expect("the catalog index key must exist beside the nested directory");
    }

    let listed = store.list_namespaces(10, None).await.unwrap().items;
    let names: Vec<&str> = listed.iter().map(AsRef::as_ref).collect();
    assert_eq!(names, ["cat-nest", "cat-nest/b"]);
}

/// Catalog pages come off the index's ordered listing in lexical order
/// (`-` < `.` < `/`), paginated by `n` plus `last`.
#[tokio::test]
async fn catalog_pages_serve_lexical_order_from_the_index() {
    let case = FSRegistryTestCase::new();
    let store = case.metadata_store();
    // Seeded out of lexical order on purpose.
    for (i, name) in ["cat-z", "cat-p/b", "cat-p", "cat-p-b", "cat-p.c"]
        .iter()
        .enumerate()
    {
        let namespace = Namespace::new(name).unwrap();
        let digest = angos_oci::Digest::sha256_of_bytes(format!("lexical-{i}").as_bytes());
        store
            .update_links(
                &namespace,
                &[LinkOperation::create(
                    LinkKind::Digest(digest.clone()),
                    digest,
                )],
            )
            .await
            .unwrap();
    }

    let page = store.list_namespaces(2, None).await.unwrap();
    let names: Vec<&str> = page.items.iter().map(AsRef::as_ref).collect();
    assert_eq!(names, ["cat-p", "cat-p-b"]);
    assert!(page.next_token.is_some(), "more pages must be signalled");

    let page = store
        .list_namespaces(2, Some("cat-p-b".to_string()))
        .await
        .unwrap();
    let names: Vec<&str> = page.items.iter().map(AsRef::as_ref).collect();
    assert_eq!(names, ["cat-p.c", "cat-p/b"]);

    let page = store
        .list_namespaces(2, Some("cat-p/b".to_string()))
        .await
        .unwrap();
    let names: Vec<&str> = page.items.iter().map(AsRef::as_ref).collect();
    assert_eq!(names, ["cat-z"]);
    assert!(page.next_token.is_none(), "the last page ends the chain");
}
