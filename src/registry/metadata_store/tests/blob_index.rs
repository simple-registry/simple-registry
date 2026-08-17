use std::str::FromStr;

use bytes::Bytes;

use angos_oci::{Digest, Namespace, Tag};
use angos_tx_engine::lock::{LockStrategy, S3LockConfig};

use crate::registry::metadata_store::tests::test_config;
use crate::registry::{
    Error,
    metadata_store::{BlobIndexOperation, LinkKind, LinkOperation, blob_index::shard::read_shard},
    path_builder,
    test_utils::fs_test_stack,
};

#[tokio::test]
async fn test_blob_index_updates_multiple_digests() {
    let config = test_config();
    let backend = config.to_backend(false, None).unwrap();
    let namespace = Namespace::new("blob-index-multi-digest-test").unwrap();

    let digests: Vec<Digest> = (0..5)
        .map(|i| {
            Digest::from_str(&format!(
                "sha256:a{i}a0000000000000000000000000000000000000000000000000000000000000"
            ))
            .unwrap()
        })
        .collect();

    let ops: Vec<LinkOperation> = digests
        .iter()
        .enumerate()
        .map(|(i, digest)| LinkOperation::Create {
            link: LinkKind::Tag(Tag::try_from(format!("tag-bim-{i}")).unwrap()),
            target: digest.clone(),
            referrer: None,
            media_type: None,
            descriptor: None,
        })
        .collect();

    backend.update_links(&namespace, &ops).await.unwrap();

    for (i, digest) in digests.iter().enumerate() {
        let blob_index = backend.read_blob_index(digest).await.unwrap();
        let ns_links = blob_index.namespace.get(&namespace).unwrap();
        let expected_link = LinkKind::Tag(Tag::try_from(format!("tag-bim-{i}")).unwrap());
        assert!(
            ns_links.contains(&expected_link),
            "Blob index for digest {digest} should contain {expected_link}"
        );
    }
}

#[tokio::test]
async fn test_tracked_link_creates_with_referrers() {
    let config = test_config();
    let backend = config.to_backend(false, None).unwrap();
    let namespace = Namespace::new("tracked-creates-referrer-test").unwrap();

    let referrer_digest =
        Digest::from_str("sha256:aa00000000000000000000000000000000000000000000000000000000000001")
            .unwrap();

    let layer_digests: Vec<Digest> = (0..3)
        .map(|i| {
            Digest::from_str(&format!(
                "sha256:b{i}b0000000000000000000000000000000000000000000000000000000000000"
            ))
            .unwrap()
        })
        .collect();

    let config_digest =
        Digest::from_str("sha256:bb00000000000000000000000000000000000000000000000000000000000001")
            .unwrap();

    let mut ops: Vec<LinkOperation> = layer_digests
        .iter()
        .map(|d| LinkOperation::Create {
            link: LinkKind::Layer(d.clone()),
            target: d.clone(),
            referrer: Some(referrer_digest.clone()),
            media_type: None,
            descriptor: None,
        })
        .collect();

    ops.push(LinkOperation::Create {
        link: LinkKind::Config(config_digest.clone()),
        target: config_digest.clone(),
        referrer: Some(referrer_digest.clone()),
        media_type: None,
        descriptor: None,
    });

    backend.update_links(&namespace, &ops).await.unwrap();

    for layer_digest in &layer_digests {
        let link = LinkKind::Layer(layer_digest.clone());
        let meta = backend
            .read_link_reference(&namespace, &link)
            .await
            .unwrap();
        assert_eq!(meta.target, *layer_digest);
        assert!(
            meta.referenced_by.contains(&referrer_digest),
            "Layer link {link} should have referrer {referrer_digest}"
        );
    }

    let config_link = LinkKind::Config(config_digest.clone());
    let meta = backend
        .read_link_reference(&namespace, &config_link)
        .await
        .unwrap();
    assert_eq!(meta.target, config_digest);
    assert!(
        meta.referenced_by.contains(&referrer_digest),
        "Config link should have referrer {referrer_digest}"
    );
}

#[tokio::test]
async fn test_tracked_link_deletes_with_referrers() {
    let config = test_config();
    let backend = config.to_backend(false, None).unwrap();
    let namespace = Namespace::new("tracked-deletes-referrer-test").unwrap();

    let referrer_digest =
        Digest::from_str("sha256:cc00000000000000000000000000000000000000000000000000000000000001")
            .unwrap();

    let layer_digests: Vec<Digest> = (0..3)
        .map(|i| {
            Digest::from_str(&format!(
                "sha256:c{i}c0000000000000000000000000000000000000000000000000000000000000"
            ))
            .unwrap()
        })
        .collect();

    let create_ops: Vec<LinkOperation> = layer_digests
        .iter()
        .map(|d| LinkOperation::Create {
            link: LinkKind::Layer(d.clone()),
            target: d.clone(),
            referrer: Some(referrer_digest.clone()),
            media_type: None,
            descriptor: None,
        })
        .collect();
    backend.update_links(&namespace, &create_ops).await.unwrap();

    for d in &layer_digests {
        let link = LinkKind::Layer(d.clone());
        let meta = backend
            .read_link_reference(&namespace, &link)
            .await
            .unwrap();
        assert_eq!(meta.target, *d);
    }

    let delete_ops: Vec<LinkOperation> = layer_digests
        .iter()
        .map(|d| LinkOperation::Delete {
            link: LinkKind::Layer(d.clone()),
            referrer: Some(referrer_digest.clone()),
        })
        .collect();
    backend.update_links(&namespace, &delete_ops).await.unwrap();

    for d in &layer_digests {
        let link = LinkKind::Layer(d.clone());
        let result = backend.read_link_reference(&namespace, &link).await;
        assert!(
            matches!(result, Err(Error::NotFound)),
            "Tracked link {link} should be deleted"
        );

        // The reference entry outlives the link as a stale over-approximation;
        // pruning it is the collector's.
        let index = backend.read_blob_index(d).await.unwrap();
        assert!(
            index
                .namespace
                .get(&namespace)
                .is_some_and(|links| links.contains(&link)),
            "the stale entry is the collector's to prune, not the writer's"
        );
    }
}

#[tokio::test]
async fn test_mixed_creates_and_deletes_across_digests() {
    let config = test_config();
    let backend = config.to_backend(false, None).unwrap();
    let namespace = Namespace::new("mixed-ops-across-digests-test").unwrap();

    let digest_keep =
        Digest::from_str("sha256:dd00000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
    let digest_remove =
        Digest::from_str("sha256:dd00000000000000000000000000000000000000000000000000000000000002")
            .unwrap();
    let digest_add =
        Digest::from_str("sha256:dd00000000000000000000000000000000000000000000000000000000000003")
            .unwrap();

    let setup_ops = vec![
        LinkOperation::Create {
            link: LinkKind::Tag(Tag::new("keep-tag").unwrap()),
            target: digest_keep.clone(),
            referrer: None,
            media_type: None,
            descriptor: None,
        },
        LinkOperation::Create {
            link: LinkKind::Tag(Tag::new("remove-tag").unwrap()),
            target: digest_remove.clone(),
            referrer: None,
            media_type: None,
            descriptor: None,
        },
    ];
    backend.update_links(&namespace, &setup_ops).await.unwrap();

    let mixed_ops = vec![
        LinkOperation::Delete {
            link: LinkKind::Tag(Tag::new("remove-tag").unwrap()),
            referrer: None,
        },
        LinkOperation::Create {
            link: LinkKind::Tag(Tag::new("new-tag").unwrap()),
            target: digest_add.clone(),
            referrer: None,
            media_type: None,
            descriptor: None,
        },
    ];
    backend.update_links(&namespace, &mixed_ops).await.unwrap();

    let keep_index = backend.read_blob_index(&digest_keep).await.unwrap();
    let keep_links = keep_index.namespace.get(&namespace).unwrap();
    assert!(keep_links.contains(&LinkKind::Tag(Tag::new("keep-tag").unwrap())));

    // Writers never remove reference entries: the removed tag's entry stays
    // as a stale over-approximation until the collector prunes it.
    let remove_index = backend.read_blob_index(&digest_remove).await.unwrap();
    assert!(
        remove_index
            .namespace
            .get(&namespace)
            .is_some_and(|links| links.contains(&LinkKind::Tag(Tag::new("remove-tag").unwrap()))),
        "the stale entry is the collector's to prune, not the writer's"
    );

    let add_index = backend.read_blob_index(&digest_add).await.unwrap();
    let add_links = add_index.namespace.get(&namespace).unwrap();
    assert!(add_links.contains(&LinkKind::Tag(Tag::new("new-tag").unwrap())));

    let result = backend
        .read_link_reference(&namespace, &LinkKind::Tag(Tag::new("remove-tag").unwrap()))
        .await;
    assert!(matches!(result, Err(Error::NotFound)));

    let new_meta = backend
        .read_link_reference(&namespace, &LinkKind::Tag(Tag::new("new-tag").unwrap()))
        .await
        .unwrap();
    assert_eq!(new_meta.target, digest_add);
}

/// Writers only produce the reference-key shape: a link write lands as one
/// key under `v2/ref/` and leaves the legacy shard directory empty.
#[tokio::test]
async fn writes_land_as_reference_keys_not_shards() {
    let config = test_config();
    let backend = config.to_backend(false, None).unwrap();
    let namespace = Namespace::new("ref-key-shape-test").unwrap();
    let digest =
        Digest::from_str("sha256:abab000000000000000000000000000000000000000000000000000000000000")
            .unwrap();

    let link = LinkKind::Tag(Tag::new("v1").unwrap());
    let ops = [LinkOperation::Create {
        link: link.clone(),
        target: digest.clone(),
        referrer: None,
        media_type: None,
        descriptor: None,
    }];
    backend.update_links(&namespace, &ops).await.unwrap();

    backend
        .store()
        .object_store()
        .head(&path_builder::blob_ref_path(&digest, &namespace, &link))
        .await
        .expect("the tag's reference key must exist");
    let shards = backend
        .store()
        .object_store()
        .list(&path_builder::blob_index_refs_dir(&digest), 10, None)
        .await
        .unwrap();
    assert!(shards.items.is_empty(), "a push must write no legacy shard");
}

/// Until scrub converts them, legacy shards must keep answering every read
/// alongside the new keys: the whole-index read, the per-namespace read, the
/// liveness check, and the cross-namespace check.
#[tokio::test]
async fn legacy_shards_merge_into_every_read() {
    let config = test_config();
    let backend = config.to_backend(false, None).unwrap();
    let legacy_ns = Namespace::new("legacy-merge-old").unwrap();
    let new_ns = Namespace::new("legacy-merge-new").unwrap();
    let digest =
        Digest::from_str("sha256:cdcd000000000000000000000000000000000000000000000000000000000000")
            .unwrap();

    let shard = serde_json::to_vec(&[LinkKind::Blob(digest.clone())]).unwrap();
    backend
        .store()
        .object_store()
        .put(
            &path_builder::blob_index_shard_path(&digest, &legacy_ns),
            Bytes::from(shard),
        )
        .await
        .unwrap();
    backend
        .update_blob_index(
            &new_ns,
            &digest,
            BlobIndexOperation::Insert(LinkKind::Blob(digest.clone())),
        )
        .await
        .unwrap();

    let index = backend.read_blob_index(&digest).await.unwrap();
    assert!(index.namespace.contains_key(&legacy_ns));
    assert!(index.namespace.contains_key(&new_ns));

    let links = backend
        .read_blob_index_namespace(&legacy_ns, &digest)
        .await
        .unwrap();
    assert!(links.contains(&LinkKind::Blob(digest.clone())));

    assert!(
        backend.blob_references_live(&digest).await.unwrap(),
        "the legacy shard must pin the blob for the collector"
    );
}

/// A shard holding an empty link set must not keep blob data alive. Removing
/// the last link deletes the shard object outright, so the empty set is written
/// directly here: it is the only way to reach the tolerance branch.
#[tokio::test]
async fn test_has_blob_references_ignores_empty_cas_shards() {
    // CAS shard updates only run when the backend's coordinator is `Cas`,
    // which the constructor selects exclusively for `LockStrategy::S3` with
    // CAS-capable conditional caps.
    let mut config = test_config();
    config.lock_strategy = LockStrategy::S3(S3LockConfig::default());
    let backend = config.to_backend(true, None).unwrap();

    let digest =
        Digest::from_str("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
            .unwrap();
    let namespace = Namespace::new("empty-cas-shard").unwrap();
    let shard_path = path_builder::blob_index_shard_path(&digest, &namespace);

    backend
        .store()
        .object_store()
        .put(&shard_path, Bytes::from_static(b"[]"))
        .await
        .unwrap();
    assert!(
        !backend.blob_references_live(&digest).await.unwrap(),
        "empty CAS shards must not keep blob data alive"
    );

    // The negative case above only means something if a populated shard of the
    // same digest reports the opposite.
    backend
        .update_blob_index(
            &namespace,
            &digest,
            BlobIndexOperation::Insert(LinkKind::Blob(digest.clone())),
        )
        .await
        .unwrap();
    assert!(
        backend.blob_references_live(&digest).await.unwrap(),
        "a shard holding a link must keep blob data alive"
    );

    backend
        .store()
        .object_store()
        .delete_prefix(&config.connection.key_prefix)
        .await
        .unwrap();
}

/// The collector's liveness test reads legacy shards the way the old
/// reclaim check did: an emptied shard was deleted by the old write path, so
/// a persisted empty one is an artifact and must not pin the blob forever,
/// while any populated one pins it until scrub converts it.
#[tokio::test]
async fn legacy_shards_gate_collector_liveness() {
    let config = test_config();
    let backend = config.to_backend(false, None).unwrap();
    let theirs = Namespace::new("theirs").unwrap();
    let digest =
        Digest::from_str("sha256:ff00000000000000000000000000000000000000000000000000000000000002")
            .unwrap();
    let theirs_shard = path_builder::blob_index_shard_path(&digest, &theirs);

    backend
        .store()
        .object_store()
        .put(&theirs_shard, Bytes::from_static(b"[]"))
        .await
        .unwrap();
    assert!(
        !backend.blob_references_live(&digest).await.unwrap(),
        "an empty legacy shard must not count as a live reference"
    );

    let links = serde_json::to_vec(&[LinkKind::Blob(digest.clone())]).unwrap();
    backend
        .store()
        .object_store()
        .put(&theirs_shard, Bytes::from(links))
        .await
        .unwrap();
    assert!(
        backend.blob_references_live(&digest).await.unwrap(),
        "a populated legacy shard must pin the blob"
    );

    // A shard whose filename no longer decodes to a valid namespace still
    // pins: skipping it would reclaim bytes another namespace holds.
    let bad_digest =
        Digest::from_str("sha256:ff00000000000000000000000000000000000000000000000000000000000003")
            .unwrap();
    let refs_dir = path_builder::blob_index_refs_dir(&bad_digest);
    let links = serde_json::to_vec(&[LinkKind::Blob(bad_digest.clone())]).unwrap();
    backend
        .store()
        .object_store()
        .put(&format!("{refs_dir}/BAD.json"), Bytes::from(links))
        .await
        .unwrap();
    assert!(
        backend.blob_references_live(&bad_digest).await.unwrap(),
        "a shard that cannot be addressed canonically must still pin the blob"
    );
}

// A corrupt shard must fail the reclaim read instead of parsing as an empty
// link set that green-lights blob-data deletion.
#[tokio::test]
async fn corrupt_shard_fails_reclaim_read_instead_of_parsing_empty() {
    let stack = fs_test_stack();
    let store = stack.store.as_ref();
    let namespace = Namespace::new("corrupt-shard-test").unwrap();
    let digest =
        Digest::from_str("sha256:ff00000000000000000000000000000000000000000000000000000000000001")
            .unwrap();

    let shard_path = path_builder::blob_index_shard_path(&digest, &namespace);
    store
        .object_store()
        .put(&shard_path, Bytes::from_static(b"not json"))
        .await
        .unwrap();

    let result = read_shard(store, &shard_path).await;
    assert!(result.is_err(), "corrupt shard must error, got: {result:?}");
}
