use std::str::FromStr;

use crate::registry::keys::DigestKeys;
use crate::registry::metadata_store::tests::test_config;
use crate::registry::{
    Error,
    metadata_store::{LinkKind, LinkOperation},
};
use angos_oci::{Digest, Namespace, Tag};

#[tokio::test]
async fn test_blob_index_updates_multiple_digests() {
    let config = test_config();
    let backend = config.to_backend(None).unwrap();
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
            size: None,
            annotations: None,
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
    let backend = config.to_backend(None).unwrap();
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
            size: None,
            annotations: None,
            descriptor: None,
        })
        .collect();

    ops.push(LinkOperation::Create {
        link: LinkKind::Config(config_digest.clone()),
        target: config_digest.clone(),
        referrer: Some(referrer_digest.clone()),
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    });

    backend.update_links(&namespace, &ops).await.unwrap();

    let entry = LinkKind::ReferencedBy(referrer_digest.clone());
    for target in layer_digests.iter().chain([&config_digest]) {
        let index = backend.read_blob_index(target).await.unwrap();
        assert!(
            index
                .namespace
                .get(&namespace)
                .is_some_and(|links| links.contains(&entry)),
            "blob {target} should carry the per-referrer entry for {referrer_digest}"
        );
    }
}

#[tokio::test]
async fn test_tracked_link_deletes_with_referrers() {
    let config = test_config();
    let backend = config.to_backend(None).unwrap();
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
            size: None,
            annotations: None,
            descriptor: None,
        })
        .collect();
    backend.update_links(&namespace, &create_ops).await.unwrap();

    let entry = LinkKind::ReferencedBy(referrer_digest.clone());
    for d in &layer_digests {
        let index = backend.read_blob_index(d).await.unwrap();
        assert!(
            index
                .namespace
                .get(&namespace)
                .is_some_and(|links| links.contains(&entry)),
            "blob {d} should carry the per-referrer entry before the delete"
        );
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

        let entry = LinkKind::ReferencedBy(referrer_digest.clone());
        let index = backend.read_blob_index(d).await.unwrap();
        assert!(
            index
                .namespace
                .get(&namespace)
                .is_some_and(|links| links.contains(&entry)),
            "the stale entry is the collector's to prune, not the writer's"
        );
    }
}

#[tokio::test]
async fn test_mixed_creates_and_deletes_across_digests() {
    let config = test_config();
    let backend = config.to_backend(None).unwrap();
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
            size: None,
            annotations: None,
            descriptor: None,
        },
        LinkOperation::Create {
            link: LinkKind::Tag(Tag::new("remove-tag").unwrap()),
            target: digest_remove.clone(),
            referrer: None,
            media_type: None,
            size: None,
            annotations: None,
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
            size: None,
            annotations: None,
            descriptor: None,
        },
    ];
    backend.update_links(&namespace, &mixed_ops).await.unwrap();

    let keep_index = backend.read_blob_index(&digest_keep).await.unwrap();
    let keep_links = keep_index.namespace.get(&namespace).unwrap();
    assert!(keep_links.contains(&LinkKind::Tag(Tag::new("keep-tag").unwrap())));

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

/// A link write lands as one key under `v2/ref/`.
#[tokio::test]
async fn a_write_lands_as_one_reference_key() {
    let config = test_config();
    let backend = config.to_backend(None).unwrap();
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
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(&namespace, &ops).await.unwrap();

    backend
        .object_store()
        .head(&digest.blob_ref_path(&namespace, &link))
        .await
        .expect("the tag's reference key must exist");
}
