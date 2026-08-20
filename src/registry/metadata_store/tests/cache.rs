use std::{str::FromStr, time::Duration};

use angos_oci::{Digest, Namespace, Tag};

use crate::registry::metadata_store::tests::{test_backend_with_cache, test_config};
use crate::registry::{
    Error,
    metadata_store::{LinkKind, LinkMetadata, LinkOperation},
    path_builder,
};

#[tokio::test]
async fn test_read_link_cache_hit_skips_storage() {
    let config = test_config();
    let (backend, _cache) = test_backend_with_cache(&config);
    let namespace = Namespace::new("cache-hit-ns").unwrap();
    let digest =
        Digest::from_str("sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
            .unwrap();
    let tag = LinkKind::Tag(Tag::new("latest").unwrap());

    let ops = vec![LinkOperation::Create {
        link: tag.clone(),
        target: digest.clone(),
        referrer: None,
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(&namespace, &ops).await.unwrap();

    let meta = backend.read_link(&namespace, &tag).await.unwrap();
    assert_eq!(meta.target, digest);

    let entry_dir = path_builder::tag_entry_dir(&namespace, &Tag::new("latest").unwrap());
    backend
        .object_store()
        .delete_prefix(&entry_dir)
        .await
        .unwrap();

    let meta = backend.read_link(&namespace, &tag).await.unwrap();
    assert_eq!(meta.target, digest);
}

#[tokio::test]
async fn test_read_link_cache_miss_fetches_from_storage() {
    let config = test_config();
    let (backend, cache) = test_backend_with_cache(&config);
    let namespace = Namespace::new("cache-miss-ns").unwrap();
    let digest =
        Digest::from_str("sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3")
            .unwrap();
    let tag = LinkKind::Tag(Tag::new("latest").unwrap());

    let ops = vec![LinkOperation::Create {
        link: tag.clone(),
        target: digest.clone(),
        referrer: None,
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(&namespace, &ops).await.unwrap();

    let meta = backend.read_link(&namespace, &tag).await.unwrap();
    assert_eq!(meta.target, digest);

    let cache_key = format!("link:{namespace}:{tag}");
    let cached: Option<LinkMetadata> = cache.retrieve(&cache_key).await.unwrap();
    assert!(cached.is_some(), "Cache should be populated after read");
    assert_eq!(cached.unwrap().target, digest);
}

#[tokio::test]
async fn test_read_link_cache_expired_refetches() {
    let mut config = test_config();
    config.link_cache_ttl = 1;
    let (backend, _cache) = test_backend_with_cache(&config);
    let namespace = Namespace::new("cache-expired-ns").unwrap();
    let digest_a =
        Digest::from_str("sha256:c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
            .unwrap();
    let digest_b =
        Digest::from_str("sha256:d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5")
            .unwrap();
    let tag = LinkKind::Tag(Tag::new("latest").unwrap());

    let ops = vec![LinkOperation::Create {
        link: tag.clone(),
        target: digest_a.clone(),
        referrer: None,
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(&namespace, &ops).await.unwrap();

    let meta = backend.read_link(&namespace, &tag).await.unwrap();
    assert_eq!(meta.target, digest_a);

    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Write straight to storage so nothing invalidates the cache entry.
    let new_metadata = LinkMetadata::from_digest(digest_b.clone());
    backend
        .write_link_reference(&namespace, &tag, &new_metadata)
        .await
        .unwrap();

    let meta = backend.read_link(&namespace, &tag).await.unwrap();
    assert_eq!(meta.target, digest_b);
}

#[tokio::test]
async fn test_update_links_populates_cache_on_overwrite() {
    let config = test_config();
    let (backend, _cache) = test_backend_with_cache(&config);
    let namespace = Namespace::new("cache-invalidate-ns").unwrap();
    let digest_a =
        Digest::from_str("sha256:e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6")
            .unwrap();
    let digest_b =
        Digest::from_str("sha256:f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1")
            .unwrap();
    let tag = LinkKind::Tag(Tag::new("latest").unwrap());

    let ops = vec![LinkOperation::Create {
        link: tag.clone(),
        target: digest_a.clone(),
        referrer: None,
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(&namespace, &ops).await.unwrap();

    let meta = backend.read_link(&namespace, &tag).await.unwrap();
    assert_eq!(meta.target, digest_a);

    let ops = vec![LinkOperation::Create {
        link: tag.clone(),
        target: digest_b.clone(),
        referrer: None,
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(&namespace, &ops).await.unwrap();

    let entry_dir = path_builder::tag_entry_dir(&namespace, &Tag::new("latest").unwrap());
    backend
        .object_store()
        .delete_prefix(&entry_dir)
        .await
        .unwrap();

    let meta = backend.read_link(&namespace, &tag).await.unwrap();
    assert_eq!(meta.target, digest_b);
}

#[tokio::test]
async fn test_update_links_populates_cache_on_create() {
    let config = test_config();
    let (backend, _cache) = test_backend_with_cache(&config);
    let namespace = Namespace::new("cache-populate-create-ns").unwrap();
    let digest =
        Digest::from_str("sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1")
            .unwrap();
    let tag = LinkKind::Tag(Tag::new("v1").unwrap());

    let ops = vec![LinkOperation::Create {
        link: tag.clone(),
        target: digest.clone(),
        referrer: None,
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(&namespace, &ops).await.unwrap();

    let entry_dir = path_builder::tag_entry_dir(&namespace, &Tag::new("v1").unwrap());
    backend
        .object_store()
        .delete_prefix(&entry_dir)
        .await
        .unwrap();

    let meta = backend.read_link(&namespace, &tag).await.unwrap();
    assert_eq!(meta.target, digest);
}

#[tokio::test]
async fn test_update_links_invalidates_cache_on_delete() {
    let config = test_config();
    let (backend, _cache) = test_backend_with_cache(&config);
    let namespace = Namespace::new("cache-invalidate-delete-ns").unwrap();
    let digest =
        Digest::from_str("sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2")
            .unwrap();
    let tag = LinkKind::Tag(Tag::new("to-delete").unwrap());

    let ops = vec![LinkOperation::Create {
        link: tag.clone(),
        target: digest.clone(),
        referrer: None,
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(&namespace, &ops).await.unwrap();

    let meta = backend.read_link(&namespace, &tag).await.unwrap();
    assert_eq!(meta.target, digest);

    let ops = vec![LinkOperation::Delete {
        link: tag.clone(),
        referrer: None,
    }];
    backend.update_links(&namespace, &ops).await.unwrap();

    let result = backend.read_link(&namespace, &tag).await;
    assert!(
        matches!(result, Err(Error::NotFound)),
        "Should get ReferenceNotFound after deleting a tag via update_links"
    );
}

#[tokio::test]
async fn test_read_link_with_access_time_update_populates_cache() {
    let config = test_config();
    let (backend, _cache) = test_backend_with_cache(&config);
    let namespace = Namespace::new("cache-access-time-ns").unwrap();
    let digest =
        Digest::from_str("sha256:a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8")
            .unwrap();
    let tag = LinkKind::Tag(Tag::new("latest").unwrap());

    let ops = vec![LinkOperation::Create {
        link: tag.clone(),
        target: digest.clone(),
        referrer: None,
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(&namespace, &ops).await.unwrap();

    let meta = backend
        .read_link_recording_access(&namespace, &tag, "test-client")
        .await
        .unwrap();
    assert_eq!(meta.target, digest);
    assert!(
        meta.accessed_at.is_some(),
        "accessed_at should be set after a recording read"
    );

    let meta = backend.read_link(&namespace, &tag).await.unwrap();
    assert_eq!(meta.target, digest);
    assert!(
        meta.accessed_at.is_some(),
        "accessed_at should be present in cached value"
    );
}

#[tokio::test]
async fn test_cache_disabled_when_ttl_zero() {
    let mut config = test_config();
    config.link_cache_ttl = 0;
    let (backend, _cache) = test_backend_with_cache(&config);
    let namespace = Namespace::new("cache-disabled-ns").unwrap();
    let digest =
        Digest::from_str("sha256:b1b2b3b4b5b6b7b8b1b2b3b4b5b6b7b8b1b2b3b4b5b6b7b8b1b2b3b4b5b6b7b8")
            .unwrap();
    let tag = LinkKind::Tag(Tag::new("latest").unwrap());

    let ops = vec![LinkOperation::Create {
        link: tag.clone(),
        target: digest.clone(),
        referrer: None,
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(&namespace, &ops).await.unwrap();

    let meta = backend.read_link(&namespace, &tag).await.unwrap();
    assert_eq!(meta.target, digest);

    let entry_dir = path_builder::tag_entry_dir(&namespace, &Tag::new("latest").unwrap());
    backend
        .object_store()
        .delete_prefix(&entry_dir)
        .await
        .unwrap();

    let result = backend.read_link(&namespace, &tag).await;
    assert!(
        matches!(result, Err(Error::NotFound)),
        "Should get ReferenceNotFound when cache is disabled and storage state is deleted"
    );
}

#[tokio::test]
async fn a_revision_record_stays_cached_past_the_tag_ttl() {
    let mut config = test_config();
    config.link_cache_ttl = 1;
    let (backend, _cache) = test_backend_with_cache(&config);
    let namespace = Namespace::new("cache-immutable-ns").unwrap();
    let digest =
        Digest::from_str("sha256:e1e2e3e4e5e6e7e8e1e2e3e4e5e6e7e8e1e2e3e4e5e6e7e8e1e2e3e4e5e6e7e8")
            .unwrap();
    let link = LinkKind::Digest(digest.clone());

    backend
        .update_links(
            &namespace,
            &[LinkOperation::create(link.clone(), digest.clone())],
        )
        .await
        .unwrap();
    let meta = backend.read_link(&namespace, &link).await.unwrap();
    assert_eq!(meta.target, digest);

    tokio::time::sleep(Duration::from_millis(1100)).await;

    // With the record gone only the cache can answer, and it must: an
    // immutable record is cached without the tag TTL bound.
    backend
        .object_store()
        .delete(&path_builder::revision_record_path(&namespace, &digest))
        .await
        .unwrap();

    let meta = backend.read_link(&namespace, &link).await.unwrap();
    assert_eq!(
        meta.target, digest,
        "an immutable record must outlive the tag TTL in cache"
    );
}

#[tokio::test]
async fn a_manifest_delete_invalidates_the_cached_revision_record() {
    let config = test_config();
    let (backend, _cache) = test_backend_with_cache(&config);
    let namespace = Namespace::new("cache-record-delete-ns").unwrap();
    let digest =
        Digest::from_str("sha256:f1f2f3f4f5f6f7f8f1f2f3f4f5f6f7f8f1f2f3f4f5f6f7f8f1f2f3f4f5f6f7f8")
            .unwrap();
    let link = LinkKind::Digest(digest.clone());

    backend
        .update_links(
            &namespace,
            &[LinkOperation::create(link.clone(), digest.clone())],
        )
        .await
        .unwrap();
    let meta = backend.read_link(&namespace, &link).await.unwrap();
    assert_eq!(meta.target, digest);

    backend
        .delete_manifest(&namespace, &[LinkOperation::delete(link.clone())], None)
        .await
        .unwrap();

    let result = backend.read_link(&namespace, &link).await;
    assert!(
        matches!(result, Err(Error::NotFound)),
        "the delete must invalidate the no-expiry cache entry, got: {result:?}"
    );
}

#[tokio::test]
async fn test_cache_keys_are_namespace_scoped() {
    let config = test_config();
    let (backend, _cache) = test_backend_with_cache(&config);
    let namespace_a = Namespace::new("cache-scope-ns-a").unwrap();
    let namespace_b = Namespace::new("cache-scope-ns-b").unwrap();
    let digest_a =
        Digest::from_str("sha256:c1c2c3c4c5c6c7c8c1c2c3c4c5c6c7c8c1c2c3c4c5c6c7c8c1c2c3c4c5c6c7c8")
            .unwrap();
    let digest_b =
        Digest::from_str("sha256:d1d2d3d4d5d6d7d8d1d2d3d4d5d6d7d8d1d2d3d4d5d6d7d8d1d2d3d4d5d6d7d8")
            .unwrap();
    let tag = LinkKind::Tag(Tag::new("latest").unwrap());

    let ops_a = vec![LinkOperation::Create {
        link: tag.clone(),
        target: digest_a.clone(),
        referrer: None,
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(&namespace_a, &ops_a).await.unwrap();

    let ops_b = vec![LinkOperation::Create {
        link: tag.clone(),
        target: digest_b.clone(),
        referrer: None,
        media_type: None,
        size: None,
        annotations: None,
        descriptor: None,
    }];
    backend.update_links(&namespace_b, &ops_b).await.unwrap();

    let meta_a = backend.read_link(&namespace_a, &tag).await.unwrap();
    let meta_b = backend.read_link(&namespace_b, &tag).await.unwrap();

    assert_eq!(meta_a.target, digest_a);
    assert_eq!(meta_b.target, digest_b);
}
