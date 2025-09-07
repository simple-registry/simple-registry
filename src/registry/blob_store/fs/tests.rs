use super::Backend;
use crate::registry::blob_store::tests::{
    test_datastore_blob_operations, test_datastore_list_blobs, test_datastore_list_uploads,
    test_datastore_upload_operations,
};
use crate::registry::tests::FSBlobStoreBackendTestCase;
use tokio::fs;

// Implementation-specific tests
#[test]
fn test_paginate() {
    let items: Vec<String> = vec![];
    let (result, token) = Backend::paginate(&items, 10, None);
    assert!(result.is_empty());
    assert!(token.is_none());

    let items: Vec<String> = vec![
        "a".to_string(),
        "b".to_string(),
        "c".to_string(),
        "d".to_string(),
    ];
    let (result, token) = Backend::paginate(&items, 10, None);
    assert_eq!(result, items);
    assert!(token.is_none());

    let (page1, token1) = Backend::paginate(&items, 2, None);
    assert_eq!(page1, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(token1, Some("b".to_string()));

    let (page2, token2) = Backend::paginate(&items, 2, token1);
    assert_eq!(page2, vec!["c".to_string(), "d".to_string()]);
    assert_eq!(token2, None);

    let (page1, token1) = Backend::paginate(&items, 1, None);
    assert_eq!(page1, vec!["a".to_string()]);
    assert_eq!(token1, Some("a".to_string()));

    let (page2, token2) = Backend::paginate(&items, 1, token1);
    assert_eq!(page2, vec!["b".to_string()]);
    assert_eq!(token2, Some("b".to_string()));

    let (page3, token3) = Backend::paginate(&items, 1, token2);
    assert_eq!(page3, vec!["c".to_string()]);
    assert_eq!(token3, Some("c".to_string()));

    let (page4, token4) = Backend::paginate(&items, 1, token3);
    assert_eq!(page4, vec!["d".to_string()]);
    assert_eq!(token4, None);
}

#[tokio::test]
async fn test_write_and_read_file() {
    let t = FSBlobStoreBackendTestCase::new();
    let backend = t.backend();

    let test_path = "test_file.txt";
    let test_content = b"Hello, world!";

    backend.store.write(test_path, test_content).await.unwrap();

    let full_path = t.path().join(test_path);
    assert!(full_path.exists());

    let content = fs::read(&full_path).await.unwrap();
    assert_eq!(content, test_content);

    let test_string = "Hello world!";
    backend
        .store
        .write(test_path, test_string.as_bytes())
        .await
        .unwrap();
    let string_content = fs::read_to_string(&full_path).await.unwrap();
    assert_eq!(string_content, test_string);
}

#[tokio::test]
async fn test_delete_empty_parent_dirs() {
    let t = FSBlobStoreBackendTestCase::new();
    let backend = t.backend();

    let nested_path = "a/b/c/d";
    let test_file_path = "a/b/c/d/test.txt";

    backend.store.write(test_file_path, b"test").await.unwrap();

    backend.store.delete(test_file_path).await.unwrap();

    backend.store.delete_dir(nested_path).await.unwrap();
    backend
        .store
        .delete_empty_parent_dirs(nested_path)
        .await
        .unwrap();

    let full_path = t.temp_dir.path().join(nested_path);
    assert!(!full_path.exists());
    assert!(t.path().exists());
}

#[tokio::test]
async fn test_list_uploads() {
    let t = FSBlobStoreBackendTestCase::new();
    test_datastore_list_uploads(t.backend()).await;
}

#[tokio::test]
async fn test_list_blobs() {
    let t = FSBlobStoreBackendTestCase::new();
    test_datastore_list_blobs(t.backend()).await;
}

#[tokio::test]
async fn test_blob_operations() {
    let t = FSBlobStoreBackendTestCase::new();
    test_datastore_blob_operations(t.backend()).await;
}

#[tokio::test]
async fn test_upload_operations() {
    let t = FSBlobStoreBackendTestCase::new();
    test_datastore_upload_operations(t.backend()).await;
}
