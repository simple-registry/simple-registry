use crate::registry::blob_store::tests::{
    test_datastore_blob_operations, test_datastore_list_blobs, test_datastore_list_uploads,
    test_datastore_upload_operations,
};
use crate::registry::tests::S3BlobStoreBackendTestCase;

#[tokio::test]
async fn test_list_uploads() {
    let t = S3BlobStoreBackendTestCase::new();
    test_datastore_list_uploads(t.backend()).await;
}

#[tokio::test]
async fn test_list_blobs() {
    let t = S3BlobStoreBackendTestCase::new();
    test_datastore_list_blobs(t.backend()).await;
}

#[tokio::test]
async fn test_blob_operations() {
    let t = S3BlobStoreBackendTestCase::new();
    test_datastore_blob_operations(t.backend()).await;
}

#[tokio::test]
async fn test_upload_operations() {
    let t = S3BlobStoreBackendTestCase::new();
    test_datastore_upload_operations(t.backend()).await;
}
