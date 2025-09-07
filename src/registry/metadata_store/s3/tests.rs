use crate::registry::metadata_store::tests::{
    test_datastore_link_operations, test_datastore_list_namespaces, test_datastore_list_referrers,
    test_datastore_list_revisions, test_datastore_list_tags,
};
use crate::registry::tests::{S3MetadataStoreBackendTestCase, S3RegistryTestCase};

#[tokio::test]
async fn test_list_namespaces() {
    let m = S3MetadataStoreBackendTestCase::new();
    test_datastore_list_namespaces(m.backend()).await;
}

#[tokio::test]
async fn test_list_tags() {
    let m = S3MetadataStoreBackendTestCase::new();
    test_datastore_list_tags(m.backend()).await;
}

#[tokio::test]
async fn test_list_referrers() {
    let r = S3RegistryTestCase::new();
    test_datastore_list_referrers(r.blob_store(), r.metadata_store()).await;
}

#[tokio::test]
async fn test_list_revisions() {
    let m = S3MetadataStoreBackendTestCase::new();
    test_datastore_list_revisions(m.backend()).await;
}

#[tokio::test]
async fn test_link_operations() {
    let t = S3MetadataStoreBackendTestCase::new();
    test_datastore_link_operations(t.backend()).await;
}
