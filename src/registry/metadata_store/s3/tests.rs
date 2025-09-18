use crate::registry::metadata_store::tests::{
    test_datastore_link_operations, test_datastore_list_namespaces, test_datastore_list_referrers,
    test_datastore_list_revisions, test_datastore_list_tags,
};
use crate::registry::tests::S3RegistryTestCase;

#[tokio::test]
async fn test_list_namespaces() {
    let t = S3RegistryTestCase::new();
    test_datastore_list_namespaces(t.blob_store(), t.metadata_store()).await;
}

#[tokio::test]
async fn test_list_tags() {
    let t = S3RegistryTestCase::new();
    test_datastore_list_tags(t.blob_store(), t.metadata_store()).await;
}

#[tokio::test]
async fn test_list_referrers() {
    let t = S3RegistryTestCase::new();
    test_datastore_list_referrers(t.blob_store(), t.metadata_store()).await;
}

#[tokio::test]
async fn test_list_revisions() {
    let t = S3RegistryTestCase::new();
    test_datastore_list_revisions(t.blob_store(), t.metadata_store()).await;
}

#[tokio::test]
async fn test_link_operations() {
    let t = S3RegistryTestCase::new();
    test_datastore_link_operations(t.blob_store(), t.metadata_store()).await;
}
