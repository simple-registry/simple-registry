use super::*;
use crate::cache;
use crate::oci::{Digest, Reference};

#[test]
fn test_get_upstream_namespace() {
    let local_name = "local";
    let upstream_name = "local/repo";

    let result = RegistryClient::get_upstream_namespace(local_name, upstream_name);
    assert_eq!(result, "repo");

    let repo_name = "local/nested";
    let namespace = "completely/different/path";
    let result = RegistryClient::get_upstream_namespace(repo_name, namespace);
    assert_eq!(result, "completely/different/path");
}

#[tokio::test]
async fn test_get_manifest_path() {
    let config = RegistryClientConfig {
        url: "https://example.com".to_string(),
        max_redirect: 5,
        server_ca_bundle: None,
        client_certificate: None,
        client_private_key: None,
        username: Some("username".to_string()),
        password: Some("password".to_string()),
    };

    let cache = Arc::new(cache::memory::Backend::new());
    let upstream = RegistryClient::new(config, cache).unwrap();

    let repo_name = "local";
    let namespace = "local/repo";
    let reference = Reference::Tag("latest".to_string());

    let path = upstream.get_manifest_path(repo_name, namespace, &reference);
    assert_eq!(path, "https://example.com/v2/repo/manifests/latest");
}

#[tokio::test]
async fn test_get_blob_path() {
    let config = RegistryClientConfig {
        url: "https://example.com".to_string(),
        max_redirect: 5,
        server_ca_bundle: None,
        client_certificate: None,
        client_private_key: None,
        username: None,
        password: None,
    };

    let cache = Arc::new(cache::memory::Backend::new());
    let upstream = RegistryClient::new(config, cache).unwrap();

    let repo_name = "local";
    let namespace = "local/repo";
    let digest =
        Digest::try_from("sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
            .unwrap();

    let path = upstream.get_blob_path(repo_name, namespace, &digest);
    assert_eq!(path, "https://example.com/v2/repo/blobs/sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
}
