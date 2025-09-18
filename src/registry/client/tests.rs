use super::*;
use crate::registry::cache;
use crate::registry::oci::{Digest, Reference};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use hyper::body::Bytes;
use hyper::header::HeaderValue;
use mockall::*;

mock! {
    #[derive(Debug)]
    pub HttpClientMock {}

    #[async_trait]
    impl HttpClient for HttpClientMock {
        async fn request(
            &self,
            request: hyper::Request<Empty<Bytes>>
        ) -> Result<Response<Incoming>, registry::Error>;
    }
}

fn build_test_upstream(url: &str, with_basic_auth: bool) -> RegistryClient {
    let basic_auth_header = if with_basic_auth {
        Some(format!(
            "Basic {}",
            BASE64_STANDARD.encode("username:password")
        ))
    } else {
        None
    };

    RegistryClient {
        url: url.to_string(),
        client: Box::new(MockHttpClientMock::new()),
        basic_auth_header,
    }
}

#[test]
fn test_get_upstream_namespace() {
    let local_name = "local";
    let upstream_name = "local/repo";

    let result = RegistryClient::get_upstream_namespace(local_name, upstream_name);
    assert_eq!(result, "repo");

    let upstream_name = "completely_different";
    let result = RegistryClient::get_upstream_namespace(local_name, upstream_name);
    assert_eq!(result, "completely_different");
}

#[tokio::test]
async fn test_get_manifest_path() {
    let upstream = build_test_upstream("https://example.com", true);

    let local_name = "local";
    let upstream_name = "local/repo";
    let reference = Reference::Tag("latest".to_string());

    let path = upstream.get_manifest_path(local_name, upstream_name, &reference);
    assert_eq!(path, "https://example.com/v2/repo/manifests/latest");
}

#[tokio::test]
async fn test_get_blob_path() {
    let upstream = build_test_upstream("https://example.com", false);

    let local_name = "local";
    let upstream_name = "local/repo";
    let digest =
        Digest::try_from("sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
            .unwrap();

    let path = upstream.get_blob_path(local_name, upstream_name, &digest);
    assert_eq!(path, "https://example.com/v2/repo/blobs/sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
}

#[tokio::test]
async fn test_get_auth_token_from_cache_success() {
    const TEST_NAMESPACE: &str = "test-namespace";

    let cache = cache::memory::Backend::new();
    let upstream = build_test_upstream("https://example.com", false);

    let result = upstream
        .get_auth_token_from_cache(&cache, TEST_NAMESPACE)
        .await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    cache
        .store(TEST_NAMESPACE, "test-token", 3600)
        .await
        .unwrap();

    let result = upstream
        .get_auth_token_from_cache(&cache, TEST_NAMESPACE)
        .await;
    assert!(result.is_ok());
    assert_eq!(
        result.unwrap(),
        Some(HeaderValue::from_str("test-token").unwrap())
    );
}
