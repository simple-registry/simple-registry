use super::*;
use crate::registry::oci::Reference;
use std::path::PathBuf;

#[test]
fn test_webhook_config_validation() {
    let valid_config = WebhookConfig {
        url: "https://example.com/authorize".to_string(),
        timeout_ms: 1000,
        auth: None,
        client_certificate_bundle: None,
        client_private_key: None,
        server_ca_bundle: None,
        forward_headers: vec![],
        cache_ttl: 60,
    };
    assert!(valid_config.validate().is_ok());

    let invalid_config1 = WebhookConfig {
        url: "https://example.com/authorize".to_string(),
        timeout_ms: 1000,
        auth: None,
        client_certificate_bundle: Some(PathBuf::from("/cert.pem")),
        client_private_key: None,
        server_ca_bundle: None,
        forward_headers: vec![],
        cache_ttl: 60,
    };
    assert!(invalid_config1.validate().is_err());

    let invalid_config2 = WebhookConfig {
        url: "https://example.com/authorize".to_string(),
        timeout_ms: 1000,
        auth: None,
        client_certificate_bundle: None,
        client_private_key: Some(PathBuf::from("/key.pem")),
        server_ca_bundle: None,
        forward_headers: vec![],
        cache_ttl: 60,
    };
    assert!(invalid_config2.validate().is_err());
}

#[test]
fn test_webhook_action_header() {
    use crate::registry::server::route::Route;

    let route = Route::GetManifest {
        namespace: "test",
        reference: Reference::Tag("latest".to_string()),
    };
    assert_eq!(route.action_name(), "get-manifest");

    let route = Route::PutManifest {
        namespace: "test",
        reference: Reference::Tag("v1.0".to_string()),
    };
    assert_eq!(route.action_name(), "put-manifest");

    let route = Route::DeleteManifest {
        namespace: "test",
        reference: Reference::Tag("old".to_string()),
    };
    assert_eq!(route.action_name(), "delete-manifest");

    let route = Route::ApiVersion;
    assert_eq!(route.action_name(), "get-api-version");

    let route = Route::GetBlob {
        namespace: "test",
        digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap(),
    };
    assert_eq!(route.action_name(), "get-blob");

    let route = Route::StartUpload {
        namespace: "test",
        digest: None,
    };
    assert_eq!(route.action_name(), "start-upload");
}

#[test]
fn test_webhook_auth_deserialization() {
    let toml = r#"
            url = "https://example.com"
            timeout_ms = 1000
            basic_auth = { username = "user", password = "pass" }
        "#;
    let config: WebhookConfig = toml::from_str(toml).unwrap();
    match config.auth {
        Some(WebhookAuth::BasicAuth { username, password }) => {
            assert_eq!(username, "user");
            assert_eq!(password, "pass");
        }
        _ => panic!("Expected BasicAuth"),
    }
    assert_eq!(config.cache_ttl, 60); // Should use default

    let toml = r#"
            url = "https://example.com"
            timeout_ms = 1000
            bearer_token = "secret-token"
            cache_ttl = 120
        "#;
    let config: WebhookConfig = toml::from_str(toml).unwrap();
    match config.auth {
        Some(WebhookAuth::BearerToken(token)) => {
            assert_eq!(token, "secret-token");
        }
        _ => panic!("Expected BearerToken"),
    }
    assert_eq!(config.cache_ttl, 120); // Should use configured value
}
