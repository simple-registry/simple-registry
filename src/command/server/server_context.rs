use crate::command::server::auth::{Authenticator, Authorizer};
use crate::command::server::error::Error;
use crate::command::server::route::Route;
use crate::command::server::ClientIdentity;
use crate::configuration::Configuration;
use crate::registry::Registry;
use hyper::http::request::Parts;
use std::sync::Arc;
use tracing::instrument;

pub struct ServerContext {
    authenticator: Arc<Authenticator>,
    authorizer: Arc<Authorizer>,
    pub registry: Registry,
}

impl ServerContext {
    pub fn new(config: &Configuration, registry: Registry) -> Result<Self, Error> {
        let Ok(cache) = config.cache.to_backend() else {
            return Err(Error::Initialization(
                "Failed to initialize cache backend".to_string(),
            ));
        };

        let authenticator = Arc::new(Authenticator::new(config, &cache)?);
        let authorizer = Arc::new(Authorizer::new(config, &cache)?);

        Ok(Self {
            authenticator,
            authorizer,
            registry,
        })
    }

    #[instrument(skip(self, parts))]
    pub async fn authenticate_request(
        &self,
        parts: &Parts,
        remote_address: Option<std::net::SocketAddr>,
    ) -> Result<ClientIdentity, Error> {
        let mut identity = self
            .authenticator
            .authenticate_request(parts, remote_address)
            .await?;
        if let Some(forwarded_for) = parts.headers.get("X-Forwarded-For") {
            if let Ok(forwarded_str) = forwarded_for.to_str() {
                if let Some(first_ip) = forwarded_str.split(',').next() {
                    identity.client_ip = Some(first_ip.trim().to_string());
                }
            }
        } else if let Some(real_ip) = parts.headers.get("X-Real-IP") {
            if let Ok(ip_str) = real_ip.to_str() {
                identity.client_ip = Some(ip_str.to_string());
            }
        }

        Ok(identity)
    }

    #[instrument(skip(self, request))]
    pub async fn authorize_request(
        &self,
        route: &Route<'_>,
        identity: &ClientIdentity,
        request: &Parts,
    ) -> Result<(), Error> {
        self.authorizer
            .authorize_request(route, identity, request, &self.registry)
            .await
    }

    pub fn is_tag_immutable(&self, namespace: &str, tag: &str) -> bool {
        self.authorizer.is_tag_immutable(namespace, tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::Configuration;
    use crate::oci::Reference;
    use argon2::password_hash::rand_core::OsRng;
    use argon2::password_hash::SaltString;
    use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
    use base64::Engine;
    use hyper::Request;
    use std::collections::HashMap;

    fn create_minimal_config() -> Configuration {
        let toml = r#"
            [blob_store.fs]
            root_dir = "/tmp/test"

            [metadata_store.fs]
            root_dir = "/tmp/test"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10
        "#;

        toml::from_str(toml).unwrap()
    }

    fn create_test_registry(config: &Configuration) -> Registry {
        use crate::registry::repository::Repository;

        let blob_store = config.blob_store.to_backend().unwrap();
        let metadata_store = config.resolve_metadata_config().to_backend().unwrap();
        let auth_cache = config.cache.to_backend().unwrap();

        let mut repositories_map = HashMap::new();
        for (name, repo_config) in &config.repository {
            let repo = Repository::new(name, repo_config, &auth_cache).unwrap();
            repositories_map.insert(name.clone(), repo);
        }
        let repositories = Arc::new(repositories_map);

        Registry::new(
            blob_store,
            metadata_store,
            repositories,
            config.global.update_pull_time,
            config.global.max_concurrent_cache_jobs,
        )
        .unwrap()
    }

    #[test]
    fn test_server_context_new_minimal() {
        let config = create_minimal_config();
        let registry = create_test_registry(&config);

        let context = ServerContext::new(&config, registry);

        assert!(context.is_ok());
    }

    #[test]
    fn test_server_context_new_with_basic_auth() {
        let salt = SaltString::generate(OsRng);
        let argon_config = Params::default();
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_config);
        let password_hash = argon.hash_password(b"testpass", &salt).unwrap().to_string();

        let toml = format!(
            r#"
            [blob_store.fs]
            root_dir = "/tmp/test"

            [metadata_store.fs]
            root_dir = "/tmp/test"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10

            [auth.identity.testuser]
            username = "testuser"
            password = "{password_hash}"
        "#
        );

        let config: Configuration = toml::from_str(&toml).unwrap();
        let registry = create_test_registry(&config);

        let context = ServerContext::new(&config, registry);

        assert!(context.is_ok());
    }

    #[test]
    fn test_server_context_new_with_global_immutable_tags() {
        let toml = r#"
            [blob_store.fs]
            root_dir = "/tmp/test"

            [metadata_store.fs]
            root_dir = "/tmp/test"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10
            immutable_tags = true
            immutable_tags_exclusions = ["^latest$"]
        "#;

        let config: Configuration = toml::from_str(toml).unwrap();
        let registry = create_test_registry(&config);

        let context = ServerContext::new(&config, registry);

        assert!(context.is_ok());
    }

    #[tokio::test]
    async fn test_authenticate_request_no_credentials() {
        let config = create_minimal_config();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        let request = Request::builder().body(()).unwrap();
        let (parts, ()) = request.into_parts();

        let result = context.authenticate_request(&parts, None).await;

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert!(identity.username.is_none());
    }

    #[tokio::test]
    async fn test_authenticate_request_with_basic_auth() {
        let salt = SaltString::generate(OsRng);
        let argon_config = Params::default();
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_config);
        let password_hash = argon.hash_password(b"testpass", &salt).unwrap().to_string();

        let toml = format!(
            r#"
            [blob_store.fs]
            root_dir = "/tmp/test"

            [metadata_store.fs]
            root_dir = "/tmp/test"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10

            [auth.identity.testuser]
            username = "testuser"
            password = "{password_hash}"
        "#
        );

        let config: Configuration = toml::from_str(&toml).unwrap();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        let auth_header = format!(
            "Basic {}",
            base64::prelude::BASE64_STANDARD.encode("testuser:testpass")
        );
        let request = Request::builder()
            .header("Authorization", auth_header)
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let result = context.authenticate_request(&parts, None).await;

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.username, Some("testuser".to_string()));
        assert_eq!(identity.id, Some("testuser".to_string()));
    }

    #[tokio::test]
    async fn test_authenticate_request_with_x_forwarded_for() {
        let config = create_minimal_config();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        let request = Request::builder()
            .header("X-Forwarded-For", "192.168.1.100, 10.0.0.1")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let result = context.authenticate_request(&parts, None).await;

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.client_ip, Some("192.168.1.100".to_string()));
    }

    #[tokio::test]
    async fn test_authenticate_request_with_x_forwarded_for_single_ip() {
        let config = create_minimal_config();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        let request = Request::builder()
            .header("X-Forwarded-For", "192.168.1.100")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let result = context.authenticate_request(&parts, None).await;

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.client_ip, Some("192.168.1.100".to_string()));
    }

    #[tokio::test]
    async fn test_authenticate_request_with_x_forwarded_for_whitespace() {
        let config = create_minimal_config();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        let request = Request::builder()
            .header("X-Forwarded-For", "  192.168.1.100  , 10.0.0.1")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let result = context.authenticate_request(&parts, None).await;

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.client_ip, Some("192.168.1.100".to_string()));
    }

    #[tokio::test]
    async fn test_authenticate_request_with_x_real_ip() {
        let config = create_minimal_config();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        let request = Request::builder()
            .header("X-Real-IP", "192.168.1.200")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let result = context.authenticate_request(&parts, None).await;

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.client_ip, Some("192.168.1.200".to_string()));
    }

    #[tokio::test]
    async fn test_authenticate_request_x_forwarded_for_takes_precedence() {
        let config = create_minimal_config();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        let request = Request::builder()
            .header("X-Forwarded-For", "192.168.1.100")
            .header("X-Real-IP", "192.168.1.200")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let result = context.authenticate_request(&parts, None).await;

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.client_ip, Some("192.168.1.100".to_string()));
    }

    #[tokio::test]
    async fn test_authenticate_request_with_remote_address() {
        let config = create_minimal_config();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        let request = Request::builder().body(()).unwrap();
        let (parts, ()) = request.into_parts();
        let remote_addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result = context
            .authenticate_request(&parts, Some(remote_addr))
            .await;

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.client_ip, Some("127.0.0.1".to_string()));
    }

    #[tokio::test]
    async fn test_authenticate_request_x_forwarded_for_overrides_remote_address() {
        let config = create_minimal_config();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        let request = Request::builder()
            .header("X-Forwarded-For", "192.168.1.100")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        let remote_addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result = context
            .authenticate_request(&parts, Some(remote_addr))
            .await;

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.client_ip, Some("192.168.1.100".to_string()));
    }

    #[tokio::test]
    async fn test_authorize_request_with_global_policy() {
        let toml = r#"
            [blob_store.fs]
            root_dir = "/tmp/test"

            [metadata_store.fs]
            root_dir = "/tmp/test"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10

            [global.access_policy]
            default_allow = true
            rules = []

            [repository.test]
            namespace_pattern = "^test/.*"

            [repository.test.access_policy]
            default_allow = true
            rules = []
        "#;

        let config: Configuration = toml::from_str(toml).unwrap();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        let route = Route::GetManifest {
            namespace: "test/repo",
            reference: Reference::Tag("latest".to_string()),
        };
        let identity = ClientIdentity::new(None);
        let request = Request::builder().body(()).unwrap();
        let (parts, ()) = request.into_parts();

        let result = context.authorize_request(&route, &identity, &parts).await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_is_tag_immutable_with_global_setting() {
        let toml = r#"
            [blob_store.fs]
            root_dir = "/tmp/test"

            [metadata_store.fs]
            root_dir = "/tmp/test"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10
            immutable_tags = true
        "#;

        let config: Configuration = toml::from_str(toml).unwrap();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        assert!(context.is_tag_immutable("test/repo", "v1.0.0"));
    }

    #[test]
    fn test_is_tag_immutable_with_exclusions() {
        let toml = r#"
            [blob_store.fs]
            root_dir = "/tmp/test"

            [metadata_store.fs]
            root_dir = "/tmp/test"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10
            immutable_tags = true
            immutable_tags_exclusions = ["^latest$", "^dev-.*"]
        "#;

        let config: Configuration = toml::from_str(toml).unwrap();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        assert!(!context.is_tag_immutable("test/repo", "latest"));
        assert!(!context.is_tag_immutable("test/repo", "dev-branch"));
        assert!(context.is_tag_immutable("test/repo", "v1.0.0"));
    }

    #[test]
    fn test_is_tag_immutable_with_repository_override() {
        let toml = r#"
            [blob_store.fs]
            root_dir = "/tmp/test"

            [metadata_store.fs]
            root_dir = "/tmp/test"

            [cache.memory]

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10
            immutable_tags = false

            [repository.myrepo]
            namespace_pattern = "^myrepo/.*"
            immutable_tags = true
            immutable_tags_exclusions = ["^test-.*"]
        "#;

        let config: Configuration = toml::from_str(toml).unwrap();
        let registry = create_test_registry(&config);
        let context = ServerContext::new(&config, registry).unwrap();

        assert!(context.is_tag_immutable("myrepo", "v1.0.0"));
        assert!(!context.is_tag_immutable("myrepo", "test-123"));
        assert!(!context.is_tag_immutable("other/repo", "v1.0.0"));
    }

    #[test]
    fn test_server_context_new_invalid_cache_config() {
        let toml = r#"
            [blob_store.fs]
            root_dir = "/tmp/test"

            [metadata_store.fs]
            root_dir = "/tmp/test"

            [cache.redis]
            url = "redis://invalid:99999"
            key_prefix = "test:"

            [server]
            bind_address = "0.0.0.0"
            port = 8000

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10
        "#;

        let config: Configuration = toml::from_str(toml).unwrap();

        let blob_store = config.blob_store.to_backend().unwrap();
        let metadata_store = config.resolve_metadata_config().to_backend().unwrap();
        let repositories = Arc::new(HashMap::new());

        let registry = Registry::new(
            blob_store,
            metadata_store,
            repositories,
            config.global.update_pull_time,
            config.global.max_concurrent_cache_jobs,
        )
        .unwrap();

        let context = ServerContext::new(&config, registry);

        assert!(context.is_err());
        if let Err(Error::Initialization(msg)) = context {
            assert_eq!(msg, "Failed to initialize cache backend");
        } else {
            panic!("Expected Initialization error");
        }
    }
}
