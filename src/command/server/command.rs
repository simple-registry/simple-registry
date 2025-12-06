use std::collections::HashMap;
use std::sync::Arc;

use argh::FromArgs;

use super::listeners::insecure::InsecureListener;
use super::listeners::tls::{ServerTlsConfig, TlsListener};
use super::ServerContext;
use crate::cache;
use crate::cache::Cache;
use crate::command::server::error::Error;
use crate::configuration::{Configuration, ServerConfig};
use crate::registry::blob_store::BlobStore;
use crate::registry::metadata_store::MetadataStore;
use crate::registry::{blob_store, repository, Registry, Repository};

pub enum ServiceListener {
    Insecure(InsecureListener),
    Secure(TlsListener),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(
    subcommand,
    name = "server",
    description = "Run the registry listeners"
)]
pub struct Options {}

pub struct Command {
    listener: ServiceListener,
}

// TODO: deduplicate!
fn build_blob_store(config: &blob_store::BlobStorageConfig) -> Result<Arc<dyn BlobStore>, Error> {
    let Ok(blob_store) = config.to_backend() else {
        let msg = "Failed to initialize blob store".to_string();
        return Err(Error::Initialization(msg));
    };

    Ok(blob_store)
}

fn build_metadata_store(config: &Configuration) -> Result<Arc<dyn MetadataStore>, Error> {
    match config.resolve_metadata_config().to_backend() {
        Ok(store) => Ok(store),
        Err(err) => {
            let msg = format!("Failed to initialize metadata store: {err}");
            Err(Error::Initialization(msg))
        }
    }
}

fn build_auth_cache(config: &cache::Config) -> Result<Arc<dyn Cache>, Error> {
    match config.to_backend() {
        Ok(cache) => Ok(cache),
        Err(err) => {
            let msg = format!("Failed to initialize auth token cache: {err}");
            Err(Error::Initialization(msg))
        }
    }
}

fn build_repository(
    name: &str,
    config: &repository::Config,
    auth_cache: &Arc<dyn Cache>,
) -> Result<Repository, Error> {
    match Repository::new(name, config, auth_cache) {
        Ok(repo) => Ok(repo),
        Err(err) => {
            let msg = format!("Failed to initialize repository '{name}': {err}");
            Err(Error::Initialization(msg))
        }
    }
}

fn build_repositories(
    configs: &HashMap<String, repository::Config>,
    auth_cache: &Arc<dyn Cache>,
) -> Result<Arc<HashMap<String, Repository>>, Error> {
    let mut repositories = HashMap::new();
    for (name, config) in configs {
        let repo = build_repository(name, config, auth_cache)?;
        repositories.insert(name.clone(), repo);
    }

    Ok(Arc::new(repositories))
}

fn build_registry(config: &Configuration) -> Result<Registry, Error> {
    let blob_store = build_blob_store(&config.blob_store)?;
    let metadata_store = build_metadata_store(config)?;
    let auth_cache = build_auth_cache(&config.cache)?;
    let repositories = build_repositories(&config.repository, &auth_cache)?;

    let Ok(registry) = Registry::new(
        blob_store,
        metadata_store,
        repositories,
        config.global.update_pull_time,
        config.global.enable_redirect,
        config.global.max_concurrent_cache_jobs,
    ) else {
        let msg = "Failed to initialize registry".to_string();
        return Err(Error::Initialization(msg));
    };

    Ok(registry)
}

impl Command {
    pub fn new(config: &Configuration) -> Result<Command, Error> {
        // TODO: non-overlapping configuration subset (?) for each of those helpers
        let registry = build_registry(config)?;
        let context = ServerContext::new(config, registry)?;

        let listener = match &config.server {
            ServerConfig::Insecure(server_config) => {
                ServiceListener::Insecure(InsecureListener::new(server_config, context))
            }
            ServerConfig::Tls(server_config) => {
                ServiceListener::Secure(TlsListener::new(server_config, context)?)
            }
        };

        Ok(Command { listener })
    }

    pub fn notify_config_change(&self, config: &Configuration) -> Result<(), Error> {
        let registry = build_registry(config)?;
        let context = ServerContext::new(config, registry)?;

        match (&self.listener, &config.server) {
            (ServiceListener::Insecure(listener), _) => listener.notify_config_change(context),
            (ServiceListener::Secure(listener), ServerConfig::Tls(server_config)) => {
                listener.notify_config_change(server_config, context)?;
            }
            _ => {}
        }

        Ok(())
    }

    pub fn notify_tls_config_change(&self, server_config: &ServerTlsConfig) -> Result<(), Error> {
        if let ServiceListener::Secure(listener) = &self.listener {
            listener.notify_tls_config_change(server_config)?;
        }

        Ok(())
    }

    pub async fn run(&self) -> Result<(), Error> {
        match &self.listener {
            ServiceListener::Insecure(listener) => listener.serve().await?,
            ServiceListener::Secure(listener) => listener.serve().await?,
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::server::listeners::tls::tests::build_config;

    fn create_minimal_config() -> Configuration {
        let toml = r#"
            [blob_store.fs]
            root_dir = "/tmp/test-blobs"

            [metadata_store.fs]
            root_dir = "/tmp/test-metadata"

            [cache.memory]

            [server]
            bind_address = "127.0.0.1"
            port = 8080

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10
        "#;

        toml::from_str(toml).unwrap()
    }

    fn create_config_with_repository() -> Configuration {
        let toml = r#"
            [blob_store.fs]
            root_dir = "/tmp/test-blobs"

            [metadata_store.fs]
            root_dir = "/tmp/test-metadata"

            [cache.memory]

            [server]
            bind_address = "127.0.0.1"
            port = 8080

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10

            [repository.test-repo.access_policy]
            default_allow = true
            rules = []
        "#;

        toml::from_str(toml).unwrap()
    }

    #[test]
    fn test_build_blob_store_filesystem_success() {
        let config = create_minimal_config();
        let result = build_blob_store(&config.blob_store);

        assert!(result.is_ok());
    }

    #[test]
    fn test_build_metadata_store_filesystem_success() {
        let config = create_minimal_config();
        let result = build_metadata_store(&config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_build_metadata_store_with_explicit_config() {
        let toml = r#"
            [blob_store.fs]
            root_dir = "/tmp/test-blobs"

            [metadata_store.fs]
            root_dir = "/tmp/test-metadata-explicit"

            [cache.memory]

            [server]
            bind_address = "127.0.0.1"
            port = 8080

            [global]
            update_pull_time = false
            max_concurrent_cache_jobs = 10
        "#;

        let config: Configuration = toml::from_str(toml).unwrap();
        let result = build_metadata_store(&config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_build_auth_cache_memory_success() {
        let config = cache::Config::Memory;
        let result = build_auth_cache(&config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_build_repository_success() {
        let toml = r"
            [access_policy]
            default_allow = true
            rules = []
        ";

        let repo_config: repository::Config = toml::from_str(toml).unwrap();
        let cache_config = cache::Config::Memory;
        let cache = build_auth_cache(&cache_config).unwrap();

        let result = build_repository("test-repo", &repo_config, &cache);

        assert!(result.is_ok());
        let repo = result.unwrap();
        assert_eq!(repo.name, "test-repo");
    }

    #[test]
    fn test_build_repository_with_upstream() {
        let toml = r#"
            [access_policy]
            default_allow = true
            rules = []

            [[upstream]]
            url = "https://registry-1.docker.io"
            username = "testuser"
            password = "testpass"
        "#;

        let repo_config: repository::Config = toml::from_str(toml).unwrap();
        let cache_config = cache::Config::Memory;
        let cache = build_auth_cache(&cache_config).unwrap();

        let result = build_repository("cached-repo", &repo_config, &cache);

        assert!(result.is_ok());
    }

    #[test]
    fn test_build_repository_with_immutable_tags() {
        let toml = r#"
            [access_policy]
            default_allow = true
            rules = []

            immutable_tags = true
            immutable_tags_exclusions = ["latest", "dev-.*"]
        "#;

        let repo_config: repository::Config = toml::from_str(toml).unwrap();
        let cache_config = cache::Config::Memory;
        let cache = build_auth_cache(&cache_config).unwrap();

        let result = build_repository("immutable-repo", &repo_config, &cache);

        assert!(result.is_ok());
    }

    #[test]
    fn test_build_repositories_empty() {
        let configs = HashMap::new();
        let cache_config = cache::Config::Memory;
        let cache = build_auth_cache(&cache_config).unwrap();

        let result = build_repositories(&configs, &cache);

        assert!(result.is_ok());
        let repos = result.unwrap();
        assert_eq!(repos.len(), 0);
    }

    #[test]
    fn test_build_repositories_single() {
        let toml = r"
            [access_policy]
            default_allow = true
            rules = []
        ";

        let repo_config: repository::Config = toml::from_str(toml).unwrap();
        let mut configs = HashMap::new();
        configs.insert("repo1".to_string(), repo_config);

        let cache_config = cache::Config::Memory;
        let cache = build_auth_cache(&cache_config).unwrap();

        let result = build_repositories(&configs, &cache);

        assert!(result.is_ok());
        let repos = result.unwrap();
        assert_eq!(repos.len(), 1);
        assert!(repos.contains_key("repo1"));
    }

    #[test]
    fn test_build_repositories_multiple() {
        let toml = r"
            [access_policy]
            default_allow = true
            rules = []
        ";

        let repo_config: repository::Config = toml::from_str(toml).unwrap();
        let mut configs = HashMap::new();
        configs.insert("repo1".to_string(), repo_config.clone());
        configs.insert("repo2".to_string(), repo_config.clone());
        configs.insert("repo3".to_string(), repo_config);

        let cache_config = cache::Config::Memory;
        let cache = build_auth_cache(&cache_config).unwrap();

        let result = build_repositories(&configs, &cache);

        assert!(result.is_ok());
        let repos = result.unwrap();
        assert_eq!(repos.len(), 3);
        assert!(repos.contains_key("repo1"));
        assert!(repos.contains_key("repo2"));
        assert!(repos.contains_key("repo3"));
    }

    #[test]
    fn test_build_registry_minimal_config() {
        let config = create_minimal_config();
        let result = build_registry(&config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_build_registry_with_repositories() {
        let config = create_config_with_repository();
        let result = build_registry(&config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_build_registry_with_update_pull_time() {
        let toml = r#"
            [blob_store.fs]
            root_dir = "/tmp/test-blobs"

            [metadata_store.fs]
            root_dir = "/tmp/test-metadata"

            [cache.memory]

            [server]
            bind_address = "127.0.0.1"
            port = 8080

            [global]
            update_pull_time = true
            max_concurrent_cache_jobs = 20
        "#;

        let config: Configuration = toml::from_str(toml).unwrap();
        let result = build_registry(&config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_command_new_insecure_listener() {
        let config = create_minimal_config();
        let result = Command::new(&config);

        assert!(result.is_ok());
        let command = result.unwrap();

        match command.listener {
            ServiceListener::Insecure(_) => {}
            ServiceListener::Secure(_) => panic!("Expected insecure listener"),
        }
    }

    #[test]
    fn test_command_new_with_repositories() {
        let config = create_config_with_repository();
        let result = Command::new(&config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_command_notify_config_change_insecure() {
        let config = create_minimal_config();
        let command = Command::new(&config).unwrap();

        let new_config = create_minimal_config();
        let result = command.notify_config_change(&new_config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_command_notify_tls_config_change_with_insecure_listener() {
        let config = create_minimal_config();
        let command = Command::new(&config).unwrap();

        let (tls_config, _temp_files) = build_config(false);
        let result = command.notify_tls_config_change(&tls_config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_service_listener_enum_variants() {
        let config = create_minimal_config();
        let ServerConfig::Insecure(insecure_config) = &config.server else {
            panic!("Expected insecure config")
        };

        let registry = build_registry(&config).unwrap();
        let context = ServerContext::new(&config, registry).unwrap();

        let insecure_listener = InsecureListener::new(insecure_config, context);
        let _service_listener = ServiceListener::Insecure(insecure_listener);
    }

    #[test]
    fn test_build_repositories_preserves_names() {
        let toml = r"
            [access_policy]
            default_allow = true
            rules = []
        ";

        let repo_config: repository::Config = toml::from_str(toml).unwrap();
        let mut configs = HashMap::new();
        configs.insert("alpha".to_string(), repo_config.clone());
        configs.insert("beta".to_string(), repo_config.clone());
        configs.insert("gamma".to_string(), repo_config);

        let cache_config = cache::Config::Memory;
        let cache = build_auth_cache(&cache_config).unwrap();
        let repos = build_repositories(&configs, &cache).unwrap();

        assert!(repos.get("alpha").is_some());
        assert!(repos.get("beta").is_some());
        assert!(repos.get("gamma").is_some());
        assert!(repos.get("delta").is_none());
    }

    #[test]
    fn test_build_registry_components_integration() {
        let config = create_config_with_repository();

        let blob_store = build_blob_store(&config.blob_store).unwrap();
        let metadata_store = build_metadata_store(&config).unwrap();
        let auth_cache = build_auth_cache(&config.cache).unwrap();
        let repositories = build_repositories(&config.repository, &auth_cache).unwrap();

        let registry = Registry::new(
            blob_store,
            metadata_store,
            repositories,
            config.global.update_pull_time,
            config.global.enable_redirect,
            config.global.max_concurrent_cache_jobs,
        );

        assert!(registry.is_ok());
    }

    #[test]
    fn test_command_new_validates_configuration() {
        let config = create_minimal_config();
        let result = Command::new(&config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_build_repositories_with_different_configs() {
        let toml1 = r"
            [access_policy]
            default_allow = true
            rules = []
        ";

        let toml2 = r#"
            [access_policy]
            default_allow = false
            rules = ["identity.username == 'admin'"]
        "#;

        let repo_config1: repository::Config = toml::from_str(toml1).unwrap();
        let repo_config2: repository::Config = toml::from_str(toml2).unwrap();

        let mut configs = HashMap::new();
        configs.insert("public".to_string(), repo_config1);
        configs.insert("private".to_string(), repo_config2);

        let cache_config = cache::Config::Memory;
        let cache = build_auth_cache(&cache_config).unwrap();
        let result = build_repositories(&configs, &cache);

        assert!(result.is_ok());
        let repos = result.unwrap();
        assert_eq!(repos.len(), 2);
    }
}
