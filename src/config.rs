use serde::Deserialize;
use std::path::Path;
use tokio::fs;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub bind_address: String,
    pub port: u16,
    pub tls: Option<ServerTlsConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerTlsConfig {
    pub server_certificate_bundle: String,
    pub server_private_key: String,
    pub client_ca_bundle: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StorageConfig {
    pub root_dir: String,
}

impl Config {
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let config_str = fs::read_to_string(path).await?;
        let config: Self = toml::from_str(&config_str)?;
        Ok(config)
    }
}
