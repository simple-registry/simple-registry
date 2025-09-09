use super::OidcProvider;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderConfig {
    pub issuer: String,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default = "default_jwks_refresh_interval")]
    pub jwks_refresh_interval: u64,
    #[serde(default)]
    pub required_audience: Option<String>,
    #[serde(default = "default_clock_skew_tolerance")]
    pub clock_skew_tolerance: u64,
}

fn default_jwks_refresh_interval() -> u64 {
    3600
}

fn default_clock_skew_tolerance() -> u64 {
    60
}

pub struct Provider {
    config: ProviderConfig,
}

impl Provider {
    pub fn new(config: ProviderConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl OidcProvider for Provider {
    fn issuer(&self) -> &str {
        &self.config.issuer
    }

    fn jwks_uri(&self) -> Option<&str> {
        self.config.jwks_uri.as_deref()
    }

    fn name(&self) -> &'static str {
        "Generic OIDC"
    }
}
