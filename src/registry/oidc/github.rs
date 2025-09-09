use super::generic;
use super::OidcProvider;
use crate::registry::Error;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderConfig {
    #[serde(default = "default_github_issuer")]
    pub issuer: String,
    #[serde(default = "default_github_jwks_uri")]
    pub jwks_uri: String,
    #[serde(default = "default_jwks_refresh_interval")]
    pub jwks_refresh_interval: u64,
    #[serde(default)]
    pub required_audience: Option<String>,
    #[serde(default = "default_clock_skew_tolerance")]
    pub clock_skew_tolerance: u64,
}

fn default_github_issuer() -> String {
    "https://token.actions.githubusercontent.com".to_string()
}

fn default_github_jwks_uri() -> String {
    "https://token.actions.githubusercontent.com/.well-known/jwks".to_string()
}

fn default_jwks_refresh_interval() -> u64 {
    3600
}

fn default_clock_skew_tolerance() -> u64 {
    60
}

pub struct Provider {
    generic: generic::Provider,
}

impl Provider {
    pub fn new(config: ProviderConfig) -> Self {
        let generic_config = generic::ProviderConfig {
            issuer: config.issuer,
            jwks_uri: Some(config.jwks_uri),
            jwks_refresh_interval: config.jwks_refresh_interval,
            required_audience: config.required_audience,
            clock_skew_tolerance: config.clock_skew_tolerance,
        };

        Self {
            generic: generic::Provider::new(generic_config),
        }
    }
}

#[async_trait]
impl OidcProvider for Provider {
    fn issuer(&self) -> &str {
        self.generic.issuer()
    }

    fn jwks_uri(&self) -> Option<&str> {
        self.generic.jwks_uri()
    }

    fn name(&self) -> &'static str {
        "GitHub Actions"
    }

    fn validate_provider_claims(
        &self,
        claims: &HashMap<String, serde_json::Value>,
    ) -> Result<(), Error> {
        if !claims.contains_key("repository") {
            return Err(Error::Unauthorized(
                "Missing repository claim in GitHub token".to_string(),
            ));
        }
        if !claims.contains_key("actor") {
            return Err(Error::Unauthorized(
                "Missing actor claim in GitHub token".to_string(),
            ));
        }
        Ok(())
    }
}
