use crate::command::server::auth::oidc::provider::generic;
use crate::command::server::auth::oidc::OidcProvider;
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

    fn jwks_refresh_interval(&self) -> u64 {
        self.generic.jwks_refresh_interval()
    }

    fn required_audience(&self) -> Option<&str> {
        self.generic.required_audience()
    }

    fn clock_skew_tolerance(&self) -> u64 {
        self.generic.clock_skew_tolerance()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_provider() {
        let config = ProviderConfig {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            jwks_uri: "https://token.actions.githubusercontent.com/.well-known/jwks".to_string(),
            jwks_refresh_interval: 3600,
            required_audience: None,
            clock_skew_tolerance: 60,
        };

        let provider = Provider::new(config);
        assert_eq!(
            provider.issuer(),
            "https://token.actions.githubusercontent.com"
        );
        assert_eq!(provider.name(), "GitHub Actions");
        assert_eq!(
            provider.jwks_uri(),
            Some("https://token.actions.githubusercontent.com/.well-known/jwks")
        );
        assert_eq!(provider.jwks_refresh_interval(), 3600);
        assert!(provider.required_audience().is_none());
        assert_eq!(provider.clock_skew_tolerance(), 60);
    }

    #[test]
    fn test_provider_with_defaults() {
        let config = ProviderConfig {
            issuer: default_github_issuer(),
            jwks_uri: default_github_jwks_uri(),
            jwks_refresh_interval: default_jwks_refresh_interval(),
            required_audience: Some("my-audience".to_string()),
            clock_skew_tolerance: default_clock_skew_tolerance(),
        };

        let provider = Provider::new(config);
        assert_eq!(
            provider.issuer(),
            "https://token.actions.githubusercontent.com"
        );
        assert_eq!(
            provider.jwks_uri(),
            Some("https://token.actions.githubusercontent.com/.well-known/jwks")
        );
        assert_eq!(provider.required_audience(), Some("my-audience"));
    }

    #[test]
    fn test_validate_provider_claims() {
        let config = ProviderConfig {
            issuer: default_github_issuer(),
            jwks_uri: default_github_jwks_uri(),
            jwks_refresh_interval: default_jwks_refresh_interval(),
            required_audience: None,
            clock_skew_tolerance: default_clock_skew_tolerance(),
        };

        let provider = Provider::new(config);

        let mut claims = HashMap::new();
        claims.insert("repository".to_string(), serde_json::json!("org/repo"));
        claims.insert("actor".to_string(), serde_json::json!("user"));
        assert!(provider.validate_provider_claims(&claims).is_ok());

        let mut claims = HashMap::new();
        claims.insert("actor".to_string(), serde_json::json!("user"));
        assert!(provider.validate_provider_claims(&claims).is_err());

        let mut claims = HashMap::new();
        claims.insert("repository".to_string(), serde_json::json!("org/repo"));
        assert!(provider.validate_provider_claims(&claims).is_err());

        let claims = HashMap::new();
        assert!(provider.validate_provider_claims(&claims).is_err());
    }
}
