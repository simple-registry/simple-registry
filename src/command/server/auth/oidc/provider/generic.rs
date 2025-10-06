use crate::cache::Cache;
use crate::command::server::auth::oidc::{Jwk, OidcProvider};
use crate::command::server::OidcClaims;
use crate::registry::Error;
use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

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

    fn jwks_refresh_interval(&self) -> u64 {
        self.config.jwks_refresh_interval
    }

    fn required_audience(&self) -> Option<&str> {
        self.config.required_audience.as_deref()
    }

    fn clock_skew_tolerance(&self) -> u64 {
        self.config.clock_skew_tolerance
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OpenIdConfiguration {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

pub async fn validate_oidc_token(
    provider_name: &str,
    provider: &dyn OidcProvider,
    token: &str,
    client: &Client,
    cache: &dyn Cache,
) -> Result<OidcClaims, Error> {
    let header = decode_header(token)
        .map_err(|e| Error::Unauthorized(format!("Failed to decode JWT header: {e}")))?;

    debug!(
        "JWT header: alg={:?}, kid={:?}, typ={:?}",
        header.alg, header.kid, header.typ
    );
    let issuer_hash = provider
        .issuer()
        .chars()
        .fold(0u32, |acc, c| acc.wrapping_mul(31).wrapping_add(c as u32));
    let jwks_cache_key = format!("oidc:{}:jwks:{issuer_hash:x}", provider.name());
    let oidc_config_cache_key = format!("oidc:{}:config:{issuer_hash:x}", provider.name());

    let jwks = fetch_jwks(
        provider,
        client,
        cache,
        &jwks_cache_key,
        &oidc_config_cache_key,
    )
    .await?;

    debug!(
        "Available JWKs: {:?}",
        jwks.keys.iter().map(|k| (k.kid(), k)).collect::<Vec<_>>()
    );

    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid() == header.kid.as_deref())
        .ok_or_else(|| {
            Error::Unauthorized(format!("No matching key found for kid: {:?}", header.kid))
        })?;

    debug!("Found matching JWK: {:?}", jwk);

    let decoding_key = jwk.to_decoding_key()?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[provider.issuer()]);
    if let Some(aud) = provider.required_audience() {
        validation.set_audience(&[aud]);
    } else {
        validation.validate_aud = false;
    }
    validation.leeway = provider.clock_skew_tolerance();
    validation.validate_exp = true;
    validation.validate_nbf = true;

    debug!("Validation settings: issuer={:?}, audience={:?}, leeway={}, validate_exp={}, validate_nbf={}, algorithms={:?}",
          validation.iss, validation.aud, validation.leeway, validation.validate_exp, validation.validate_nbf, validation.algorithms);

    let token_data =
        decode::<HashMap<String, serde_json::Value>>(token, &decoding_key, &validation).map_err(
            |e| {
                warn!("JWT decode failed with error: {:?}", e);
                Error::Unauthorized(format!("JWT validation failed: {e}"))
            },
        )?;

    provider.validate_provider_claims(&token_data.claims)?;

    debug!("{} provider: Token validated successfully", provider.name());
    Ok(OidcClaims {
        provider_name: provider_name.to_string(),
        provider_type: provider.name().to_string(),
        claims: token_data.claims,
    })
}

async fn fetch_jwks(
    provider: &dyn OidcProvider,
    client: &Client,
    cache: &dyn Cache,
    jwks_cache_key: &str,
    oidc_config_cache_key: &str,
) -> Result<Jwks, Error> {
    if let Ok(Some(cached)) = cache.retrieve(jwks_cache_key).await {
        if let Ok(jwks) = serde_json::from_str::<Jwks>(&cached) {
            debug!("Using cached JWKS");
            return Ok(jwks);
        }
    }

    let jwks_uri = if let Some(uri) = provider.jwks_uri() {
        uri.to_string()
    } else {
        let oidc_config =
            fetch_oidc_configuration(provider, client, cache, oidc_config_cache_key).await?;
        oidc_config.jwks_uri
    };

    let response = client
        .get(&jwks_uri)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| Error::Internal(format!("Failed to fetch JWKS: {e}")))?;

    if !response.status().is_success() {
        return Err(Error::Internal(format!(
            "Failed to fetch JWKS: HTTP {}",
            response.status()
        )));
    }

    let jwks: Jwks = response
        .json()
        .await
        .map_err(|e| Error::Internal(format!("Failed to parse JWKS: {e}")))?;

    let _ = cache
        .store(
            jwks_cache_key,
            &serde_json::to_string(&jwks)?,
            provider.jwks_refresh_interval(),
        )
        .await;

    info!("Fetched and cached JWKS from {}", jwks_uri);
    Ok(jwks)
}

async fn fetch_oidc_configuration(
    provider: &dyn OidcProvider,
    client: &Client,
    cache: &dyn Cache,
    oidc_config_cache_key: &str,
) -> Result<OpenIdConfiguration, Error> {
    if let Ok(Some(cached)) = cache.retrieve(oidc_config_cache_key).await {
        if let Ok(config) = serde_json::from_str::<OpenIdConfiguration>(&cached) {
            debug!("Using cached OIDC configuration");
            return Ok(config);
        }
    }

    let discovery_url = format!("{}/.well-known/openid-configuration", provider.issuer());

    let response = client
        .get(&discovery_url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| Error::Internal(format!("Failed to fetch OIDC configuration: {e}")))?;

    if !response.status().is_success() {
        return Err(Error::Internal(format!(
            "Failed to fetch OIDC configuration: HTTP {}",
            response.status()
        )));
    }

    let config: OpenIdConfiguration = response
        .json()
        .await
        .map_err(|e| Error::Internal(format!("Failed to parse OIDC configuration: {e}")))?;

    if config.issuer != provider.issuer() {
        return Err(Error::Internal(format!(
            "OIDC configuration issuer mismatch: expected {}, got {}",
            provider.issuer(),
            config.issuer
        )));
    }

    let _ = cache
        .store(
            oidc_config_cache_key,
            &serde_json::to_string(&config)?,
            provider.jwks_refresh_interval(),
        )
        .await;

    info!(
        "Fetched and cached OIDC configuration from {}",
        discovery_url
    );
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::Algorithm;

    #[test]
    fn test_create_provider() {
        let config = ProviderConfig {
            issuer: "https://example.com".to_string(),
            jwks_uri: None,
            jwks_refresh_interval: 3600,
            required_audience: Some("test-audience".to_string()),
            clock_skew_tolerance: 60,
        };

        let provider = Provider::new(config);
        assert_eq!(provider.issuer(), "https://example.com");
        assert_eq!(provider.name(), "Generic OIDC");
        assert!(provider.jwks_uri().is_none());
        assert_eq!(provider.jwks_refresh_interval(), 3600);
        assert_eq!(provider.required_audience(), Some("test-audience"));
        assert_eq!(provider.clock_skew_tolerance(), 60);
    }

    #[test]
    fn test_provider_with_jwks_uri() {
        let config = ProviderConfig {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: Some("https://auth.example.com/.well-known/jwks".to_string()),
            jwks_refresh_interval: 7200,
            required_audience: None,
            clock_skew_tolerance: 120,
        };

        let provider = Provider::new(config);
        assert_eq!(provider.issuer(), "https://auth.example.com");
        assert_eq!(
            provider.jwks_uri(),
            Some("https://auth.example.com/.well-known/jwks")
        );
        assert_eq!(provider.jwks_refresh_interval(), 7200);
        assert!(provider.required_audience().is_none());
        assert_eq!(provider.clock_skew_tolerance(), 120);
    }

    #[test]
    fn test_validation_new_with_rs256() {
        let header = jsonwebtoken::Header {
            alg: Algorithm::RS256,
            ..Default::default()
        };

        let validation = Validation::new(header.alg);
        assert!(validation.algorithms.contains(&Algorithm::RS256));
        assert_eq!(validation.algorithms.len(), 1);
    }

    #[test]
    fn test_validation_algorithms_behavior() {
        for alg in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::ES256,
            Algorithm::ES384,
        ] {
            let validation = Validation::new(alg);
            assert!(
                validation.algorithms.contains(&alg),
                "Algorithm {alg:?} not found in validation.algorithms"
            );
            assert_eq!(
                validation.algorithms.len(),
                1,
                "Expected single algorithm, got {:?}",
                validation.algorithms
            );
        }
    }

    #[test]
    fn test_github_actions_token_header() {
        let header = jsonwebtoken::Header {
            alg: Algorithm::RS256,
            kid: Some("cc413527-173f-5a05-976e-9c52b1d7b431".to_string()),
            typ: Some("JWT".to_string()),
            ..Default::default()
        };

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&["https://token.actions.githubusercontent.com"]);
        validation.set_audience(&["https://github.com/simple-registry"]);
        validation.leeway = 60;
        validation.validate_exp = true;
        validation.validate_nbf = true;

        assert!(validation.algorithms.contains(&Algorithm::RS256));
        assert_eq!(validation.algorithms.len(), 1);

        assert!(validation.iss.is_some());
        assert!(validation.aud.is_some());
        assert_eq!(validation.leeway, 60);
    }
}
