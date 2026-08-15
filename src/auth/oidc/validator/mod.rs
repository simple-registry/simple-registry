use std::{collections::HashMap, time::Duration};

use jsonwebtoken::{Algorithm, Header, Validation, decode, decode_header};
use reqwest::{Client, header::ACCEPT};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::{
    auth::Error,
    auth::{
        oidc::{Config, Jwk},
        sha256_hex,
    },
    cache::Cache,
    identity::OidcClaims,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OpenIdConfiguration {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug)]
struct CachedJson<T> {
    value: T,
    from_cache: bool,
}

struct CachedJsonRequest<'a> {
    client: &'a Client,
    cache: &'a Cache,
    cache_key: &'a str,
    url: &'a str,
    ttl: u64,
    read_cache: bool,
    fetch_timeout: Option<Duration>,
}

pub async fn validate_oidc_token(
    provider_name: &str,
    provider: &Config,
    token: &str,
    client: &Client,
    cache: &Cache,
) -> Result<OidcClaims, Error> {
    let header = decode_header(token)
        .map_err(|e| Error::Unauthorized(format!("Failed to decode JWT header: {e}")))?;

    let mut jwks = fetch_jwks(provider, client, cache).await?;
    if jwks.from_cache
        && cached_jwks_misses_kid(&jwks.value, &header)
        && let Some(refreshed) = refresh_jwks_rate_limited(provider, client, cache).await?
    {
        jwks = refreshed;
    }

    verify_jwt_with_header(token, &header, &jwks.value, provider_name, provider)
}

fn verify_jwt_with_header(
    token: &str,
    header: &Header,
    jwks: &Jwks,
    provider_name: &str,
    provider: &Config,
) -> Result<OidcClaims, Error> {
    debug!(
        "JWT header: alg={:?}, kid={:?}, typ={:?}",
        header.alg, header.kid, header.typ
    );

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

    let validation = build_validation(provider, header.alg);

    debug!(
        "Validation settings: issuer={:?}, audience={:?}, leeway={}, validate_exp={}, validate_nbf={}, algorithms={:?}",
        validation.iss,
        validation.aud,
        validation.leeway,
        validation.validate_exp,
        validation.validate_nbf,
        validation.algorithms
    );

    let token_data =
        decode::<HashMap<String, serde_json::Value>>(token, &decoding_key, &validation).map_err(
            |e| {
                warn!("JWT decode failed with error: {:?}", e);
                Error::Unauthorized(format!("JWT validation failed: {e}"))
            },
        )?;

    provider.verify_required_claims(&token_data.claims)?;

    debug!(
        "Token validated successfully for issuer {}",
        provider.issuer
    );
    Ok(OidcClaims {
        provider_name: provider_name.to_string(),
        claims: token_data.claims,
    })
}

fn build_validation(provider: &Config, alg: Algorithm) -> Validation {
    let mut validation = Validation::new(alg);
    // `decode` rejects a header algorithm absent from this list, and separately
    // rejects the whole list when an entry belongs to another key family, so
    // only the allowed algorithms of the header's own family may be offered.
    validation.algorithms = provider
        .allowed_algorithms
        .iter()
        .filter(|allowed| allowed.family() == alg.family())
        .copied()
        .collect();
    validation.set_issuer(&[provider.issuer.as_str()]);
    if let Some(aud) = &provider.required_audience {
        validation.set_audience(&[aud.as_str()]);
    } else {
        validation.validate_aud = false;
    }
    validation.leeway = provider.clock_skew_tolerance;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation
}

fn cached_jwks_misses_kid(jwks: &Jwks, header: &Header) -> bool {
    let Some(kid) = header.kid.as_deref() else {
        return false;
    };
    !jwks.keys.iter().any(|key| key.kid() == Some(kid))
}

async fn query_json<T>(
    client: &Client,
    url: &str,
    fetch_timeout: Option<Duration>,
) -> Result<T, Error>
where
    T: DeserializeOwned,
{
    let fetch = async {
        let response = client
            .get(url)
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| Error::ProviderUnavailable(format!("Failed to fetch URL {url}: {e}")))?;

        if !response.status().is_success() {
            let msg = format!("Failed to fetch URL {url}: HTTP {}", response.status());
            return Err(Error::ProviderUnavailable(msg));
        }

        response.json().await.map_err(|e| {
            Error::ProviderUnavailable(format!("Failed to parse JSON from {url}: {e}"))
        })
    };

    match fetch_timeout {
        Some(duration) => timeout(duration, fetch)
            .await
            .map_err(|_| Error::ProviderUnavailable(format!("Timed out fetching URL {url}")))?,
        None => fetch.await,
    }
}

async fn get_jwks_url(
    provider: &Config,
    client: &Client,
    cache: &Cache,
    fetch_timeout: Option<Duration>,
) -> Result<String, Error> {
    if let Some(uri) = provider.jwks_uri.as_deref() {
        return Ok(uri.to_string());
    }
    let oidc_config =
        fetch_oidc_configuration_with_timeout(provider, client, cache, fetch_timeout).await?;

    Ok(oidc_config.jwks_uri)
}

/// Shortest interval between forced JWKS refetches for one provider. A cached
/// JWKS missing the token's kid forces a refetch, so without a floor an
/// unauthenticated client sending random kids drives one outbound fetch per
/// request. The cost is that a key rotation can take this long to be picked up.
const JWKS_REFRESH_COOLDOWN_SECS: u64 = 60;

/// The keys below name the issuer, not the config entry: two entries trusting
/// one issuer describe the same signing keys, so they share the cached document
/// rather than each fetching their own.
fn jwks_refresh_cooldown_key(provider: &Config) -> String {
    let issuer_hash = sha256_hex(&provider.issuer);
    format!("oidc:jwks-refresh:{issuer_hash}")
}

fn jwks_cache_key(provider: &Config) -> String {
    let issuer_hash = sha256_hex(&provider.issuer);
    format!("oidc:jwks:{issuer_hash}")
}

fn oidc_configuration_cache_key(provider: &Config) -> String {
    let issuer_hash = sha256_hex(&provider.issuer);
    format!("oidc:config:{issuer_hash}")
}

async fn fetch_cached_json<T, F>(
    request: CachedJsonRequest<'_>,
    validate_fresh: F,
) -> Result<CachedJson<T>, Error>
where
    T: DeserializeOwned + Serialize,
    F: FnOnce(&T) -> Result<(), Error>,
{
    if request.read_cache {
        match request.cache.retrieve::<T>(request.cache_key).await {
            Ok(Some(value)) => {
                debug!("Using cached OIDC JSON for {}", request.cache_key);
                return Ok(CachedJson {
                    value,
                    from_cache: true,
                });
            }
            Err(err) => {
                warn!(
                    "OIDC cache retrieve failed for {}: {err}",
                    request.cache_key
                );
            }
            Ok(None) => {}
        }
    }

    let value = query_json::<T>(request.client, request.url, request.fetch_timeout).await?;
    validate_fresh(&value)?;

    if let Err(err) = request
        .cache
        .store(request.cache_key, &value, request.ttl)
        .await
    {
        warn!("OIDC cache store failed for {}: {err}", request.cache_key);
    }

    Ok(CachedJson {
        value,
        from_cache: false,
    })
}

/// Load the provider's JWKS, preferring the cache. `from_cache` on the result
/// tells the caller whether it may still be stale for a just-rotated key.
async fn fetch_jwks(
    provider: &Config,
    client: &Client,
    cache: &Cache,
) -> Result<CachedJson<Jwks>, Error> {
    let timeout = Duration::from_secs(provider.http_request_timeout_secs);
    let cache_key = jwks_cache_key(provider);
    let jwks_url = get_jwks_url(provider, client, cache, Some(timeout)).await?;
    let fetched = fetch_cached_json::<Jwks, _>(
        CachedJsonRequest {
            client,
            cache,
            cache_key: &cache_key,
            url: &jwks_url,
            ttl: provider.jwks_refresh_interval,
            read_cache: true,
            fetch_timeout: Some(timeout),
        },
        |_| Ok(()),
    )
    .await?;

    if !fetched.from_cache {
        info!("Fetched JWKS from {jwks_url}");
    }
    Ok(fetched)
}

/// Force a refetch unless one already ran inside
/// [`JWKS_REFRESH_COOLDOWN_SECS`], returning `None` when it is suppressed so
/// the caller keeps its cached JWKS and the token fails on the missing key.
/// The marker is claimed before fetching, so a burst of unknown-kid requests
/// costs one outbound fetch rather than one each.
async fn refresh_jwks_rate_limited(
    provider: &Config,
    client: &Client,
    cache: &Cache,
) -> Result<Option<CachedJson<Jwks>>, Error> {
    let cooldown_key = jwks_refresh_cooldown_key(provider);
    if cache
        .retrieve_value(&cooldown_key)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        debug!(
            "Skipping JWKS refresh for issuer {}: one already ran within the cooldown",
            provider.issuer
        );
        return Ok(None);
    }
    let _ = cache
        .store_value(&cooldown_key, "1", JWKS_REFRESH_COOLDOWN_SECS)
        .await;

    info!("Refreshing JWKS for issuer {}", provider.issuer);
    refresh_jwks(provider, client, cache).await.map(Some)
}

/// Force a fresh JWKS fetch, bypassing the cache under a short timeout. Used
/// when a cached JWKS is missing the token's key id (a rotated signing key).
async fn refresh_jwks(
    provider: &Config,
    client: &Client,
    cache: &Cache,
) -> Result<CachedJson<Jwks>, Error> {
    let timeout = Duration::from_secs(provider.jwks_refresh_timeout_secs);
    let cache_key = jwks_cache_key(provider);
    let jwks_url = get_jwks_url(provider, client, cache, Some(timeout)).await?;
    let fetched = fetch_cached_json::<Jwks, _>(
        CachedJsonRequest {
            client,
            cache,
            cache_key: &cache_key,
            url: &jwks_url,
            ttl: provider.jwks_refresh_interval,
            read_cache: false,
            fetch_timeout: Some(timeout),
        },
        |_| Ok(()),
    )
    .await?;

    info!("Fetched JWKS from {jwks_url}");
    Ok(fetched)
}

#[cfg(test)]
async fn fetch_oidc_configuration(
    provider: &Config,
    client: &Client,
    cache: &Cache,
) -> Result<OpenIdConfiguration, Error> {
    fetch_oidc_configuration_with_timeout(provider, client, cache, None).await
}

async fn fetch_oidc_configuration_with_timeout(
    provider: &Config,
    client: &Client,
    cache: &Cache,
    fetch_timeout: Option<Duration>,
) -> Result<OpenIdConfiguration, Error> {
    let cache_key = oidc_configuration_cache_key(provider);
    let config_url = format!("{}/.well-known/openid-configuration", provider.issuer);
    let fetched = fetch_cached_json::<OpenIdConfiguration, _>(
        CachedJsonRequest {
            client,
            cache,
            cache_key: &cache_key,
            url: &config_url,
            ttl: provider.jwks_refresh_interval,
            read_cache: true,
            fetch_timeout,
        },
        |config| validate_oidc_configuration(provider, config),
    )
    .await?;

    if !fetched.from_cache {
        info!("Fetched OIDC configuration from {config_url}");
    }
    Ok(fetched.value)
}

fn validate_oidc_configuration(
    provider: &Config,
    config: &OpenIdConfiguration,
) -> Result<(), Error> {
    let expected_issuer = &provider.issuer;
    if &config.issuer != expected_issuer {
        return Err(Error::Unauthorized(format!(
            "OIDC configuration issuer mismatch: expected {expected_issuer}, got {}",
            config.issuer
        )));
    }

    Ok(())
}

#[cfg(test)]
pub mod tests;
