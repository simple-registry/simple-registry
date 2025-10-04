use crate::configuration::{
    CacheStoreConfig, Error, IdentityConfig, OidcProviderConfig, TokenConfig,
};
use crate::registry;
use crate::registry::cache::{self, Cache};
use crate::registry::server::auth::oidc::OidcValidator;
use crate::registry::server::auth::token::{TokenAuthMiddleware, TokenSigner};
use crate::registry::server::auth::{
    AuthMiddleware, AuthResult, BasicAuthValidator, MtlsValidator,
};
use crate::registry::server::ClientIdentity;
use crate::registry::Registry;
use chrono::Duration;
use hyper::http::request::Parts;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use tracing::instrument;

pub struct ServerContext {
    mtls_middleware: Arc<MtlsValidator>,
    basic_auth_middleware: Arc<BasicAuthValidator>,
    oidc_middlewares: Arc<Vec<OidcValidator>>,
    token_middleware: Option<Arc<TokenAuthMiddleware>>,
    pub token_signer: Option<Arc<TokenSigner>>,
    pub registry: Registry,
}

impl ServerContext {
    pub fn build_oidc_validators(
        oidc_config: &HashMap<String, OidcProviderConfig>,
        auth_token_cache: &CacheStoreConfig,
    ) -> Result<Arc<Vec<OidcValidator>>, Error> {
        let mut validators = Vec::new();
        for (name, provider_config) in oidc_config {
            let cache: Box<dyn Cache> = match auth_token_cache {
                CacheStoreConfig::Redis(redis_config) => {
                    Box::new(cache::redis::Backend::new(redis_config.clone())?)
                }
                CacheStoreConfig::Memory => Box::new(cache::memory::Backend::new()),
            };

            let validator =
                OidcValidator::new(name.clone(), provider_config, cache).map_err(|e| {
                    Error::Http(format!("Failed to create OIDC validator '{name}': {e}"))
                })?;

            validators.push(validator);
        }
        Ok(Arc::new(validators))
    }

    fn load_hmac_keys(token_config: &TokenConfig) -> Result<(EncodingKey, DecodingKey), Error> {
        let secret = token_config.secret.as_ref().ok_or_else(|| {
            Error::Http("Token authentication with HS256/HS384/HS512 requires 'secret'".to_string())
        })?;
        let secret_bytes = secret.as_bytes();
        Ok((
            EncodingKey::from_secret(secret_bytes),
            DecodingKey::from_secret(secret_bytes),
        ))
    }

    fn load_key_pair<F, G>(
        token_config: &TokenConfig,
        encoding_fn: F,
        decoding_fn: G,
        algorithm_name: &str,
    ) -> Result<(EncodingKey, DecodingKey), Error>
    where
        F: FnOnce(&[u8]) -> Result<EncodingKey, jsonwebtoken::errors::Error>,
        G: FnOnce(&[u8]) -> Result<DecodingKey, jsonwebtoken::errors::Error>,
    {
        let private_key_path = token_config.private_key_path.as_ref().ok_or_else(|| {
            Error::Http(format!(
                "Token authentication with {algorithm_name} requires 'private_key_path'"
            ))
        })?;
        let public_key_path = token_config.public_key_path.as_ref().ok_or_else(|| {
            Error::Http(format!(
                "Token authentication with {algorithm_name} requires 'public_key_path'"
            ))
        })?;

        let private_key_pem = fs::read(private_key_path)
            .map_err(|e| Error::Http(format!("Failed to read private key: {e}")))?;
        let public_key_pem = fs::read(public_key_path)
            .map_err(|e| Error::Http(format!("Failed to read public key: {e}")))?;

        Ok((
            encoding_fn(&private_key_pem)
                .map_err(|e| Error::Http(format!("Failed to parse private key: {e}")))?,
            decoding_fn(&public_key_pem)
                .map_err(|e| Error::Http(format!("Failed to parse public key: {e}")))?,
        ))
    }

    fn load_rsa_keys(token_config: &TokenConfig) -> Result<(EncodingKey, DecodingKey), Error> {
        Self::load_key_pair(
            token_config,
            EncodingKey::from_rsa_pem,
            DecodingKey::from_rsa_pem,
            "RS256/RS384/RS512",
        )
    }

    fn load_ec_keys(token_config: &TokenConfig) -> Result<(EncodingKey, DecodingKey), Error> {
        Self::load_key_pair(
            token_config,
            EncodingKey::from_ec_pem,
            DecodingKey::from_ec_pem,
            "ES256/ES384",
        )
    }

    pub fn build_token_signer(
        token_config: Option<TokenConfig>,
    ) -> Result<Option<Arc<TokenSigner>>, Error> {
        let Some(token_config) = token_config else {
            return Ok(None);
        };

        let issuer = token_config.issuer.clone();

        let algorithm = match token_config.algorithm.as_str() {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            "ES256" => Algorithm::ES256,
            "ES384" => Algorithm::ES384,
            alg => {
                return Err(Error::Http(format!(
                    "Unsupported token signing algorithm: {alg}"
                )))
            }
        };

        let (encoding_key, decoding_key) = match algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                Self::load_hmac_keys(&token_config)?
            }
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                Self::load_rsa_keys(&token_config)?
            }
            Algorithm::ES256 | Algorithm::ES384 => Self::load_ec_keys(&token_config)?,
            _ => return Err(Error::Http(format!("Unsupported algorithm: {algorithm:?}"))),
        };

        let default_ttl = humantime::parse_duration(&token_config.default_ttl)
            .map_err(|e| Error::Http(format!("Invalid default_ttl: {e}")))?
            .as_secs();
        let max_ttl = humantime::parse_duration(&token_config.max_ttl)
            .map_err(|e| Error::Http(format!("Invalid max_ttl: {e}")))?
            .as_secs();

        let signer = TokenSigner::new(
            encoding_key,
            decoding_key,
            algorithm,
            issuer,
            Duration::seconds(i64::try_from(default_ttl).unwrap_or(3600)),
            Duration::seconds(i64::try_from(max_ttl).unwrap_or(86400)),
        );

        Ok(Some(Arc::new(signer)))
    }

    pub fn new(
        identities: &HashMap<String, IdentityConfig>,
        registry: Registry,
        oidc_middlewares: Arc<Vec<OidcValidator>>,
        token_config: Option<TokenConfig>,
    ) -> Result<Self, Error> {
        let mtls_middleware = Arc::new(MtlsValidator::new());
        let basic_auth_middleware = Arc::new(BasicAuthValidator::new(identities));

        let token_signer = Self::build_token_signer(token_config)?;
        let token_middleware = token_signer
            .as_ref()
            .map(|signer| Arc::new(TokenAuthMiddleware::new(Arc::clone(signer))));

        Ok(Self {
            mtls_middleware,
            basic_auth_middleware,
            oidc_middlewares,
            token_middleware,
            token_signer,
            registry,
        })
    }

    #[instrument(skip(self, parts))]
    pub async fn authenticate_request(
        &self,
        parts: &Parts,
        remote_address: Option<std::net::SocketAddr>,
    ) -> Result<ClientIdentity, registry::Error> {
        let mut identity = ClientIdentity::default();

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
        } else if let Some(addr) = remote_address {
            identity.client_ip = Some(addr.ip().to_string());
        }

        self.mtls_middleware
            .authenticate(parts, &mut identity)
            .await?;

        if let Some(token_middleware) = &self.token_middleware {
            match token_middleware.authenticate(parts, &mut identity).await {
                Ok(AuthResult::Authenticated) => return Ok(identity),
                Ok(AuthResult::NoCredentials) => {}
                Err(e) => return Err(e),
            }
        }

        for validator in self.oidc_middlewares.iter() {
            match validator.authenticate(parts, &mut identity).await {
                Ok(AuthResult::Authenticated) => return Ok(identity),
                Ok(AuthResult::NoCredentials) => {}
                Err(e) => return Err(e),
            }
        }

        match self
            .basic_auth_middleware
            .authenticate(parts, &mut identity)
            .await
        {
            Ok(AuthResult::Authenticated) => return Ok(identity),
            Ok(AuthResult::NoCredentials) => {}
            Err(e) => return Err(e),
        }

        Ok(identity)
    }
}
