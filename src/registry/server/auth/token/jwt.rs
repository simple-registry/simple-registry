use crate::registry::server::auth::token::AccessEntry;
use crate::registry::Error;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryTokenClaims {
    pub iss: String,
    pub sub: String,
    pub exp: i64,
    pub access: Vec<AccessEntry>,
}

pub struct TokenSigner {
    encoding_key: Arc<EncodingKey>,
    decoding_key: Arc<DecodingKey>,
    algorithm: Algorithm,
    issuer: String,
    default_ttl: Duration,
    max_ttl: Duration,
}

impl TokenSigner {
    pub fn new(
        encoding_key: EncodingKey,
        decoding_key: DecodingKey,
        algorithm: Algorithm,
        issuer: String,
        default_ttl: Duration,
        max_ttl: Duration,
    ) -> Self {
        Self {
            encoding_key: Arc::new(encoding_key),
            decoding_key: Arc::new(decoding_key),
            algorithm,
            issuer,
            default_ttl,
            max_ttl,
        }
    }

    pub fn generate_token(
        &self,
        subject: &str,
        access: Vec<AccessEntry>,
        ttl: Option<Duration>,
    ) -> Result<(String, DateTime<Utc>), Error> {
        let now = Utc::now();
        let requested_ttl = ttl.unwrap_or(self.default_ttl);
        let actual_ttl = std::cmp::min(requested_ttl, self.max_ttl);
        let exp = now + actual_ttl;

        let claims = RegistryTokenClaims {
            iss: self.issuer.clone(),
            sub: subject.to_string(),
            exp: exp.timestamp(),
            access,
        };

        let header = Header::new(self.algorithm);
        let token = encode(&header, &claims, &self.encoding_key)
            .map_err(|e| Error::Internal(format!("Failed to sign token: {e}")))?;

        Ok((token, exp))
    }

    pub fn validate_token(&self, token: &str) -> Result<RegistryTokenClaims, Error> {
        let mut validation = Validation::new(self.algorithm);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = 0;
        validation.validate_aud = false;
        validation.validate_nbf = false;

        decode::<RegistryTokenClaims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| Error::Unauthorized(format!("Invalid token: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::server::auth::token::AccessEntry;

    fn create_test_signer() -> TokenSigner {
        TokenSigner::new(
            EncodingKey::from_secret(b"test-secret"),
            DecodingKey::from_secret(b"test-secret"),
            Algorithm::HS256,
            "test-issuer".to_string(),
            Duration::hours(1),
            Duration::hours(24),
        )
    }

    #[test]
    fn test_generate_and_validate_token() {
        let signer = create_test_signer();
        let access = vec![AccessEntry {
            resource_type: "repository".to_string(),
            name: "myorg/myapp".to_string(),
            actions: vec!["pull".to_string(), "push".to_string()],
        }];

        let (token, _exp) = signer
            .generate_token("test-user", access.clone(), None)
            .unwrap();

        let claims = signer.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "test-user");
        assert_eq!(claims.iss, "test-issuer");
        assert_eq!(claims.access.len(), 1);
        assert_eq!(claims.access[0].name, "myorg/myapp");
        assert_eq!(claims.access[0].actions, vec!["pull", "push"]);
    }

    #[test]
    fn test_token_expiration() {
        let signer = create_test_signer();
        let access = vec![AccessEntry {
            resource_type: "repository".to_string(),
            name: "test/repo".to_string(),
            actions: vec!["pull".to_string()],
        }];

        let (_token, exp) = signer.generate_token("user", access, None).unwrap();

        let now = Utc::now();
        assert!(exp > now);
        assert!(exp <= now + Duration::hours(1));
    }

    #[test]
    fn test_ttl_capped_at_max() {
        let signer = create_test_signer();
        let access = vec![AccessEntry {
            resource_type: "repository".to_string(),
            name: "test/repo".to_string(),
            actions: vec!["pull".to_string()],
        }];

        let requested_ttl = Duration::hours(48);
        let (token, _) = signer
            .generate_token("user", access, Some(requested_ttl))
            .unwrap();

        let claims = signer.validate_token(&token).unwrap();

        let exp_from_claims = DateTime::from_timestamp(claims.exp, 0).unwrap();
        let now = Utc::now();
        let actual_ttl = exp_from_claims.signed_duration_since(now);

        assert!(actual_ttl.num_seconds() <= Duration::hours(24).num_seconds());
        assert!(actual_ttl.num_seconds() > Duration::hours(23).num_seconds());
    }

    #[test]
    fn test_invalid_token_rejected() {
        let signer = create_test_signer();
        let result = signer.validate_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_issuer_rejected() {
        let signer1 = create_test_signer();
        let signer2 = TokenSigner::new(
            EncodingKey::from_secret(b"test-secret"),
            DecodingKey::from_secret(b"test-secret"),
            Algorithm::HS256,
            "different-issuer".to_string(),
            Duration::hours(1),
            Duration::hours(24),
        );

        let access = vec![AccessEntry {
            resource_type: "repository".to_string(),
            name: "test/repo".to_string(),
            actions: vec!["pull".to_string()],
        }];

        let (token, _) = signer1.generate_token("user", access, None).unwrap();
        let result = signer2.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let signer1 = TokenSigner::new(
            EncodingKey::from_secret(b"secret1"),
            DecodingKey::from_secret(b"secret1"),
            Algorithm::HS256,
            "issuer".to_string(),
            Duration::hours(1),
            Duration::hours(24),
        );
        let signer2 = TokenSigner::new(
            EncodingKey::from_secret(b"secret2"),
            DecodingKey::from_secret(b"secret2"),
            Algorithm::HS256,
            "issuer".to_string(),
            Duration::hours(1),
            Duration::hours(24),
        );

        let access = vec![AccessEntry {
            resource_type: "repository".to_string(),
            name: "test/repo".to_string(),
            actions: vec!["pull".to_string()],
        }];

        let (token, _) = signer1.generate_token("user", access, None).unwrap();
        let result = signer2.validate_token(&token);
        assert!(result.is_err());
    }
}
