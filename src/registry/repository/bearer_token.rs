use crate::registry::Error;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct BearerToken {
    token: Option<String>,
    access_token: Option<String>,
    #[serde(default = "BearerToken::default_expires_in")]
    expires_in: u64,
}

impl BearerToken {
    fn default_expires_in() -> u64 {
        3600
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice(slice)?)
    }

    pub fn ttl(&self) -> u64 {
        self.expires_in
    }

    pub fn token(mut self) -> Result<String, Error> {
        self.token
            .take()
            .or(self.access_token.take())
            .ok_or_else(|| Error::Internal("Missing token in authentication response".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_expires_in() {
        assert_eq!(BearerToken::default_expires_in(), 3600);
    }

    #[test]
    fn test_from_slice_token() {
        let json = r#"{"token":"test_token","expires_in":3600}"#;
        let token = BearerToken::from_slice(json.as_bytes()).expect("Failed to parse token");
        assert_eq!(token.ttl(), 3600);
        assert_eq!(token.token(), Ok("test_token".to_string()));
    }

    #[test]
    fn test_from_slice_access_token() {
        let json = r#"{"access_token":"test_token","expires_in":3600}"#;
        let token = BearerToken::from_slice(json.as_bytes()).expect("Failed to parse token");
        assert_eq!(token.ttl(), 3600);
        assert_eq!(token.token(), Ok("test_token".to_string()));
    }

    #[test]
    fn test_from_slice_default_ttl() {
        let json = r#"{"access_token":"test_token"}"#;
        let token = BearerToken::from_slice(json.as_bytes()).expect("Failed to parse token");
        assert_eq!(token.ttl(), 3600);
        assert_eq!(token.token(), Ok("test_token".to_string()));
    }

    #[test]
    fn test_from_slice_missing_token() {
        let json = r#"{"expires_in":3600}"#;
        let token = BearerToken::from_slice(json.as_bytes()).expect("Failed to parse token");
        assert_eq!(token.ttl(), 3600);
        assert_eq!(
            token.token(),
            Err(Error::Internal(
                "Missing token in authentication response".to_string()
            ))
        );
    }
}
