use crate::registry::Error;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
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

    pub fn token(&self) -> Result<String, Error> {
        self.token
            .clone()
            .or(self.access_token.clone())
            .ok_or_else(|| Error::Internal("Missing token in authentication response".to_string()))
    }

    pub fn ttl(&self) -> u64 {
        self.expires_in
    }
}
