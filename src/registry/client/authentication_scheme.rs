use crate::registry::Error;
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

static WWW_AUTHENTICATE_HEADER_PARAMETER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(\w+)="([^"]+)""#).unwrap());

#[derive(Debug, PartialEq)]
pub enum AuthenticationScheme {
    Bearer(String, HashMap<String, String>),
    Basic,
}

impl AuthenticationScheme {
    pub fn from_www_authenticate_header(header: &str) -> Result<Self, Error> {
        let header_parameters;
        if header.starts_with("Bearer ") {
            header_parameters = header.trim_start_matches("Bearer ").trim();
            let mut parameters = HashMap::new();

            for (_, [key, value]) in WWW_AUTHENTICATE_HEADER_PARAMETER
                .captures_iter(header_parameters)
                .map(|c| c.extract())
            {
                parameters.insert(key.to_string(), value.to_string());
            }

            let realm = parameters.remove("realm").ok_or_else(|| {
                Error::Internal("Missing realm parameter in WWW-Authenticate header".to_string())
            })?;

            Ok(Self::Bearer(realm, parameters))
        } else if header.starts_with("Basic ") {
            Ok(Self::Basic)
        } else {
            Err(Error::Internal(
                "Unsupported authentication scheme in WWW-Authenticate header".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bearer_from_www_authenticate_header() {
        let header = "Bearer realm=\"https://example.com\",service=\"example\"";
        let scheme = AuthenticationScheme::from_www_authenticate_header(header).unwrap();

        let mut expected_parameters = HashMap::new();
        expected_parameters.insert("service".to_string(), "example".to_string());

        assert_eq!(
            scheme,
            AuthenticationScheme::Bearer("https://example.com".to_string(), expected_parameters)
        );
    }

    #[test]
    fn test_basic_from_www_authenticate_header() {
        let header = "Basic realm=\"https://example.com\"";
        let scheme = AuthenticationScheme::from_www_authenticate_header(header).unwrap();

        assert_eq!(scheme, AuthenticationScheme::Basic);
    }

    #[test]
    fn test_invalid_from_www_authenticate_header() {
        let header = "Invalid realm=\"https://example.com\"";
        let error = AuthenticationScheme::from_www_authenticate_header(header).unwrap_err();

        assert_eq!(
            error,
            Error::Internal(
                "Unsupported authentication scheme in WWW-Authenticate header".to_string()
            )
        );
    }
}
