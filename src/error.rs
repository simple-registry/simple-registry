use crate::RegistryResponseBody;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use sha2::digest::crypto_common::hazmat;
use std::cmp::PartialEq;
use std::fmt::Display;
use tracing::{debug, error};

#[derive(Debug, PartialEq)]
pub enum RegistryError {
    BlobUnknown,
    BlobUploadInvalid,
    BlobUploadUnknown,
    DigestInvalid,
    ManifestBlobUnknown,
    ManifestInvalid(Option<String>),
    ManifestUnknown,
    NameInvalid,
    NameUnknown,
    SizeInvalid,
    Unauthorized(Option<String>),
    Denied,
    Unsupported,
    TooManyRequests,
    // Convenience
    RangeNotSatisfiable,
    // Catch-all
    NotFound,
    InternalServerError(Option<String>),
}

impl RegistryError {
    pub fn to_response(&self) -> Response<RegistryResponseBody> {
        let (status, code) = match self {
            RegistryError::BlobUnknown => (StatusCode::NOT_FOUND, "BLOB_UNKNOWN"),
            RegistryError::BlobUploadInvalid => (StatusCode::BAD_REQUEST, "BLOB_UPLOAD_INVALID"),
            RegistryError::BlobUploadUnknown => (StatusCode::NOT_FOUND, "BLOB_UPLOAD_UNKNOWN"),
            RegistryError::DigestInvalid => (StatusCode::BAD_REQUEST, "DIGEST_INVALID"),
            RegistryError::ManifestBlobUnknown => (StatusCode::NOT_FOUND, "MANIFEST_BLOB_UNKNOWN"),
            RegistryError::ManifestInvalid(_) => (StatusCode::BAD_REQUEST, "MANIFEST_INVALID"),
            RegistryError::ManifestUnknown => (StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN"),
            RegistryError::NameInvalid => (StatusCode::BAD_REQUEST, "NAME_INVALID"),
            RegistryError::NameUnknown => (StatusCode::NOT_FOUND, "NAME_UNKNOWN"),
            RegistryError::SizeInvalid => (StatusCode::BAD_REQUEST, "SIZE_INVALID"),
            RegistryError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            RegistryError::Denied => (StatusCode::FORBIDDEN, "DENIED"),
            RegistryError::Unsupported => (StatusCode::BAD_REQUEST, "UNSUPPORTED"),
            RegistryError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "TOOMANYREQUESTS"),
            // Convenience
            RegistryError::RangeNotSatisfiable => {
                (StatusCode::RANGE_NOT_SATISFIABLE, "SIZE_INVALID")
            } // Can't find a better code from the OCI spec
            // Catch-all
            RegistryError::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            RegistryError::InternalServerError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR")
            }
        };

        let body = serde_json::json!({
            "errors": [{
                "code": code,
                "message": self.to_string(),
                "detail": null
            }]
        });

        let body = body.to_string();
        let body = bytes::Bytes::from(body);

        match self {
            RegistryError::Unauthorized(_) => {
                let basic_realm =
                    format!("Basic realm=\"{}\", charset=\"UTF-8\"", "Docker Registry");

                Response::builder()
                    .status(status)
                    .header("Content-Type", "application/json")
                    .header("WWW-Authenticate", basic_realm)
                    .body(RegistryResponseBody::Fixed(Full::new(body)))
                    .unwrap()
            }
            _ => Response::builder()
                .status(status)
                .header("Content-Type", "application/json")
                .body(RegistryResponseBody::Fixed(Full::new(body)))
                .unwrap(),
        }
    }
}

impl Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            RegistryError::BlobUnknown => "blob unknown to registry",
            RegistryError::BlobUploadInvalid => "blob upload invalid",
            RegistryError::BlobUploadUnknown => "blob upload unknown to registry",
            RegistryError::DigestInvalid => "provided digest did not match uploaded content",
            RegistryError::ManifestBlobUnknown => {
                "manifest references a manifest or blob unknown to registry"
            }
            RegistryError::ManifestInvalid(Some(s)) => s.as_str(),
            RegistryError::ManifestInvalid(None) => "manifest invalid",
            RegistryError::ManifestUnknown => "manifest unknown to registry",
            RegistryError::NameInvalid => "invalid repository name",
            RegistryError::NameUnknown => "repository name not known to registry",
            RegistryError::SizeInvalid => "provided length did not match content length",
            RegistryError::Unauthorized(Some(s)) => s.as_str(),
            RegistryError::Unauthorized(None) => "authentication required",
            RegistryError::Denied => "requested access to the resource is denied",
            RegistryError::Unsupported => "the operation is unsupported",
            RegistryError::TooManyRequests => "too many requests",
            // Convenience
            RegistryError::RangeNotSatisfiable => "range not satisfiable",
            // Catch-all
            RegistryError::NotFound => "resource not found",
            RegistryError::InternalServerError(Some(s)) => s.as_str(),
            RegistryError::InternalServerError(None) => "internal server error",
        };

        write!(f, "{}", message)
    }
}

impl From<std::io::Error> for RegistryError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::NotFound {
            debug!("Error: {:?}", error);
            RegistryError::NameUnknown
        } else {
            debug!("Error: {:?}", error);
            RegistryError::InternalServerError(Some("I/O error during operations".to_string()))
        }
    }
}

impl From<regex::Error> for RegistryError {
    fn from(error: regex::Error) -> Self {
        error!("Regex error: {:?}", error);
        RegistryError::InternalServerError(Some("Regex error during operations".to_string()))
    }
}

impl From<hyper::Error> for RegistryError {
    fn from(error: hyper::Error) -> Self {
        error!("Hyper error: {:?}", error);
        RegistryError::InternalServerError(Some("HTTP error during operations".to_string()))
    }
}

impl From<hyper::http::Error> for RegistryError {
    fn from(error: hyper::http::Error) -> Self {
        error!("Hyper HTTP error: {:?}", error);
        RegistryError::InternalServerError(Some("HTTP error during operations".to_string()))
    }
}

impl From<serde_json::Error> for RegistryError {
    fn from(error: serde_json::Error) -> Self {
        error!("Serde JSON error: {:?}", error);
        RegistryError::InternalServerError(Some(
            "(De)Serialization error during operations".to_string(),
        ))
    }
}

impl From<cel_interpreter::ParseError> for RegistryError {
    fn from(error: cel_interpreter::ParseError) -> Self {
        error!("CEL error: {:?}", error);
        RegistryError::InternalServerError(Some("CEL error during operations".to_string()))
    }
}

impl From<hazmat::DeserializeStateError> for RegistryError {
    fn from(error: hazmat::DeserializeStateError) -> Self {
        error!("Crypto error: {:?}", error);
        RegistryError::InternalServerError(Some("Crypto error during operations".to_string()))
    }
}
