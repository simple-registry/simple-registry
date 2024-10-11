use crate::RegistryResponseBody;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use log::debug;
use sha2::digest::crypto_common::hazmat;
use std::cmp::PartialEq;
use std::fmt::Display;

#[derive(Debug, PartialEq)]
pub enum RegistryError {
    InternalServerError,
    NotFound,
    //NameUnknown,
    BlobUnknown,
    Unauthorized(String),
    //Denied,
    //TooManyRequests,
    DigestInvalid,
    RangeNotSatisfiable,
    Unsupported,
    //ManifestUnknown,
    ManifestInvalid,
    //ManifestUnverified,
    NameInvalid,
}

impl RegistryError {
    pub fn to_response(&self) -> Response<RegistryResponseBody> {
        let (status, code, message) = match self {
            RegistryError::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERVER_ERROR",
                "Internal server error",
            ),
            RegistryError::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND", "Resource not found"),
            /*RegistryError::NameUnknown => (
                StatusCode::NOT_FOUND,
                "NAME_UNKNOWN",
                "Repository name not known to registry",
            ),*/
            RegistryError::BlobUnknown => (
                StatusCode::NOT_FOUND,
                "BLOB_UNKNOWN",
                "Blob unknown to registry",
            ),
            RegistryError::Unauthorized(s) => {
                (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", s.as_str())
            }
            RegistryError::DigestInvalid => (
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                "Provided digest did not match uploaded content",
            ),
            RegistryError::RangeNotSatisfiable => (
                StatusCode::RANGE_NOT_SATISFIABLE,
                "RANGE_NOT_SATISFIABLE",
                "Requested range not satisfiable",
            ),
            RegistryError::Unsupported => (
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
                "The operation is unsupported.",
            ),
            RegistryError::ManifestInvalid => (
                StatusCode::BAD_REQUEST,
                "MANIFEST_INVALID",
                "Manifest invalid",
            ),
            RegistryError::NameInvalid => (
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
                "Invalid repository name",
            ),
        };

        let body = serde_json::json!({
            "errors": [{
                "code": code,
                "message": message,
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
            RegistryError::InternalServerError => "Internal server error",
            RegistryError::NotFound => "Resource not found",
            /*RegistryError::NameUnknown => "Repository name not known to registry",*/
            RegistryError::Unauthorized(s) => s,
            /*RegistryError::Denied => "Denied",
            RegistryError::TooManyRequests => "Too many requests",
            RegistryError::ManifestUnknown => "Manifest unknown",
            RegistryError::ManifestUnverified => "Manifest unverified",*/
            RegistryError::BlobUnknown => "Blob unknown to registry",
            RegistryError::DigestInvalid => "Provided digest did not match uploaded content",
            RegistryError::RangeNotSatisfiable => "Requested range not satisfiable",
            RegistryError::Unsupported => "The operation is unsupported.",
            RegistryError::ManifestInvalid => "Manifest invalid",
            RegistryError::NameInvalid => "Invalid repository name",
        };

        write!(f, "{}", message)
    }
}

impl From<std::io::Error> for RegistryError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::NotFound {
            debug!("Error: {:?}", error);
            RegistryError::NotFound
        } else {
            debug!("Error: {:?}", error);
            RegistryError::InternalServerError
        }
    }
}

impl From<regex::Error> for RegistryError {
    fn from(_: regex::Error) -> Self {
        RegistryError::InternalServerError
    }
}

impl From<hyper::Error> for RegistryError {
    fn from(_: hyper::Error) -> Self {
        RegistryError::InternalServerError
    }
}

impl From<hyper::http::Error> for RegistryError {
    fn from(_: hyper::http::Error) -> Self {
        RegistryError::InternalServerError
    }
}

impl From<serde_json::Error> for RegistryError {
    fn from(_: serde_json::Error) -> Self {
        RegistryError::InternalServerError
    }
}

impl From<hazmat::DeserializeStateError> for RegistryError {
    fn from(_: hazmat::DeserializeStateError) -> Self {
        RegistryError::InternalServerError
    }
}
