use crate::registry::oci_types;
use crate::registry::{cache_store, data_store};
use std::cmp::PartialEq;
use std::fmt::Display;
use tracing::{debug, warn};

#[derive(Debug, PartialEq)]
pub enum Error {
    BlobUnknown,
    // BlobUploadInvalid,
    BlobUploadUnknown,
    DigestInvalid,
    ManifestBlobUnknown,
    ManifestInvalid(String),
    ManifestUnknown,
    NameInvalid,
    NameUnknown,
    //SizeInvalid,
    Unauthorized(String),
    Denied(String),
    Unsupported,
    // TooManyRequests,
    //
    // Convenience
    RangeNotSatisfiable,
    // Catch-all
    NotFound,
    Internal(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BlobUnknown => write!(f, "blob unknown to registry"),
            //RegistryError::BlobUploadInvalid => "blob upload invalid",
            Error::BlobUploadUnknown => write!(f, "blob upload unknown to registry"),
            Error::DigestInvalid => write!(f, "provided digest did not match uploaded content"),
            Error::ManifestBlobUnknown => {
                write!(f, "manifest references a blob unknown to registry")
            }
            Error::ManifestInvalid(s) => write!(f, "manifest invalid: {s}"),
            Error::ManifestUnknown => write!(f, "manifest unknown to registry"),
            Error::NameInvalid => write!(f, "invalid repository name"),
            Error::NameUnknown => write!(f, "repository name not known to registry"),
            //RegistryError::SizeInvalid => "provided length did not match content length",
            Error::Unauthorized(s) => write!(f, "{s}"),
            Error::Denied(s) => write!(f, "{s}"),
            Error::Unsupported => write!(f, "the operation is unsupported"),
            //RegistryError::TooManyRequests => "too many requests",
            // Convenience
            Error::RangeNotSatisfiable => write!(f, "range not satisfiable"),
            // Catch-all
            Error::NotFound => write!(f, "resource not found"),
            Error::Internal(s) => write!(f, "internal server error: {s}"),
        }
    }
}

impl From<cache_store::Error> for Error {
    fn from(error: cache_store::Error) -> Self {
        warn!("Cache error: {:?}", error);
        Error::Internal("Cache error during operations".to_string())
    }
}

impl From<oci_types::Error> for Error {
    fn from(error: oci_types::Error) -> Self {
        warn!("OCI error: {:?}", error);
        Error::NameInvalid
    }
}

impl From<data_store::Error> for Error {
    fn from(error: data_store::Error) -> Self {
        match error {
            data_store::Error::UploadNotFound => Error::BlobUploadUnknown,
            data_store::Error::BlobNotFound => Error::BlobUnknown,
            data_store::Error::ReferenceNotFound => Error::ManifestBlobUnknown,
            _ => {
                warn!("Data store error: {:?}", error);
                Error::Internal("Data store error during operations".to_string())
            }
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        debug!("Error: {:?}", error);
        Error::Internal("I/O error during operations".to_string())
    }
}

impl From<hyper::http::Error> for Error {
    fn from(error: hyper::http::Error) -> Self {
        debug!("Hyper HTTP error: {:?}", error);
        Error::Internal("HTTP error during operations".to_string())
    }
}

// XXX: at least repository_upstream is using this error type
impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        debug!("Serde JSON error: {:?}", error);
        Error::Internal("(De)Serialization error during operations".to_string())
    }
}

impl From<cel_interpreter::ExecutionError> for Error {
    fn from(err: cel_interpreter::ExecutionError) -> Self {
        debug!("CEL error: {:?}", err);
        Error::Internal("Policy evaluation error".to_string())
    }
}

impl From<Box<dyn std::error::Error>> for Error {
    fn from(error: Box<dyn std::error::Error>) -> Self {
        debug!("Error: {:?}", error);
        Error::Internal("Error during operations".to_string())
    }
}
