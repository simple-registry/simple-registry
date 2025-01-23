use crate::registry::cache_store;
use aws_sdk_s3::config::http::HttpResponse;
use aws_sdk_s3::error::SdkError;
use sha2::digest::crypto_common::hazmat;
use std::cmp::PartialEq;
use std::fmt::Display;
use std::string::FromUtf8Error;
use tracing::{debug, error, warn};

#[derive(Debug, PartialEq)]
pub enum Error {
    BlobUnknown,
    // BlobUploadInvalid,
    BlobUploadUnknown,
    DigestInvalid,
    ManifestBlobUnknown,
    ManifestInvalid(Option<String>),
    ManifestUnknown,
    NameInvalid,
    NameUnknown,
    //SizeInvalid,
    Unauthorized(Option<String>),
    // Denied,
    Unsupported,
    // TooManyRequests,
    //
    // Convenience
    RangeNotSatisfiable,
    // Catch-all
    NotFound,
    Internal(Option<String>),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BlobUnknown => write!(f, "blob unknown to registry"),
            //RegistryError::BlobUploadInvalid => "blob upload invalid",
            Error::BlobUploadUnknown => write!(f, "blob upload unknown to registry"),
            Error::DigestInvalid => write!(f, "provided digest did not match uploaded content"),
            Error::ManifestBlobUnknown => {
                write!(
                    f,
                    "manifest references a manifest or blob unknown to registry"
                )
            }
            Error::ManifestInvalid(Some(s)) => write!(f, "manifest invalid: {s}"),
            Error::ManifestInvalid(None) => write!(f, "manifest invalid"),
            Error::ManifestUnknown => write!(f, "manifest unknown to registry"),
            Error::NameInvalid => write!(f, "invalid repository name"),
            Error::NameUnknown => write!(f, "repository name not known to registry"),
            //RegistryError::SizeInvalid => "provided length did not match content length",
            Error::Unauthorized(Some(s)) => write!(f, "unauthorized: {s}"),
            Error::Unauthorized(None) => write!(f, "unauthorized"),
            //RegistryError::Denied => "requested access to the resource is denied",
            Error::Unsupported => write!(f, "the operation is unsupported"),
            //RegistryError::TooManyRequests => "too many requests",
            // Convenience
            Error::RangeNotSatisfiable => write!(f, "range not satisfiable"),
            // Catch-all
            Error::NotFound => write!(f, "resource not found"),
            Error::Internal(Some(s)) => write!(f, "internal server error: {s}"),
            Error::Internal(None) => write!(f, "internal server error"),
        }
    }
}

impl From<cache_store::Error> for Error {
    fn from(error: cache_store::Error) -> Self {
        warn!("Cache error: {:?}", error);
        Error::Internal(Some("Cache error during operations".to_string()))
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::NotFound {
            debug!("Error: {:?}", error);
            Error::NameUnknown
        } else {
            debug!("Error: {:?}", error);
            Error::Internal(Some("I/O error during operations".to_string()))
        }
    }
}

impl From<regex::Error> for Error {
    fn from(error: regex::Error) -> Self {
        debug!("Regex error: {:?}", error);
        Error::Internal(Some("Regex error during operations".to_string()))
    }
}

impl From<hyper::Error> for Error {
    fn from(error: hyper::Error) -> Self {
        debug!("Hyper error: {:?}", error);
        Error::Internal(Some("HTTP error during operations".to_string()))
    }
}

impl From<hyper::http::Error> for Error {
    fn from(error: hyper::http::Error) -> Self {
        debug!("Hyper HTTP error: {:?}", error);
        Error::Internal(Some("HTTP error during operations".to_string()))
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        debug!("Serde JSON error: {:?}", error);
        Error::Internal(Some(
            "(De)Serialization error during operations".to_string(),
        ))
    }
}

impl From<FromUtf8Error> for Error {
    fn from(error: FromUtf8Error) -> Self {
        debug!("UTF-8 error: {:?}", error);
        Error::Internal(Some("UTF-8 error during operations".to_string()))
    }
}

impl From<cel_interpreter::ParseError> for Error {
    fn from(error: cel_interpreter::ParseError) -> Self {
        debug!("CEL error: {:?}", error);
        Error::Internal(Some("CEL error during operations".to_string()))
    }
}

impl From<hazmat::DeserializeStateError> for Error {
    fn from(error: hazmat::DeserializeStateError) -> Self {
        debug!("Crypto error: {:?}", error);
        Error::Internal(Some("Crypto error during operations".to_string()))
    }
}

impl<T> From<SdkError<T, HttpResponse>> for Error
where
    T: std::fmt::Debug,
{
    fn from(error: SdkError<T, HttpResponse>) -> Self {
        error!("Error handling object: {:?}", error);
        Error::Internal(Some("S3 error during operations".to_string()))
    }
}
