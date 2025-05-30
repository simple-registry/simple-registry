use crate::registry::oci_types;
use aws_sdk_s3::config::http::HttpResponse;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_sdk_s3::primitives::ByteStreamError;
use sha2::digest::crypto_common::hazmat::DeserializeStateError;
use std::string::FromUtf8Error;
use std::{fmt, io};

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    HashSerialization(String),
    JSONSerialization(String),
    StorageBackend(String),
    InvalidFormat(String),
    UploadNotFound,
    BlobNotFound,
    ReferenceNotFound,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::HashSerialization(e) => write!(f, "Hash state management error: {e}"),
            Error::JSONSerialization(e) => write!(f, "JSON serialization error: {e}"),
            Error::StorageBackend(e) => write!(f, "Storage backend error: {e}"),
            Error::InvalidFormat(e) => write!(f, "Reference format error: {e}"),
            Error::UploadNotFound => write!(f, "Upload not found"),
            Error::BlobNotFound => write!(f, "Blob not found"),
            Error::ReferenceNotFound => write!(f, "Reference not found"),
        }
    }
}

impl From<DeserializeStateError> for Error {
    fn from(e: DeserializeStateError) -> Self {
        Error::HashSerialization(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JSONSerialization(e.to_string())
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Error::InvalidFormat(e.to_string())
    }
}

// FS and generic IO errors

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::NotFound {
            Error::ReferenceNotFound
        } else {
            Error::StorageBackend(e.to_string())
        }
    }
}

// S3 errors

impl From<HeadObjectError> for Error {
    fn from(e: HeadObjectError) -> Self {
        Error::StorageBackend(e.to_string())
    }
}

impl From<GetObjectError> for Error {
    fn from(e: GetObjectError) -> Self {
        Error::StorageBackend(e.to_string())
    }
}

impl<T> From<SdkError<T, HttpResponse>> for Error {
    fn from(e: SdkError<T, HttpResponse>) -> Self {
        Error::StorageBackend(e.to_string())
    }
}

impl From<ByteStreamError> for Error {
    fn from(e: ByteStreamError) -> Self {
        Error::StorageBackend(e.to_string())
    }
}

//

impl From<oci_types::Error> for Error {
    fn from(e: oci_types::Error) -> Self {
        Error::InvalidFormat(e.to_string())
    }
}
