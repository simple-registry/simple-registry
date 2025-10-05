use crate::registry::{data_store, oci};
use aws_sdk_s3::config::http::HttpResponse;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_sdk_s3::primitives::ByteStreamError;
use sha2::digest::crypto_common::hazmat::DeserializeStateError;
use std::fmt::Debug;
use std::num::TryFromIntError;
use std::string::FromUtf8Error;
use std::{fmt, io};
use tracing::error;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    DataStore(data_store::Error),
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
            Error::DataStore(err) => write!(f, "Data store error: {err}"),
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

impl From<data_store::Error> for Error {
    fn from(err: data_store::Error) -> Self {
        match err {
            data_store::Error::NotFound(_) => Error::ReferenceNotFound,
            _ => Error::DataStore(err),
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
            error!("IO error: {e:?}");
            Error::StorageBackend(e.to_string())
        }
    }
}

impl From<TryFromIntError> for Error {
    fn from(e: TryFromIntError) -> Self {
        error!("TryFromIntError: {e:?}");
        Error::InvalidFormat(e.to_string())
    }
}

// S3 errors

impl From<HeadObjectError> for Error {
    fn from(e: HeadObjectError) -> Self {
        error!("HeadObjectError: {e:?}");
        Error::StorageBackend(format!("HeadObjectError: {e:?}"))
    }
}

impl From<GetObjectError> for Error {
    fn from(e: GetObjectError) -> Self {
        error!("GetObjectError: {e:?}");
        Error::StorageBackend(format!("GetObjectError: {e:?}"))
    }
}

impl<T> From<SdkError<T, HttpResponse>> for Error
where
    T: Debug,
{
    fn from(e: SdkError<T, HttpResponse>) -> Self {
        error!("SdkError: {e:?}");
        Error::StorageBackend(format!("SdkError: {e:?}"))
    }
}

impl From<ByteStreamError> for Error {
    fn from(e: ByteStreamError) -> Self {
        error!("ByteStreamError: {e:?}");
        Error::StorageBackend(format!("ByteStreamError: {e:?}"))
    }
}

impl From<chrono::format::ParseError> for Error {
    fn from(e: chrono::format::ParseError) -> Self {
        Error::InvalidFormat(e.to_string())
    }
}

impl From<oci::Error> for Error {
    fn from(e: oci::Error) -> Self {
        Error::InvalidFormat(e.to_string())
    }
}
