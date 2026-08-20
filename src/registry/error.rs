use std::{num::TryFromIntError, string::FromUtf8Error};

use hyper::header::InvalidHeaderValue;
use sha2::digest::common::hazmat::DeserializeStateError;
use tracing::warn;

use angos_oci::{Error as OciError, http_range};
use angos_storage::Error as StorageError;

use crate::{configuration, jobs::store as job_store, policy, registry::cache, registry_client};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("{0}")]
    Initialization(String),
    #[error("blob unknown to registry")]
    BlobUnknown,
    #[error("blob is still referenced")]
    BlobReferenced,
    #[error("blob upload unknown to registry")]
    BlobUploadUnknown,
    #[error("provided digest did not match uploaded content")]
    DigestInvalid,
    #[error("manifest references a blob unknown to registry")]
    ManifestBlobUnknown,
    #[error("manifest body exceeds supported size limit of {limit} bytes")]
    ManifestBodyTooLarge { limit: usize },
    #[error("blob body exceeds supported size limit of {limit} bytes")]
    BlobBodyTooLarge { limit: usize },
    #[error("manifest invalid: {0}")]
    ManifestInvalid(String),
    #[error("manifest unknown to registry")]
    ManifestUnknown,
    #[error("invalid repository name")]
    NameInvalid,
    #[error("repository name not known to registry")]
    NameUnknown,
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Denied(String),
    #[error("the operation is unsupported")]
    Unsupported,
    #[error("range not satisfiable")]
    RangeNotSatisfiable,
    #[error("resource not found")]
    NotFound,
    /// A transactional write could not be applied because a concurrent writer
    /// won the compare-and-set: the retry budget was exhausted or a precondition
    /// failed. Distinct from [`Self::ReplicationSuperseded`] (a last-writer-wins
    /// convergence, not a retry-conflict). Mapped to HTTP 409.
    #[error("{0}")]
    Conflict(String),
    /// A collector run covers a blob the write references; transient, the
    /// client retries after the collector's batch moves on.
    #[error("reclamation in progress: {0}")]
    ReclamationInProgress(String),
    /// A replication write lost last-writer-wins: the local tag is strictly
    /// newer than the incoming `source_ts`. Mapped to a distinct OCI code so
    /// the sender can treat it as convergence rather than a conflict to retry.
    #[error("{0}")]
    ReplicationSuperseded(String),
    /// A `required`-policy webhook rejected or failed the event delivery.
    /// The operation itself has already committed when this surfaces.
    #[error("event delivery failed: {0}")]
    EventDelivery(String),
    #[error("internal server error: {0}")]
    Internal(String),
    /// Stored content that does not decode. Distinct from [`Self::Internal`]
    /// because re-reading returns the same bytes: a caller reclaiming broken
    /// state can act on it instead of treating it as a transient failure.
    #[error("corrupt stored data: {0}")]
    Corrupt(String),

    // Typed variants that preserve the source error chain.
    #[error("configuration error during operations: {0}")]
    Configuration(#[from] configuration::Error),
    #[error("cache error during operations: {0}")]
    Cache(#[from] cache::Error),
    #[error("I/O error during operations: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP error during operations: {0}")]
    Http(#[from] hyper::http::Error),
    #[error("(de)serialization error during operations: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid header value: {0}")]
    InvalidHeader(#[from] InvalidHeaderValue),
}

// A raw storage outcome carries no domain context. `NotFound` becomes the
// generic `NotFound`; call sites that know a miss means a specific
// blob/upload/manifest 404 intercept `StorageError::NotFound` explicitly before
// `?` reaches this impl. A backend failure is an opaque 500.
impl From<StorageError> for Error {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::NotFound => Error::NotFound,
            StorageError::Backend(msg) => Error::Internal(msg),
        }
    }
}

// Decoding stored bytes: a failure is the content, not the read, so it is
// permanent and reported as `Corrupt` (still HTTP 500).
impl From<DeserializeStateError> for Error {
    fn from(error: DeserializeStateError) -> Self {
        Error::Corrupt(format!("hash state deserialization error: {error}"))
    }
}

impl From<FromUtf8Error> for Error {
    fn from(error: FromUtf8Error) -> Self {
        Error::Corrupt(error.to_string())
    }
}

impl From<TryFromIntError> for Error {
    fn from(error: TryFromIntError) -> Self {
        Error::Internal(error.to_string())
    }
}

impl From<chrono::format::ParseError> for Error {
    fn from(error: chrono::format::ParseError) -> Self {
        Error::Corrupt(error.to_string())
    }
}

// `policy::Error` routes to `Initialization` to preserve the prior behaviour.
// A `#[from]` variant is not used here because the mapping is semantic, not
// structural: all policy errors collapse into the string-carrying `Initialization`.
impl From<policy::Error> for Error {
    fn from(error: policy::Error) -> Self {
        Error::Initialization(error.to_string())
    }
}

// `job_store::Error` routes by variant: a missing record is a `404`, every
// other failure (storage, initialisation) is an opaque `500`.
impl From<job_store::Error> for Error {
    fn from(error: job_store::Error) -> Self {
        match error {
            job_store::Error::NotFound => Error::NotFound,
            other => Error::Internal(other.to_string()),
        }
    }
}

// The outbound client's remote outcomes map variant for variant, so the
// pull-through path surfaces a remote miss as the matching local OCI code.
impl From<registry_client::Error> for Error {
    fn from(error: registry_client::Error) -> Self {
        match error {
            registry_client::Error::Initialization(msg) => Error::Initialization(msg),
            registry_client::Error::Unauthorized(msg) => Error::Unauthorized(msg),
            registry_client::Error::Denied(msg) => Error::Denied(msg),
            registry_client::Error::BlobUnknown => Error::BlobUnknown,
            registry_client::Error::ManifestUnknown => Error::ManifestUnknown,
            registry_client::Error::ManifestBodyTooLarge { limit } => {
                Error::ManifestBodyTooLarge { limit }
            }
            registry_client::Error::Unsupported => Error::Unsupported,
            registry_client::Error::RangeNotSatisfiable => Error::RangeNotSatisfiable,
            registry_client::Error::Internal(msg) => Error::Internal(msg),
        }
    }
}

// A malformed range and an unservable one are both a 416 to the client.
impl From<http_range::Error> for Error {
    fn from(_: http_range::Error) -> Self {
        Error::RangeNotSatisfiable
    }
}

// `OciError` routes to `NameInvalid`: preserve that semantic.
impl From<OciError> for Error {
    fn from(_: OciError) -> Self {
        Error::NameInvalid
    }
}

impl Error {
    /// Maps a manifest parse or ingress-validation failure to the code the OCI
    /// spec gives a malformed manifest. The blanket `From<OciError>` above
    /// answers `NameInvalid` instead, so every manifest body goes through here
    /// to keep one error shape.
    pub fn manifest_invalid(error: &OciError) -> Self {
        warn!("Rejecting manifest: {error}");
        Error::ManifestInvalid(error.to_string())
    }
}

// `x509_parser::error::X509Error` routes to `Unauthorized`: preserve that
// semantic.
impl From<x509_parser::error::X509Error> for Error {
    fn from(_: x509_parser::error::X509Error) -> Self {
        Error::Unauthorized("Invalid client certificate".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;

    use chrono::DateTime;
    use x509_parser::error::X509Error;

    use crate::registry::error::*;

    #[test]
    fn from_io_error_preserves_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
        assert!(StdError::source(&err).is_some());
        assert!(err.to_string().contains("I/O error during operations"));
    }

    #[test]
    fn from_serde_json_preserves_source() {
        let serde_err = serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
        let err: Error = serde_err.into();
        assert!(matches!(err, Error::Serde(_)));
        assert!(StdError::source(&err).is_some());
        assert!(
            err.to_string()
                .contains("(de)serialization error during operations")
        );
    }

    #[test]
    fn from_storage_not_found_routes_to_not_found() {
        let err: Error = StorageError::NotFound.into();
        assert!(matches!(err, Error::NotFound));
    }

    #[test]
    fn from_configuration_preserves_source() {
        let config_err = configuration::Error::Initialization("cfg failed".to_string());
        let err: Error = config_err.into();
        assert!(matches!(err, Error::Configuration(_)));
        assert!(StdError::source(&err).is_some());
        assert!(
            err.to_string()
                .contains("configuration error during operations")
        );
    }

    #[test]
    fn from_cache_preserves_source() {
        let cache_err = cache::Error::Execution("cache miss".to_string());
        let err: Error = cache_err.into();
        assert!(matches!(err, Error::Cache(_)));
        assert!(StdError::source(&err).is_some());
        assert!(err.to_string().contains("cache error during operations"));
    }

    #[test]
    fn from_oci_error_routes_to_name_invalid() {
        let err: Error = OciError::InvalidDigest("bad digest".to_string()).into();
        assert!(matches!(err, Error::NameInvalid));
    }

    #[test]
    fn from_policy_error_routes_to_initialization() {
        let err: Error = policy::Error::Evaluation("eval failed".to_string()).into();
        assert!(matches!(err, Error::Initialization(_)));
        assert!(err.to_string().contains("eval failed"));
    }

    #[test]
    fn from_x509_error_routes_to_unauthorized() {
        let err: Error = X509Error::InvalidCertificate.into();
        assert!(matches!(err, Error::Unauthorized(_)));
        assert!(err.to_string().contains("Invalid client certificate"));
    }

    /// The reclaim paths key off `Corrupt` to tell undecodable stored bytes
    /// from a transient read, so each decode failure must land there.
    #[test]
    fn decoding_stored_bytes_fails_as_corrupt() {
        let not_utf8 = String::from_utf8(vec![0xff, 0xfe]).unwrap_err();
        assert!(matches!(Error::from(not_utf8), Error::Corrupt(_)));

        let not_rfc3339 = DateTime::parse_from_rfc3339("not-a-timestamp").unwrap_err();
        assert!(matches!(Error::from(not_rfc3339), Error::Corrupt(_)));
    }

    /// A backend read that failed is transient, and must stay distinct from
    /// corrupt content or a reclaim would delete a live upload.
    #[test]
    fn a_backend_read_failure_stays_internal() {
        let error = Error::from(StorageError::Backend("connection reset".to_string()));
        assert!(matches!(error, Error::Internal(_)));
    }
}
