use hyper::StatusCode;

use angos_oci::response::ErrorCode;

use crate::{
    auth,
    command::{
        bootstrap,
        server::error::{Error, INTERNAL_ERROR_CODE},
    },
    configuration, event_webhook,
    jobs::store as job_store,
    metrics_provider, registry,
    registry_client::REPLICATION_SUPERSEDED_CODE,
};

fn oci_error(status_code: StatusCode, code: ErrorCode, msg: Option<String>) -> Error {
    angos_error(status_code, code.as_str(), msg)
}

/// The same body under a code the spec does not define: angos's own extensions,
/// which a 5xx may carry and a replication peer reads to settle convergence.
fn angos_error(status_code: StatusCode, code: &str, msg: Option<String>) -> Error {
    Error::Custom {
        status_code,
        code: code.to_string(),
        msg,
    }
}

impl From<registry::Error> for Error {
    fn from(error: registry::Error) -> Self {
        match error {
            registry::Error::Initialization(msg) => Error::Initialization(msg),
            registry::Error::BlobUnknown => {
                oci_error(StatusCode::NOT_FOUND, ErrorCode::BlobUnknown, None)
            }
            // `405` is what end-10 lists for a refused blob delete, so the
            // reason travels in the message rather than in a status outside
            // that set: the client has only to delete the manifest first.
            registry::Error::BlobReferenced => oci_error(
                StatusCode::METHOD_NOT_ALLOWED,
                ErrorCode::Denied,
                Some(error.to_string()),
            ),
            registry::Error::BlobUploadUnknown => {
                oci_error(StatusCode::NOT_FOUND, ErrorCode::BlobUploadUnknown, None)
            }
            registry::Error::DigestInvalid => {
                oci_error(StatusCode::BAD_REQUEST, ErrorCode::DigestInvalid, None)
            }
            registry::Error::ManifestBlobUnknown => {
                oci_error(StatusCode::NOT_FOUND, ErrorCode::ManifestBlobUnknown, None)
            }
            registry::Error::ManifestBodyTooLarge { .. } => oci_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::ManifestInvalid,
                Some(error.to_string()),
            ),
            registry::Error::BlobBodyTooLarge { .. } => oci_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::BlobUploadInvalid,
                Some(error.to_string()),
            ),
            registry::Error::ManifestInvalid(msg) => oci_error(
                StatusCode::BAD_REQUEST,
                ErrorCode::ManifestInvalid,
                Some(msg),
            ),
            registry::Error::ManifestUnknown => {
                oci_error(StatusCode::NOT_FOUND, ErrorCode::ManifestUnknown, None)
            }
            registry::Error::NameInvalid => {
                oci_error(StatusCode::BAD_REQUEST, ErrorCode::NameInvalid, None)
            }
            registry::Error::NameUnknown | registry::Error::NotFound => {
                oci_error(StatusCode::NOT_FOUND, ErrorCode::NameUnknown, None)
            }
            registry::Error::Unauthorized(msg) => {
                oci_error(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, Some(msg))
            }
            registry::Error::Denied(msg) => {
                oci_error(StatusCode::FORBIDDEN, ErrorCode::Denied, Some(msg))
            }
            registry::Error::Unsupported => {
                oci_error(StatusCode::BAD_REQUEST, ErrorCode::Unsupported, None)
            }
            registry::Error::RangeNotSatisfiable => oci_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                ErrorCode::SizeInvalid,
                None,
            ),
            // A refused write (an immutable tag, a concurrent-writer CAS
            // conflict): HTTP 409 so the client retries, under the spec code
            // closest to a rejected write.
            registry::Error::Conflict(msg) => {
                oci_error(StatusCode::CONFLICT, ErrorCode::Denied, Some(msg))
            }
            // The one code outside the spec's set, and the only one a client
            // never sees: it answers a replication write, which angos marks with
            // its own header and whose sender reads this code to converge.
            registry::Error::ReplicationSuperseded(msg) => {
                angos_error(StatusCode::CONFLICT, REPLICATION_SUPERSEDED_CODE, Some(msg))
            }
            registry::Error::EventDelivery(msg) => Error::Execution(msg),
            // Corrupt content is a 500 like any other internal failure; only
            // the reclaim paths inside angos act on the distinction.
            registry::Error::Internal(msg) | registry::Error::Corrupt(msg) => angos_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR_CODE,
                Some(msg),
            ),
            // Every remaining variant is an opaque server-side failure with no
            // client-actionable OCI code. Matched exhaustively (no catch-all) so
            // a newly added variant must be mapped deliberately here.
            registry::Error::Configuration(_)
            | registry::Error::Cache(_)
            | registry::Error::Io(_)
            | registry::Error::Http(_)
            | registry::Error::Serde(_)
            | registry::Error::PolicyExecution(_)
            | registry::Error::InvalidHeader(_)
            | registry::Error::InvalidUri(_)
            | registry::Error::Serialization(_) => angos_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR_CODE,
                Some(error.to_string()),
            ),
        }
    }
}

impl From<auth::Error> for Error {
    fn from(e: auth::Error) -> Self {
        match e {
            auth::Error::Initialization(msg) => Error::Initialization(msg),
            auth::Error::Execution(msg) => Error::Execution(msg),
            auth::Error::Unauthorized(msg) => Error::Unauthorized(msg),
            auth::Error::ProviderUnavailable(msg) => Error::ProviderUnavailable(msg),
            // A registry error the authorizer surfaced keeps its OCI mapping.
            auth::Error::Registry(inner) => Error::from(*inner),
        }
    }
}

impl From<bootstrap::Error> for Error {
    fn from(e: bootstrap::Error) -> Self {
        match e {
            bootstrap::Error::StorageBackend(inner) | bootstrap::Error::Coordination(inner) => {
                Error::Initialization(format!("Failed to initialize storage handles: {inner}"))
            }
            bootstrap::Error::Cache(inner) => {
                Error::Initialization(format!("Failed to initialize auth token cache: {inner}"))
            }
            bootstrap::Error::Repository { name, source } => Error::Initialization(format!(
                "Failed to initialize repository '{name}': {source}"
            )),
            bootstrap::Error::Overlap(inner) => Error::Initialization(inner.to_string()),
            bootstrap::Error::JobQueue(inner) => {
                Error::Initialization(format!("Failed to initialize job queue: {inner}"))
            }
            bootstrap::Error::EventWebhook(inner) => {
                Error::Initialization(format!("Failed to initialize event webhooks: {inner}"))
            }
            bootstrap::Error::Registry(inner) => {
                Error::Initialization(format!("Failed to initialize registry: {inner}"))
            }
        }
    }
}

impl From<job_store::Error> for Error {
    fn from(e: job_store::Error) -> Self {
        Error::Initialization(e.to_string())
    }
}

impl From<metrics_provider::Error> for Error {
    fn from(error: metrics_provider::Error) -> Self {
        match error {
            metrics_provider::Error::Initialization(msg) => Error::Initialization(msg),
            metrics_provider::Error::Encode(msg) => Error::Internal(msg),
        }
    }
}

impl From<configuration::Error> for Error {
    fn from(error: configuration::Error) -> Self {
        match error {
            configuration::Error::Initialization(msg)
            | configuration::Error::InvalidFormat(msg)
            | configuration::Error::NotReadable(msg) => Error::Internal(msg),
        }
    }
}

impl From<event_webhook::Error> for Error {
    fn from(error: event_webhook::Error) -> Self {
        match error {
            event_webhook::Error::Initialization(msg) => Error::Initialization(msg),
            event_webhook::Error::Dispatch(msg) => Error::Execution(msg),
        }
    }
}
