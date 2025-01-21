use hyper::header::InvalidHeaderValue;
use opentelemetry::trace::TraceError;
use rustls_pki_types::pem;
use std::{fmt, io};
use tracing::debug;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    StorageBackend(String),
    MissingExpectedTLSSection(String),
    ConfigurationFileFormat(String),
    StreamingChunkSize(String),
    LockManagerInit(String),
    Http(String),
    Tls(String),
    TracingInit(TraceError),
    CELPolicy(cel_interpreter::ParseError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "IO error: {err}"),
            Error::StorageBackend(err) => {
                write!(f, "Storage backend error: {err}")
            }
            Error::MissingExpectedTLSSection(err) => {
                write!(f, "Missing expected TLS section: {err}")
            }
            Error::ConfigurationFileFormat(err) => {
                write!(f, "Configuration file format error.")?;
                write!(f, "{}", err.as_str())
            }
            Error::StreamingChunkSize(err) => {
                write!(f, "Streaming chunk size error: {err}")
            }
            Error::LockManagerInit(err) => {
                write!(f, "Lock manager initialization error: {err}")
            }
            Error::Http(err) => {
                write!(f, "HTTP error: {err}")
            }
            Error::Tls(err) => {
                write!(f, "TLS error: {err}")
            }
            Error::TracingInit(err) => {
                write!(f, "Tracing initialization error: {err}")
            }
            Error::CELPolicy(err) => {
                write!(f, "CEL policy error")?;
                write!(f, "{err}")
            }
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<toml::de::Error> for Error {
    fn from(error: toml::de::Error) -> Self {
        debug!("TOML error: {error:?}");
        Error::ConfigurationFileFormat("TOML deserialization error during operations".to_string())
    }
}

impl From<InvalidHeaderValue> for Error {
    fn from(err: InvalidHeaderValue) -> Self {
        Error::Http(format!("{err:?}"))
    }
}

impl From<rustls::Error> for Error {
    fn from(err: rustls::Error) -> Self {
        Error::Tls(err.to_string())
    }
}

impl From<rustls::server::VerifierBuilderError> for Error {
    fn from(err: rustls::server::VerifierBuilderError) -> Self {
        Error::Tls(err.to_string())
    }
}

impl From<pem::Error> for Error {
    fn from(err: pem::Error) -> Self {
        Error::Tls(err.to_string())
    }
}

impl From<TraceError> for Error {
    fn from(error: TraceError) -> Self {
        Error::TracingInit(error)
    }
}

impl From<cel_interpreter::ParseError> for Error {
    fn from(error: cel_interpreter::ParseError) -> Self {
        Error::CELPolicy(error)
    }
}
