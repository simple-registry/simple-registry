use crate::registry::{cache, task_queue};
use hyper::header::InvalidHeaderValue;
use opentelemetry_otlp::ExporterBuildError;
use opentelemetry_sdk::trace::TraceError;
use rustls_pki_types::pem;
use std::{fmt, io};
use tracing::debug;

#[derive(Debug)]
pub enum Error {
    Cache(cache::Error),
    MetadataStore(String),
    Io(io::Error),
    MissingExpectedTLSSection(String),
    ConfigurationFileFormat(String),
    StreamingChunkSize(String),
    Http(String),
    TaskQueue(task_queue::Error),
    Tls(String),
    TracingInit(TraceError),
    ExporterInit(ExporterBuildError),
    CELPolicy(cel_interpreter::ParseErrors),
    PolicyCompilation(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Cache(err) => write!(f, "Cache error: {err}"),
            Error::MetadataStore(err) => write!(f, "Metadata store error: {err}"),
            Error::Io(err) => write!(f, "IO error: {err}"),
            Error::MissingExpectedTLSSection(error) => {
                write!(f, "Missing expected TLS section: {error}")
            }
            Error::ConfigurationFileFormat(error) => {
                write!(f, "Configuration file format error.")?;
                write!(f, "{error}")
            }
            Error::StreamingChunkSize(error) => {
                write!(f, "Streaming chunk size error: {error}")
            }
            Error::Http(error) => {
                write!(f, "HTTP error: {error}")
            }
            Error::TaskQueue(error) => {
                write!(f, "Task queue error: {error}")
            }
            Error::Tls(error) => {
                write!(f, "TLS error: {error}")
            }
            Error::TracingInit(error) => {
                write!(f, "Tracing initialization error: {error}")
            }
            Error::ExporterInit(error) => {
                write!(f, "Exporter initialization error: {error}")
            }
            Error::CELPolicy(error) => {
                write!(f, "CEL policy error")?;
                write!(f, "{error}")
            }
            Error::PolicyCompilation(msg) => {
                write!(f, "Policy compilation error: {msg}")
            }
        }
    }
}

impl From<cache::Error> for Error {
    fn from(error: cache::Error) -> Self {
        debug!("Cache error: {error}");
        Error::Cache(error)
    }
}

impl From<task_queue::Error> for Error {
    fn from(error: task_queue::Error) -> Self {
        debug!("Task queue error: {error}");
        Error::TaskQueue(error)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<toml::de::Error> for Error {
    fn from(error: toml::de::Error) -> Self {
        debug!("TOML error: {error}");
        Error::ConfigurationFileFormat(error.to_string())
    }
}

impl From<InvalidHeaderValue> for Error {
    fn from(error: InvalidHeaderValue) -> Self {
        Error::Http(format!("{error}"))
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

impl From<ExporterBuildError> for Error {
    fn from(error: ExporterBuildError) -> Self {
        Error::ExporterInit(error)
    }
}

impl From<cel_interpreter::ParseErrors> for Error {
    fn from(error: cel_interpreter::ParseErrors) -> Self {
        Error::CELPolicy(error)
    }
}
