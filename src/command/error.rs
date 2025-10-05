use crate::registry::{blob_store, metadata_store};
use crate::{configuration, registry};
use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    Fatal(String),
    IO(io::Error),
    Watcher(String),
    Configuration(configuration::Error),
    Registry(registry::Error),
    MetadataStore(metadata_store::Error),
    BlobStore(blob_store::Error),
    Std(Box<dyn std::error::Error>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Fatal(msg) => write!(f, "Fatal error: {msg}"),
            Error::IO(err) => write!(f, "IO error: {err}"),
            Error::Watcher(err) => write!(f, "Watcher error: {err}"),
            Error::Configuration(err) => {
                write!(f, "Configuration error:")?;
                write!(f, "{err}")
            }
            Error::Registry(err) => {
                write!(f, "Registry error")?;
                write!(f, "{err}")
            }
            Error::MetadataStore(err) => {
                write!(f, "Metadata store error")?;
                write!(f, "{err}")
            }
            Error::BlobStore(err) => {
                write!(f, "Blob store error")?;
                write!(f, "{err}")
            }
            Error::Std(err) => {
                write!(f, "Standard error")?;
                write!(f, "{err}")
            }
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err)
    }
}

impl From<notify::Error> for Error {
    fn from(err: notify::Error) -> Self {
        Error::Watcher(err.to_string())
    }
}

impl From<configuration::Error> for Error {
    fn from(err: configuration::Error) -> Self {
        Error::Configuration(err)
    }
}

impl From<registry::Error> for Error {
    fn from(err: registry::Error) -> Self {
        Error::Registry(err)
    }
}

impl From<metadata_store::Error> for Error {
    fn from(err: metadata_store::Error) -> Self {
        Error::MetadataStore(err)
    }
}

impl From<blob_store::Error> for Error {
    fn from(err: blob_store::Error) -> Self {
        Error::BlobStore(err)
    }
}

impl From<Box<dyn std::error::Error>> for Error {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        Error::Std(err)
    }
}
