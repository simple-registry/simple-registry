use crate::error::RegistryError;
use rustls_pki_types::pem;
use std::{fmt, io};

#[derive(Debug)]
pub enum CommandError {
    IO(io::Error),
    TLSError(String),
    ConfigurationError(String),
    RegistryError(RegistryError),
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CommandError::IO(err) => write!(f, "IO error: {}", err),
            CommandError::TLSError(err) => write!(f, "TLS error: {}", err),
            CommandError::ConfigurationError(err) => write!(f, "Configuration error: {}", err),
            CommandError::RegistryError(err) => write!(f, "Registry error: {}", err),
        }
    }
}

impl From<io::Error> for CommandError {
    fn from(err: io::Error) -> Self {
        CommandError::IO(err)
    }
}

impl From<notify::Error> for CommandError {
    fn from(err: notify::Error) -> Self {
        CommandError::ConfigurationError(err.to_string())
    }
}

impl From<RegistryError> for CommandError {
    fn from(err: RegistryError) -> Self {
        CommandError::RegistryError(err)
    }
}

impl From<rustls::Error> for CommandError {
    fn from(err: rustls::Error) -> Self {
        CommandError::TLSError(err.to_string())
    }
}

impl From<rustls::server::VerifierBuilderError> for CommandError {
    fn from(err: rustls::server::VerifierBuilderError) -> Self {
        CommandError::TLSError(err.to_string())
    }
}

impl From<pem::Error> for CommandError {
    fn from(err: pem::Error) -> Self {
        CommandError::TLSError(err.to_string())
    }
}
