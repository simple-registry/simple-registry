use crate::{configuration, registry};
use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    Watcher(String),
    Configuration(configuration::Error),
    Registry(registry::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
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
