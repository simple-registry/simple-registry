use crate::registry::{data_store, lock_store};
use crate::{configuration, registry};
use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    Watcher(String),
    Configuration(configuration::Error),
    Registry(registry::Error),
    DataStore(data_store::Error),
    LockStore(lock_store::Error),
    Std(Box<dyn std::error::Error>),
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
            Error::DataStore(err) => {
                write!(f, "Data store error")?;
                write!(f, "{err}")
            }
            Error::LockStore(err) => {
                write!(f, "Lock store error")?;
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

impl From<data_store::Error> for Error {
    fn from(err: data_store::Error) -> Self {
        Error::DataStore(err)
    }
}

impl From<lock_store::Error> for Error {
    fn from(err: lock_store::Error) -> Self {
        Error::LockStore(err)
    }
}

impl From<Box<dyn std::error::Error>> for Error {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        Error::Std(err)
    }
}
