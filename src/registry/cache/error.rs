use redis::RedisError;
use std::fmt;
use tracing::debug;

#[derive(Debug, PartialEq)]
pub enum Error {
    StorageError(String),
    NotFound,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::StorageError(err) => write!(f, "Storage error: {err}"),
            Error::NotFound => write!(f, "Not found"),
        }
    }
}

impl From<RedisError> for Error {
    fn from(error: RedisError) -> Self {
        let error = format!("Redis error: {error}");
        debug!("{error}");
        Error::StorageError(error)
    }
}
