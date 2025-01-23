use redis::RedisError;
use std::fmt;
use tracing::debug;

#[derive(Debug, PartialEq)]
pub enum Error {
    BackendError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BackendError(err) => write!(f, "Storage error: {err}"),
        }
    }
}

impl From<RedisError> for Error {
    fn from(error: RedisError) -> Self {
        let error = format!("Redis error: {error:?}");
        debug!("{error}");
        Error::BackendError(error)
    }
}
