use redis::RedisError;
use std::fmt;
use tracing::warn;

#[derive(Debug, PartialEq)]
pub enum Error {
    Backend(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Backend(err) => write!(f, "{err}"),
        }
    }
}

impl From<RedisError> for Error {
    fn from(error: RedisError) -> Self {
        warn!("Redis backend error: {error}");
        Error::Backend("Backend error".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::RedisError;

    #[test]
    fn test_error_display() {
        let backend_error = Error::Backend("Some backend error".to_string());
        assert_eq!(format!("{backend_error}"), "Some backend error");
    }

    #[test]
    fn test_from_redis_error() {
        let redis_error = RedisError::from((redis::ErrorKind::IoError, "IO error occurred"));
        let error: Error = redis_error.into();
        assert_eq!(error, Error::Backend("Backend error".to_string()));
    }
}
