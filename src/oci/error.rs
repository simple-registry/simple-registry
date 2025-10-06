use std::fmt::Display;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidFormat(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidFormat(s) => write!(f, "Invalid format: {s}"),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::InvalidFormat(format!("{e}"))
    }
}
