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
