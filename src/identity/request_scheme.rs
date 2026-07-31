/// The scheme a request was served on, recorded by the listener as a request
/// extension.
///
/// HTTP/1.1 sends origin-form request targets, which carry no scheme, so the
/// URI alone cannot tell a TLS request from a plaintext one. Only the listener
/// knows, so it states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestScheme {
    Http,
    Https,
}

impl RequestScheme {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}
