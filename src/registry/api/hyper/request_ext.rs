use crate::registry::Error;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use hyper::header::{AsHeaderName, HeaderName, ACCEPT, AUTHORIZATION};
use hyper::Request;
use lazy_static::lazy_static;
use regex::Regex;
use serde::de::DeserializeOwned;
use std::io;
use tokio::io::AsyncRead;
use tokio_util::io::StreamReader;
use tracing::{debug, error, warn};

lazy_static! {
    static ref RANGE_RE: Regex = Regex::new(r"^(?:bytes=)?(?P<start>\d+)-(?P<end>\d+)$").unwrap();
}

pub trait RequestExt {
    fn get_header<K: AsHeaderName>(&self, header: K) -> Option<String>;
    fn query_parameters<D: DeserializeOwned + Default>(&self) -> Result<D, Error>;

    fn provided_credentials(&self) -> Option<(String, String)>;

    fn accepted_content_types(&self) -> Vec<String>;

    fn range(&self, header_name: HeaderName) -> Result<Option<(u64, u64)>, Error>;
}

impl<T> RequestExt for Request<T> {
    fn get_header<K>(&self, header: K) -> Option<String>
    where
        K: AsHeaderName,
    {
        self.headers()
            .get(header)
            .and_then(|header| header.to_str().ok())
            .map(ToString::to_string)
    }

    fn query_parameters<D: DeserializeOwned + Default>(&self) -> Result<D, Error> {
        let Some(query) = self.uri().query() else {
            return Ok(Default::default());
        };

        serde_urlencoded::from_str(query).map_err(|e| {
            warn!("Failed to parse query parameters: {}", e);
            Error::Unsupported
        })
    }

    fn provided_credentials(&self) -> Option<(String, String)> {
        let Some(authorization) = self.get_header(AUTHORIZATION) else {
            debug!("No authorization header found");
            return None;
        };

        error!("Authorization header: {authorization}");
        let value = authorization.strip_prefix("Basic ")?;
        let value = BASE64_STANDARD.decode(value).ok()?;
        let value = String::from_utf8(value).ok()?;

        let (username, password) = value.split_once(':')?;
        Some((username.to_string(), password.to_string()))
    }

    fn accepted_content_types(&self) -> Vec<String> {
        self.headers()
            .get_all(ACCEPT)
            .iter()
            .filter_map(|h| h.to_str().ok())
            .map(ToString::to_string)
            .collect()
    }

    fn range(&self, header: HeaderName) -> Result<Option<(u64, u64)>, Error> {
        let Some(range_header) = self.get_header(header) else {
            return Ok(None);
        };

        let captures = RANGE_RE.captures(&range_header).ok_or_else(|| {
            warn!("Invalid Range header format: {}", range_header);
            Error::RangeNotSatisfiable
        })?;

        let (Some(start), Some(end)) = (captures.name("start"), captures.name("end")) else {
            return Err(Error::RangeNotSatisfiable);
        };

        let start = start.as_str().parse::<u64>().map_err(|e| {
            warn!("Error parsing 'start' in Range header: {}", e);
            Error::RangeNotSatisfiable
        })?;

        let end = end.as_str().parse::<u64>().map_err(|e| {
            warn!("Error parsing 'end' in Range header: {}", e);
            Error::RangeNotSatisfiable
        })?;

        if start > end {
            warn!(
                "Range start ({}) is greater than range end ({})",
                start, end
            );
            return Err(Error::RangeNotSatisfiable);
        }

        Ok(Some((start, end)))
    }
}

pub trait IntoAsyncRead {
    fn into_async_read(self) -> impl AsyncRead;
}

impl<S> IntoAsyncRead for Request<S>
where
    S: BodyExt,
    S::Error: Sync + Send + std::error::Error + 'static,
{
    fn into_async_read(self) -> impl AsyncRead {
        let stream = self
            .into_data_stream()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));
        StreamReader::new(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::api::body::Body;
    use hyper::header::{HeaderValue, RANGE};
    use std::collections::HashMap;
    use tokio::io::AsyncReadExt;

    #[test]
    fn test_query_parameters() {
        let request = Request::builder()
            .uri("http://localhost:8080/?foo=bar&baz=qux")
            .body(())
            .unwrap();

        let query_parameters: HashMap<String, String> = request.query_parameters().unwrap();
        assert_eq!(query_parameters.len(), 2);
        assert_eq!(query_parameters.get("foo"), Some(&"bar".to_string()));
        assert_eq!(query_parameters.get("baz"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_parse_authorization_header() {
        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Basic dXNlcjpwYXNzd29yZA=="),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            request.provided_credentials(),
            Some(("user".to_string(), "password".to_string()))
        );

        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Bearer dXNlcjpwYXNzd29yZA=="),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(request.provided_credentials(), None);

        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Basic dXNlcjpw YXNzd29yZA="),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(request.provided_credentials(), None);

        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Basic dXNlcjpwY%%%%XNzd29yZA"),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(request.provided_credentials(), None);

        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Basic dXNlcjpwYXNzd29yZA==="),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(request.provided_credentials(), None);

        let request = Request::builder()
            .header(
                AUTHORIZATION,
                HeaderValue::from_static("Basic dXNlcjpwYXNzd29yZA=="),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            request.provided_credentials(),
            Some(("user".to_string(), "password".to_string()))
        );
    }

    #[test]
    fn test_get_accepted_content_type() {
        let request = Request::builder()
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(ACCEPT, HeaderValue::from_static("application/xml"))
            .header(ACCEPT, HeaderValue::from_static("text/plain"));
        let request = request.body(Body::empty()).unwrap();

        let result = request.accepted_content_types();
        assert_eq!(
            result,
            vec!["application/json", "application/xml", "text/plain"]
        );
    }

    #[test]
    fn test_range() {
        let request = Request::builder()
            .header(RANGE, "bytes=0-499")
            .body(())
            .unwrap();

        let range = request.range(RANGE).unwrap().unwrap();
        assert_eq!(range, (0, 499));
    }

    #[test]
    fn test_range_invalid() {
        let request = Request::builder()
            .header(RANGE, "bytes=500-499")
            .body(())
            .unwrap();

        let range = request.range(RANGE);
        assert!(range.is_err());

        let request = Request::builder()
            .header(RANGE, "bytes=0-")
            .body(())
            .unwrap();

        let range = request.range(RANGE);
        assert!(range.is_err());

        let request = Request::builder()
            .header(RANGE, "bytes=-499")
            .body(())
            .unwrap();

        let range = request.range(RANGE);
        assert!(range.is_err());

        let request = Request::builder()
            .header(RANGE, "bytes=plouf")
            .body(())
            .unwrap();

        let range = request.range(RANGE);
        assert!(range.is_err());
    }

    #[tokio::test]
    async fn test_into_async_read() {
        let mut request = Request::builder()
            .body(String::from("Hello World!"))
            .unwrap()
            .into_async_read();

        let mut buf = Vec::new();
        request.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"Hello World!");
    }
}
