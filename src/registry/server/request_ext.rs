use crate::registry::Error;
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{AsHeaderName, HeaderName, ACCEPT, AUTHORIZATION};
use hyper::http::request::Parts;
use regex::Regex;
use std::io;
use std::sync::LazyLock;
use tokio::io::AsyncRead;
use tokio_util::io::StreamReader;
use tracing::warn;

static RANGE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:bytes=)?(?P<start>\d+)-(?P<end>\d+)?$").unwrap());

pub trait HeaderExt {
    fn get_header<K: AsHeaderName>(&self, header: K) -> Option<String>;
    fn range(&self, header: HeaderName) -> Result<Option<(u64, Option<u64>)>, Error>;
    fn accepted_content_types(&self) -> Vec<String>;
    fn bearer_token(&self) -> Option<String>;
}

impl HeaderExt for Parts {
    fn get_header<K>(&self, header: K) -> Option<String>
    where
        K: AsHeaderName,
    {
        self.headers
            .get(header)
            .and_then(|header| header.to_str().ok())
            .map(ToString::to_string)
    }

    fn range(&self, header: HeaderName) -> Result<Option<(u64, Option<u64>)>, Error> {
        let Some(range_header) = self.get_header(header) else {
            return Ok(None);
        };

        let captures = RANGE_RE.captures(&range_header).ok_or_else(|| {
            warn!("Invalid Range header format: {range_header}");
            Error::RangeNotSatisfiable
        })?;

        let (Some(start), end) = (captures.name("start"), captures.name("end")) else {
            return Err(Error::RangeNotSatisfiable);
        };

        let start = start.as_str().parse::<u64>().map_err(|error| {
            warn!("Error parsing 'start' in Range header: {error}");
            Error::RangeNotSatisfiable
        })?;

        if let Some(end) = end {
            let end = end.as_str().parse::<u64>().map_err(|error| {
                warn!("Error parsing 'end' in Range header: {error}");
                Error::RangeNotSatisfiable
            })?;

            if start > end {
                warn!("Range start ({start}) is greater than range end ({end})");
                return Err(Error::RangeNotSatisfiable);
            }

            Ok(Some((start, Some(end))))
        } else {
            Ok(Some((start, None)))
        }
    }

    fn accepted_content_types(&self) -> Vec<String> {
        self.headers
            .get_all(ACCEPT)
            .iter()
            .filter_map(|h| h.to_str().ok())
            .map(ToString::to_string)
            .collect()
    }

    fn bearer_token(&self) -> Option<String> {
        let authorization = self.get_header(AUTHORIZATION)?;
        authorization
            .strip_prefix("Bearer ")
            .map(std::string::ToString::to_string)
    }
}

pub trait IntoAsyncRead {
    fn into_async_read(self) -> impl AsyncRead;
}

impl IntoAsyncRead for Incoming {
    fn into_async_read(self) -> impl AsyncRead {
        let stream = self.into_data_stream().map_err(io::Error::other);
        StreamReader::new(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ResponseBody;
    use hyper::header::{HeaderValue, RANGE};
    use hyper::Request;

    #[test]
    fn test_get_accepted_content_type() {
        let request = Request::builder()
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(ACCEPT, HeaderValue::from_static("application/xml"))
            .header(ACCEPT, HeaderValue::from_static("text/plain"));
        let request = request.body(ResponseBody::empty()).unwrap();
        let (parts, _) = request.into_parts();

        let result = parts.accepted_content_types();
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
        let (parts, ()) = request.into_parts();

        let range = parts.range(RANGE).unwrap().unwrap();
        assert_eq!(range, (0, Some(499)));
    }

    #[test]
    fn test_range_no_end() {
        let request = Request::builder()
            .header(RANGE, "bytes=0-")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let range = parts.range(RANGE).unwrap().unwrap();
        assert_eq!(range, (0, None));
    }

    #[test]
    fn test_range_invalid() {
        let request = Request::builder()
            .header(RANGE, "bytes=500-499")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let range = parts.range(RANGE);
        assert!(range.is_err());

        let request = Request::builder()
            .header(RANGE, "bytes=-499")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let range = parts.range(RANGE);
        assert!(range.is_err());

        let request = Request::builder()
            .header(RANGE, "bytes=plouf")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let range = parts.range(RANGE);
        assert!(range.is_err());
    }
}
