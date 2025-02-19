use crate::registry::Error;
use hyper::header::HeaderName;
use hyper::Request;
use lazy_static::lazy_static;
use regex::Regex;
use serde::de::DeserializeOwned;
use tracing::warn;

lazy_static! {
    static ref RANGE_RE: Regex = Regex::new(r"^(?:bytes=)?(?P<start>\d+)-(?P<end>\d+)$").unwrap();
}

pub trait RequestExt {
    fn query_parameters<D: DeserializeOwned + Default>(&self) -> Result<D, Error>;

    fn range(&self, header_name: HeaderName) -> Result<Option<(u64, u64)>, Error>;
}

impl<T> RequestExt for Request<T> {
    fn query_parameters<D: DeserializeOwned + Default>(&self) -> Result<D, Error> {
        let Some(query) = self.uri().query() else {
            return Ok(Default::default());
        };

        serde_urlencoded::from_str(query).map_err(|e| {
            warn!("Failed to parse query parameters: {}", e);
            Error::Unsupported
        })
    }

    fn range(&self, header: HeaderName) -> Result<Option<(u64, u64)>, Error> {
        let Some(range_header) = self.headers().get(header) else {
            return Ok(None);
        };

        let range_str = range_header.to_str().map_err(|e| {
            warn!("Error parsing Range header as string: {}", e);
            Error::RangeNotSatisfiable
        })?;

        let captures = RANGE_RE.captures(range_str).ok_or_else(|| {
            warn!("Invalid Range header format: {}", range_str);
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

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::RANGE;
    use std::collections::HashMap;

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
}
