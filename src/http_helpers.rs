use crate::error::RegistryError;
use crate::RegistryResponseBody;
use hyper::header::HeaderValue;
use hyper::{Response, StatusCode};
use lazy_static::lazy_static;
use log::warn;
use regex::Regex;
use serde::de::DeserializeOwned;

lazy_static! {
    static ref RANGE_RE: Regex = Regex::new(r"^(?:bytes=)?(?P<start>\d+)-(?P<end>\d+)$").unwrap();
}

pub fn parse_range_header(range_header: &HeaderValue) -> Result<(u64, u64), RegistryError> {
    let range_str = range_header.to_str().map_err(|e| {
        warn!("Error parsing Range header as string: {}", e);
        RegistryError::RangeNotSatisfiable
    })?;

    let captures = RANGE_RE.captures(range_str).ok_or_else(|| {
        warn!("Invalid Range header format: {}", range_str);
        RegistryError::RangeNotSatisfiable
    })?;

    let (Some(start), Some(end)) = (captures.name("start"), captures.name("end")) else {
        return Err(RegistryError::RangeNotSatisfiable);
    };

    let start = start.as_str().parse::<u64>().map_err(|e| {
        warn!("Error parsing 'start' in Range header: {}", e);
        RegistryError::RangeNotSatisfiable
    })?;

    let end = end.as_str().parse::<u64>().map_err(|e| {
        warn!("Error parsing 'end' in Range header: {}", e);
        RegistryError::RangeNotSatisfiable
    })?;

    if start > end {
        warn!(
            "Range start ({}) is greater than range end ({})",
            start, end
        );
        return Err(RegistryError::RangeNotSatisfiable);
    }

    Ok((start, end))
}

pub fn parse_query_parameters<T: DeserializeOwned + Default>(
    query: Option<&str>,
) -> Result<T, RegistryError> {
    let Some(query) = query else {
        return Ok(Default::default());
    };

    serde_urlencoded::from_str(query).map_err(|e| {
        warn!("Failed to parse query parameters: {}", e);
        RegistryError::Unsupported
    })
}

pub fn paginated_response(
    body: String,
    link: Option<String>,
) -> Result<Response<RegistryResponseBody>, RegistryError> {
    let res = match link {
        Some(link) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .header("Link", format!("<{}>; rel=\"next\"", link))
            .body(RegistryResponseBody::fixed(body.into_bytes()))?,
        None => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(RegistryResponseBody::fixed(body.into_bytes()))?,
    };

    Ok(res)
}
