use crate::error::RegistryError;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use hyper::header::HeaderValue;
use lazy_static::lazy_static;
use regex::Regex;
use serde::de::DeserializeOwned;
use tracing::{debug, warn};

lazy_static! {
    static ref RANGE_RE: Regex = Regex::new(r"^(?:bytes=)?(?P<start>\d+)-(?P<end>\d+)$").unwrap();
}

pub fn parse_authorization_header(header: &HeaderValue) -> Option<(String, String)> {
    let Ok(header_str) = header.to_str() else {
        debug!("Error parsing Authorization header as string");
        return None;
    };

    let parts: Vec<&str> = header_str.split_whitespace().collect();
    if parts.len() != 2 {
        debug!("Invalid Authorization header format: {}", header_str);
        return None;
    }

    if parts[0] != "Basic" {
        debug!("Invalid Authorization header type: {}", parts[0]);
        return None;
    }

    let Ok(auth_details) = BASE64_STANDARD.decode(parts[1]) else {
        debug!("Error decoding Authorization header");
        return None;
    };

    let Ok(auth_str) = String::from_utf8(auth_details) else {
        debug!("Error parsing Authorization header as UTF8 string");
        return None;
    };

    let parts: Vec<&str> = auth_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        warn!("Invalid Authorization header format: {}", auth_str);
        return None;
    }

    Some((parts[0].to_string(), parts[1].to_string()))
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
