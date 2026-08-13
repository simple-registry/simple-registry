//! Byte ranges on the wire: the window a client asks for in a `Range` header,
//! and the window a `206` reports in `Content-Range`. Parsing and formatting
//! both live here so the registry, the request layer, and the upstream client
//! read and write one grammar.

use std::{fmt::Display, str::FromStr};

use hyper::header::{HeaderValue, InvalidHeaderValue};

static BYTES_RANGE_PREFIX: &str = "bytes=";
static BYTES_CONTENT_PREFIX: &str = "bytes ";
/// The `Content-Range` complete length of a body whose total size is unknown.
static UNKNOWN_TOTAL_LENGTH: &str = "*";

/// Why a range could not be read or served. Every variant is a `416` to the
/// client, so callers map it onto their own not-satisfiable error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Malformed(String),
    #[error("the requested range cannot be satisfied")]
    Unsatisfiable,
}

fn malformed(value: &str) -> Error {
    Error::Malformed(format!("Invalid Range header format: '{value}'"))
}

fn is_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_number(value: &str, part: &str) -> Result<u64, Error> {
    value.parse::<u64>().map_err(|error| {
        Error::Malformed(format!("Error parsing '{part}' in Range header: {error}"))
    })
}

/// Parses a `start-end` value where `end` is optional (`100-200`, `0-`).
fn parse_start_end(value: &str) -> Result<RequestRange, Error> {
    let (start, end) = value
        .split_once('-')
        .filter(|(start, end)| is_digits(start) && (end.is_empty() || is_digits(end)))
        .ok_or_else(|| malformed(value))?;

    let start = parse_number(start, "start")?;
    if end.is_empty() {
        return Ok(RequestRange::FromTo { start, end: None });
    }

    let end = parse_number(end, "end")?;
    if start > end {
        return Err(Error::Malformed(format!(
            "Invalid Range header: start ({start}) > end ({end})"
        )));
    }

    Ok(RequestRange::FromTo {
        start,
        end: Some(end),
    })
}

fn strip_bytes_prefix(value: &str) -> Option<&str> {
    if value.len() < BYTES_RANGE_PREFIX.len() {
        return None;
    }

    let (prefix, range_value) = value.split_at(BYTES_RANGE_PREFIX.len());
    prefix
        .eq_ignore_ascii_case(BYTES_RANGE_PREFIX)
        .then_some(range_value)
}

/// A single byte range as a client asks for it: an explicit window, open-ended
/// when `end` is absent, or a suffix length anchored to the end of the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestRange {
    FromTo { start: u64, end: Option<u64> },
    Suffix(u64),
}

impl RequestRange {
    /// Parses a `Range` header value. `None` is a multi-range request, which is
    /// answered with the whole body rather than refused.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a value without the `bytes=` unit, with a
    /// non-numeric bound, or with an end before its start.
    pub fn parse(value: &str) -> Result<Option<Self>, Error> {
        let Some(range_value) = strip_bytes_prefix(value) else {
            return Err(malformed(value));
        };

        if range_value.contains(',') {
            return Ok(None);
        }

        if let Some(suffix) = range_value.strip_prefix('-') {
            if !is_digits(suffix) {
                return Err(malformed(value));
            }
            return Ok(Some(RequestRange::Suffix(parse_number(suffix, "suffix")?)));
        }

        parse_start_end(range_value).map(Some)
    }

    /// Parses an upload offset, where the `bytes=` unit is optional: chunked
    /// upload clients send the offset both bare and prefixed. Only the explicit
    /// `start-end` form is accepted, a suffix being meaningless for an offset.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a non-numeric bound or an end before its start.
    pub fn parse_offset(value: &str) -> Result<Self, Error> {
        parse_start_end(strip_bytes_prefix(value).unwrap_or(value))
    }

    /// The first byte asked for, absent on a suffix range: that one is anchored
    /// to the end of a body whose length the caller may not know yet.
    pub fn start(self) -> Option<u64> {
        match self {
            RequestRange::FromTo { start, .. } => Some(start),
            RequestRange::Suffix(_) => None,
        }
    }

    /// Resolves the requested window against a known body length, clamping an
    /// end past the last byte and a suffix longer than the body. `None` means
    /// the range is to be ignored, as an empty body has no window to serve.
    ///
    /// # Errors
    ///
    /// [`Error::Unsatisfiable`] for a start at or past the body length, an
    /// inverted window, or a zero-length suffix.
    pub fn resolve(self, total_length: u64) -> Result<Option<ResponseRange>, Error> {
        if total_length == 0 {
            return Ok(None);
        }

        let last_byte = total_length - 1;
        let (start, end) = match self {
            RequestRange::FromTo { start, end } => {
                if start >= total_length {
                    return Err(Error::Unsatisfiable);
                }

                let end = end.unwrap_or(last_byte).min(last_byte);
                if end < start {
                    return Err(Error::Unsatisfiable);
                }

                (start, end)
            }
            RequestRange::Suffix(suffix_length) => {
                if suffix_length == 0 {
                    return Err(Error::Unsatisfiable);
                }

                let length = suffix_length.min(total_length);
                (total_length - length, last_byte)
            }
        };

        Ok(Some(ResponseRange {
            start,
            end,
            total_length: Some(total_length),
        }))
    }
}

impl Display for RequestRange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestRange::FromTo {
                start,
                end: Some(end),
            } => write!(formatter, "{BYTES_RANGE_PREFIX}{start}-{end}"),
            RequestRange::FromTo { start, end: None } => {
                write!(formatter, "{BYTES_RANGE_PREFIX}{start}-")
            }
            RequestRange::Suffix(length) => write!(formatter, "{BYTES_RANGE_PREFIX}-{length}"),
        }
    }
}

impl TryFrom<RequestRange> for HeaderValue {
    type Error = InvalidHeaderValue;

    fn try_from(range: RequestRange) -> Result<Self, Self::Error> {
        HeaderValue::try_from(range.to_string())
    }
}

/// The window a `206` serves. `total_length` is absent when the complete length
/// is unknown, which `Content-Range` spells `*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseRange {
    pub start: u64,
    pub end: u64,
    pub total_length: Option<u64>,
}

impl ResponseRange {
    /// The number of bytes served, `end` being inclusive.
    pub fn length(self) -> u64 {
        self.end - self.start + 1
    }
}

impl FromStr for ResponseRange {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let window = value
            .strip_prefix(BYTES_CONTENT_PREFIX)
            .ok_or_else(|| malformed(value))?;
        let (window, total_length) = window.split_once('/').ok_or_else(|| malformed(value))?;
        let total_length = if total_length == UNKNOWN_TOTAL_LENGTH {
            None
        } else {
            Some(parse_number(total_length, "complete length")?)
        };

        match parse_start_end(window)? {
            RequestRange::FromTo {
                start,
                end: Some(end),
            } => Ok(ResponseRange {
                start,
                end,
                total_length,
            }),
            // `parse_start_end` accepts the open-ended form a request may use;
            // a served window always names its last byte.
            _ => Err(malformed(value)),
        }
    }
}

impl Display for ResponseRange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{BYTES_CONTENT_PREFIX}{}-{}/",
            self.start, self.end
        )?;
        match self.total_length {
            Some(total_length) => write!(formatter, "{total_length}"),
            None => write!(formatter, "{UNKNOWN_TOTAL_LENGTH}"),
        }
    }
}

impl TryFrom<ResponseRange> for HeaderValue {
    type Error = InvalidHeaderValue;

    fn try_from(range: ResponseRange) -> Result<Self, Self::Error> {
        HeaderValue::try_from(range.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_every_requested_form() {
        assert_eq!(
            RequestRange::parse("bytes=0-499").unwrap(),
            Some(RequestRange::FromTo {
                start: 0,
                end: Some(499)
            })
        );
        assert_eq!(
            RequestRange::parse("bytes=5-").unwrap(),
            Some(RequestRange::FromTo {
                start: 5,
                end: None
            })
        );
        assert_eq!(
            RequestRange::parse("bytes=-64").unwrap(),
            Some(RequestRange::Suffix(64))
        );
    }

    /// A multi-range request is served whole rather than refused.
    #[test]
    fn parse_ignores_multiple_ranges() {
        assert_eq!(RequestRange::parse("bytes=0-10,20-30").unwrap(), None);
    }

    #[test]
    fn parse_rejects_a_value_without_the_bytes_unit() {
        assert!(matches!(
            RequestRange::parse("100-200"),
            Err(Error::Malformed(_))
        ));
    }

    /// The offset form is what chunked-upload clients send, bare or prefixed.
    #[test]
    fn parse_offset_accepts_the_unit_as_optional() {
        let expected = RequestRange::FromTo {
            start: 0,
            end: Some(41),
        };
        assert_eq!(RequestRange::parse_offset("0-41").unwrap(), expected);
        assert_eq!(RequestRange::parse_offset("bytes=0-41").unwrap(), expected);
    }

    #[test]
    fn parse_offset_rejects_an_inverted_window() {
        let error =
            RequestRange::parse_offset("500-499").expect_err("inverted window must be refused");
        assert!(
            error.to_string().contains("start (500) > end (499)"),
            "the error must name both bounds, got: {error}"
        );
    }

    #[test]
    fn request_range_round_trips_through_its_header_value() {
        for range in [
            RequestRange::FromTo {
                start: 5,
                end: Some(10),
            },
            RequestRange::FromTo {
                start: 5,
                end: None,
            },
            RequestRange::Suffix(64),
        ] {
            let header =
                HeaderValue::try_from(range).expect("a range must format as a header value");
            assert_eq!(
                RequestRange::parse(header.to_str().unwrap()).unwrap(),
                Some(range)
            );
        }
    }

    #[test]
    fn resolve_clamps_to_the_body_length() {
        assert_eq!(
            RequestRange::FromTo {
                start: 4,
                end: Some(99)
            }
            .resolve(10)
            .unwrap(),
            Some(ResponseRange {
                start: 4,
                end: 9,
                total_length: Some(10)
            })
        );
        assert_eq!(
            RequestRange::FromTo {
                start: 4,
                end: None
            }
            .resolve(10)
            .unwrap(),
            Some(ResponseRange {
                start: 4,
                end: 9,
                total_length: Some(10)
            })
        );
        assert_eq!(
            RequestRange::Suffix(99).resolve(10).unwrap(),
            Some(ResponseRange {
                start: 0,
                end: 9,
                total_length: Some(10)
            })
        );
    }

    #[test]
    fn resolve_reads_a_suffix_from_the_end() {
        assert_eq!(
            RequestRange::Suffix(4).resolve(10).unwrap(),
            Some(ResponseRange {
                start: 6,
                end: 9,
                total_length: Some(10)
            })
        );
    }

    #[test]
    fn resolve_ignores_ranges_for_an_empty_body() {
        assert!(matches!(
            RequestRange::FromTo {
                start: 0,
                end: None
            }
            .resolve(0),
            Ok(None)
        ));
        assert!(matches!(RequestRange::Suffix(1).resolve(0), Ok(None)));
    }

    #[test]
    fn resolve_refuses_a_window_outside_the_body() {
        assert!(matches!(
            RequestRange::FromTo {
                start: 10,
                end: None
            }
            .resolve(10),
            Err(Error::Unsatisfiable)
        ));
        assert!(matches!(
            RequestRange::Suffix(0).resolve(10),
            Err(Error::Unsatisfiable)
        ));
    }

    #[test]
    fn response_range_reports_its_served_length() {
        let range = ResponseRange {
            start: 5,
            end: 10,
            total_length: Some(100),
        };
        assert_eq!(range.length(), 6);
    }

    #[test]
    fn response_range_round_trips_through_its_header_value() {
        for range in [
            ResponseRange {
                start: 5,
                end: 10,
                total_length: Some(100),
            },
            ResponseRange {
                start: 0,
                end: 9,
                total_length: None,
            },
        ] {
            let header =
                HeaderValue::try_from(range).expect("a range must format as a header value");
            assert_eq!(
                header.to_str().unwrap().parse::<ResponseRange>().unwrap(),
                range
            );
        }
    }

    #[test]
    fn response_range_spells_an_unknown_total_length() {
        let range = ResponseRange {
            start: 5,
            end: 10,
            total_length: None,
        };
        assert_eq!(range.to_string(), "bytes 5-10/*");
    }

    /// An upstream `Content-Range` that names no last byte cannot describe a served
    /// window, so it must not be forwarded as one.
    #[test]
    fn response_range_rejects_an_open_ended_window() {
        assert!("bytes 5-/100".parse::<ResponseRange>().is_err());
        assert!("5-10/100".parse::<ResponseRange>().is_err());
    }
}
