use std::{
    fmt::{Display, Formatter},
    str::FromStr,
    sync::LazyLock,
};

use regex::Regex;

use crate::types::{Error, MediaType};

// RFC 9110 media-range: `*/*`, `type/*` or `type/subtype`, each optionally
// followed by parameters (a `q` weight above all). The name grammar matches
// `MediaType`'s; only the two wildcard forms are additional, which is why an
// `Accept` value cannot be a [`MediaType`].
static MEDIA_RANGE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:\*/\*|[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/(?:\*|[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}))(?:[ \t]*;.*)?$",
    )
    .unwrap()
});

/// One member of an `Accept` header: what a client will take, which a
/// [`MediaType`] cannot express because `*/*` and `type/*` are not media types.
/// The private field forces construction through the validating constructors, so
/// a value forwarded to an upstream is always a well-formed media range.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MediaRange(String);

impl MediaRange {
    /// # Errors
    ///
    /// Returns [`Error::InvalidMediaRange`] when `s` is not a media range.
    pub fn new(s: &str) -> Result<Self, Error> {
        if MEDIA_RANGE_REGEX.is_match(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(Error::InvalidMediaRange(s.to_string()))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Every media type is a media range, so no re-validation is needed.
impl From<MediaType> for MediaRange {
    fn from(media_type: MediaType) -> Self {
        Self(media_type.to_string())
    }
}

impl FromStr for MediaRange {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Display for MediaRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Manifest media types stamped as `Accept` headers on every manifest probe.
/// Without them a content-negotiating registry may return a converted
/// representation whose digest never matches the one asked for.
#[must_use]
pub fn manifest_accept_types() -> Vec<MediaRange> {
    [
        MediaType::oci_manifest(),
        MediaType::oci_index(),
        MediaType::docker_manifest(),
        MediaType::docker_manifest_list(),
    ]
    .map(MediaRange::from)
    .to_vec()
}

#[cfg(test)]
mod tests {
    use crate::types::MediaType;
    use crate::types::media_range::MediaRange;

    /// The wildcard forms are why an `Accept` member is not a `MediaType`:
    /// clients send `*/*` by default, and it must survive to the upstream.
    #[test]
    fn the_wildcard_forms_are_accepted() {
        for raw in ["*/*", "application/*", "application/json"] {
            assert!(
                MediaRange::new(raw).is_ok(),
                "'{raw}' must parse as a media range"
            );
        }
    }

    #[test]
    fn parameters_are_kept_verbatim() {
        let range = MediaRange::new("application/json;q=0.9").unwrap();
        assert_eq!(range.as_str(), "application/json;q=0.9");
    }

    #[test]
    fn a_wildcard_type_with_a_concrete_subtype_is_refused() {
        for raw in ["*/json", "", "application", "/json", "application/"] {
            assert!(
                MediaRange::new(raw).is_err(),
                "'{raw}' must not parse as a media range"
            );
        }
    }

    #[test]
    fn a_media_type_converts_without_re_validation() {
        let media_type = MediaType::oci_manifest();
        let range = MediaRange::from(media_type.clone());
        assert_eq!(range.as_str(), media_type.to_string());
    }
}
