use chrono::{DateTime, Utc};

/// Metadata for a single stored object, returned by `ObjectStore::head`.
#[derive(Clone, Debug, PartialEq)]
pub struct ObjectMeta {
    pub size: u64,
    pub last_modified: Option<DateTime<Utc>>,
}

/// One page of results from a flat listing (`ObjectStore::list`).
///
/// `next_token` is `Some` when the listing was truncated; pass it back to
/// the next `list` call to resume. `None` means the listing is complete.
#[derive(Clone, Debug, PartialEq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_token: Option<String>,
}

/// Every immediate child under a prefix, with no ordering guarantee. Same two
/// name sets as [`ChildrenPage`], without the pagination cursor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Children {
    pub sub_prefixes: Vec<String>,
    pub objects: Vec<String>,
}

/// One page of results from a hierarchical listing (`ObjectStore::list_children`).
///
/// `sub_prefixes` contains the immediate sub-prefix names (the "subdirectories"
/// directly under the requested prefix). Each name is **bare**: the delimiter
/// (trailing `/`) is stripped, so a key `prefix/v1/foo` yields the sub-prefix
/// `v1`, not `v1/`. All backends honour this so consumers can treat the names
/// identically regardless of backend. `objects` contains any keys sitting
/// directly at the requested prefix level with no further `/` separator.
/// `next_token` follows the same semantics as `Page::next_token`.
#[derive(Clone, Debug, PartialEq)]
pub struct ChildrenPage {
    pub sub_prefixes: Vec<String>,
    pub objects: Vec<String>,
    pub next_token: Option<String>,
}
