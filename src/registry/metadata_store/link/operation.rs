//! The link mutations callers submit to the write planner.

use std::collections::BTreeMap;

use angos_oci::{Descriptor, Digest, MediaType};

use crate::registry::metadata_store::LinkKind;

/// How a manifest push treats newly-referenced digests the target namespace
/// does not already own, enforced by the link planner's ownership pre-read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferencePolicy {
    /// Reject the push with `MANIFEST_BLOB_UNKNOWN`.
    Strict,
    /// Store the manifest but skip the ownership-granting links for unowned
    /// references, so they stay dangling rather than handing the namespace
    /// read access to content it never pushed.
    Permissive,
    /// Trust every reference as owned; only pull-through cache-fill, which
    /// fetches the content from the upstream the namespace mirrors, may use it.
    Trusted,
}

/// A single link mutation. A `Delete` carrying a `referrer` decrements a
/// tracked link's (layer, config) reference count instead of removing it.
#[derive(Debug, Clone)]
pub enum LinkOperation {
    Create {
        link: LinkKind,
        target: Digest,
        referrer: Option<Digest>,
        media_type: Option<MediaType>,
        size: Option<u64>,
        annotations: Option<BTreeMap<String, String>>,
        descriptor: Option<Box<Descriptor>>,
    },
    Delete {
        link: LinkKind,
        referrer: Option<Digest>,
    },
}

impl LinkOperation {
    pub fn create(link: LinkKind, target: Digest) -> Self {
        Self::Create {
            link,
            target,
            referrer: None,
            media_type: None,
            size: None,
            annotations: None,
            descriptor: None,
        }
    }

    pub fn create_with_referrer(link: LinkKind, target: Digest, referrer: Digest) -> Self {
        Self::Create {
            link,
            target,
            referrer: Some(referrer),
            media_type: None,
            size: None,
            annotations: None,
            descriptor: None,
        }
    }

    /// `size` and `annotations` are persisted only by a tag entry, for tag
    /// history.
    pub fn create_with_media_type(
        link: LinkKind,
        target: Digest,
        media_type: Option<MediaType>,
        size: Option<u64>,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Self {
        Self::Create {
            link,
            target,
            referrer: None,
            media_type,
            size,
            annotations,
            descriptor: None,
        }
    }

    /// Creates a link carrying a pre-computed `Descriptor` (referrer index entry).
    pub fn create_with_descriptor(
        link: LinkKind,
        target: Digest,
        descriptor: Box<Descriptor>,
    ) -> Self {
        Self::Create {
            link,
            target,
            referrer: None,
            media_type: None,
            size: None,
            annotations: None,
            descriptor: Some(descriptor),
        }
    }

    pub fn delete(link: LinkKind) -> Self {
        Self::Delete {
            link,
            referrer: None,
        }
    }

    pub fn delete_with_referrer(link: LinkKind, referrer: Digest) -> Self {
        Self::Delete {
            link,
            referrer: Some(referrer),
        }
    }
}
