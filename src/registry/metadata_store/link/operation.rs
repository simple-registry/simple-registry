//! Public link-mutation operation type.

use std::collections::BTreeMap;

use angos_oci::{Descriptor, Digest, MediaType};

use crate::registry::metadata_store::LinkKind;

/// How a manifest push treats newly-referenced digests the target namespace
/// does not already own. Enforced by the link planner's ownership pre-read;
/// the `v2/gc` marker check keeps it from racing a concurrent reclaim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferencePolicy {
    /// Reject the push with `MANIFEST_BLOB_UNKNOWN`.
    Strict,
    /// Store the manifest but skip the ownership-granting links for unowned
    /// references, so they stay dangling and resolve as unknown on a later pull
    /// instead of handing the namespace read access to content it never pushed.
    Permissive,
    /// Trust every reference as owned. Used only by pull-through cache-fill,
    /// where the referenced content is fetched from the upstream the namespace
    /// mirrors.
    Trusted,
}

/// A single link mutation submitted to [`crate::registry::metadata_store::MetadataStore::update_links`].
/// `Create` carries the target digest and optional referrer / media-type /
/// descriptor metadata, plus the manifest's size and annotations for the tag
/// entries that persist them; `Delete` carries an optional referrer
/// qualification so tracked links (layers, configs) decrement their reference
/// count rather than being removed outright.
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
    /// Creates a link with no referrer, media type, or descriptor.
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

    /// Creates a link carrying a parent `referrer` digest.
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

    /// Creates a link carrying an optional `media_type`, plus the manifest's
    /// size and annotations where a tag entry persists them for tag history.
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

    /// Deletes a link with no referrer qualification.
    pub fn delete(link: LinkKind) -> Self {
        Self::Delete {
            link,
            referrer: None,
        }
    }

    /// Deletes a link qualified by a parent `referrer` digest.
    pub fn delete_with_referrer(link: LinkKind, referrer: Digest) -> Self {
        Self::Delete {
            link,
            referrer: Some(referrer),
        }
    }
}
