use hyper::HeaderMap;

use angos_oci::{Digest, MediaType};

pub struct ManifestMeta {
    pub media_type: Option<MediaType>,
    pub digest: Digest,
    pub size: u64,
}

pub struct ManifestBody {
    pub media_type: Option<MediaType>,
    pub digest: Digest,
    pub content: Vec<u8>,
}

/// What a manifest GET resolved to, before it becomes a response: the pull
/// event needs the served digest, which the response itself does not hand back.
pub enum GetManifestResponse {
    Redirect {
        digest: Digest,
        headers: HeaderMap,
    },
    Body {
        digest: Digest,
        content: Vec<u8>,
        headers: HeaderMap,
    },
}

impl GetManifestResponse {
    pub fn digest(&self) -> &Digest {
        match self {
            GetManifestResponse::Redirect { digest, .. }
            | GetManifestResponse::Body { digest, .. } => digest,
        }
    }
}

/// What a manifest PUT committed. The registry serves `headers` and decides
/// replication off the rest, so both outlive the write.
pub struct PutManifestResponse {
    pub digest: Digest,
    /// Whether the write changed local state, as validated by the committed
    /// link transaction itself (no racy pre-read); gates the replication
    /// re-dispatch.
    pub changed: bool,
    pub headers: HeaderMap,
}
