//! The validated value types of the distribution protocol: what a digest, a
//! namespace, a reference, a media type and a byte range are allowed to be.
//! Each one parses and renders itself, so neither end of the protocol
//! hand-rolls a grammar.

pub mod constants;
pub mod http_range;

mod descriptor;
mod digest;
mod error;
mod manifest;
mod media_range;
mod media_type;
mod namespace;
mod reference;
mod tag;
mod upload_session_id;

pub use constants::{
    DOCKER_REFERENCE_DIGEST, IN_TOTO_PREDICATE_TYPE, OCI_INDEX_MEDIA_TYPE, OCI_MANIFEST_MEDIA_TYPE,
};
pub use descriptor::{Descriptor, Platform};
pub use digest::{Algorithm, Digest};
pub use error::Error;
pub use manifest::{Content, Manifest, OCI_MANIFEST_SCHEMA_VERSION};
pub use media_range::{MediaRange, manifest_accept_types};
pub use media_type::MediaType;
pub use namespace::{Namespace, namespace_belongs_to};
pub use reference::Reference;
pub use tag::Tag;
pub use upload_session_id::UploadSessionId;
