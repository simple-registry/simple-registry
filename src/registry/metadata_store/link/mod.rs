//! The link domain: the link value types ([`LinkKind`], [`LinkMetadata`],
//! [`LinkOperation`]), the single-link [`storage`] primitives with their
//! cache, and the consolidated write planner ([`ops`]) that batches link
//! mutations with their blob-index side effects and carries the
//! `store_manifest` / `delete_manifest` wrappers.

mod kind;
mod metadata;
mod operation;
mod ops;
mod record;
mod storage;
pub mod tag;

pub use kind::LinkKind;
pub use metadata::LinkMetadata;
pub use operation::{LinkOperation, ReferencePolicy};
pub use ops::LinksCommit;
pub use ops::LinksTx;
