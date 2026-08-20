//! The link domain: the link value types, the single-link [`storage`]
//! primitives with their cache, and the [`ops`] write planner that batches
//! link mutations with their blob-index side effects.

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
