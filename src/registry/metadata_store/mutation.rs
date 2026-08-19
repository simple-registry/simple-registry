//! [`Mutation`]: the vocabulary the metadata planners use to describe the
//! writes of one operation before applying them as ordered fan-out
//! puts/deletes.

use bytes::Bytes;

/// One planned write. The link planner and the blob index collect these into
/// ordered waves and apply them as plain puts/deletes.
#[derive(Clone, Debug)]
pub enum Mutation {
    /// Write `body` to `key`, replacing any existing object.
    Put { key: String, body: Bytes },
    /// Delete `key`. Deleting a missing key is a no-op.
    Delete { key: String },
}
