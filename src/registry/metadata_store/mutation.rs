//! [`Mutation`]: how the metadata planners describe one operation's writes
//! before applying them as ordered fan-out puts and deletes.

use bytes::Bytes;

/// One planned write, collected by the link planner and the blob index into
/// ordered waves.
#[derive(Clone, Debug)]
pub enum Mutation {
    /// Write `body` to `key`, replacing any existing object.
    Put { key: String, body: Bytes },
    /// Delete `key`; deleting a missing key is a no-op.
    Delete { key: String },
}
