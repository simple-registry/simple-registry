//! The OCI distribution vocabulary. [`types`] holds the validated values of
//! the protocol and [`request`] the shape of every operation, both spoken by
//! either end, [`response`] the answers they carry back; [`server`] reads a
//! request and renders the answer's headers, [`client`] builds the request and
//! reads those headers back.

pub mod client;
pub mod header;
pub mod path;
pub mod request;
pub mod response;
pub mod server;
pub mod types;

pub use types::*;
