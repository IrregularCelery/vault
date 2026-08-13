//! Storage layer for encrypted blobs and index persistence.
//!
//! Defines the [`Backend`] trait as well as some implementations:
//!
//! - [`local::Storage`]: Filesystem-backed, scoped per user via a content-addressed
//!   hex directory tree derived from the user's public signing key.
//! - [`remote::Storage`]: Transport-backed, delegates every operation to a remote
//!   server via the vault protocol.

mod backend;

pub mod chunk;
pub mod hashpath;
pub mod index;
pub mod local;
pub mod remote;

pub use backend::*;
