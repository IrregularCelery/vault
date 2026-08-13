//! Vault server.
//!
//! Accepts incoming transport connections and serves blob and index operations.

mod acceptor;

pub use acceptor::*;
