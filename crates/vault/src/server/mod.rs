//! Vault server.
//!
//! Accepts incoming transport connections and serves blob and manifest operations.

mod acceptor;

pub use acceptor::*;
