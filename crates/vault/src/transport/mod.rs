//! Encrypted transport layer for client-server communication.
//!
//! The [`Backend`] trait abstracts a bidirectional, message-orianted, encrypted channel.

mod backend;

pub mod noise;

pub use backend::*;
