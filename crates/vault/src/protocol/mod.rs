//! Binary request/response protocol for client–server communication.
//!
//! After the a successful transport is established, the client sends a [`ClientInit`] message
//! to authenticate its identity. Subsequent turns are [`request::Request`] / [`response::Response`]
//! pairs exchanged in a loop until the connection closes.

mod codec;

pub mod request;
pub mod response;

pub use codec::*;
