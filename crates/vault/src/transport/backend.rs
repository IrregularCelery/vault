//! The [`Backend`] trait for abstract encrypted transports.

use gate::sys::{io, macros::vec::Vec};

/// Errors from transport-level operations.
#[derive(Debug)]
pub enum Error {
    /// The transport handshake failed or the post-handshake application protocol was violated.
    Handshake(&'static str),

    /// An underlying I/O error on the byte stream.
    Io(io::Error),

    /// The message to be sent exceeds the maximum allowed size.
    MessageTooLarge,

    /// The remote peer closed the connection.
    Closed,

    /// Specific message error.
    Other(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Handshake(e) => write!(f, "handshake failed: {}", e),
            Self::Io(e) => write!(f, "I/O: {}", e),
            Self::MessageTooLarge => write!(f, "message is too large"),
            Self::Closed => write!(f, "connection closed"),
            Self::Other(e) => write!(f, "{}", e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: gate::sys::io::Error) -> Self {
        Self::Io(value)
    }
}

/// An abstract bidirectional, message-oriented, encrypted channel.
pub trait Backend {
    /// Sends a message to the remote peer.
    fn send(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Receives and returns a message from the remote peer.
    fn recv(&mut self) -> Result<Vec<u8>, Error>;

    /// The remote peer's verified long-term static public key / identifier.
    fn peer_static_key(&self) -> [u8; 32];

    /// Handshake transcript hash, identical on both peers after a successful handshake.
    fn handshake_hash(&self) -> [u8; 32];
}
