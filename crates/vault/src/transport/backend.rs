use gate::sys::{io, macros::vec::Vec};

#[derive(Debug)]
pub enum Error {
    Handshake(&'static str),
    Io(io::Error),
    Closed,
    Other(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Handshake(e) => write!(f, "handshake failed: {}", e),
            Self::Io(e) => write!(f, "I/O: {}", e),
            Self::Closed => write!(f, "connection closed"),
            Self::Other(e) => write!(f, "{}", e),
        }
    }
}

pub trait Backend {
    fn send(&mut self, data: &[u8]) -> Result<(), Error>;
    fn recv(&mut self) -> Result<Vec<u8>, Error>;

    /// The remote peer's verified static public key / identifier.
    /// Noise: remote X25519 static public key.
    fn peer_static_key(&self) -> [u8; 32];

    /// Handshake transcript hash, identical on both peers after a successful handshake.
    fn handshake_hash(&self) -> [u8; 32];
}
