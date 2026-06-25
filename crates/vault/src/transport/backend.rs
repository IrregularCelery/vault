use gate::sys::{io, macros::vec::Vec};

#[derive(Debug)]
pub enum Error {
    Handshake(&'static str),
    Closed,
    Other(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Handshake(e) => write!(f, "handshake failed: {}", e),
            Self::Closed => write!(f, "connection closed"),
            Self::Other(e) => write!(f, "{}", e),
        }
    }
}

pub trait Backend {
    fn send(&mut self, data: &[u8]) -> Result<(), Error>;
    fn recv(&mut self) -> Result<Vec<u8>, Error>;
}
