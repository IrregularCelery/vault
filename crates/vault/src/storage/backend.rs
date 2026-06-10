use gate::sys::{io, string::String, vec::Vec};

#[derive(Debug)]
pub enum Error {
    NotFound,
    Io(io::Error),
    Other(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotFound => write!(f, "blob not found"),
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Other(e) => write!(f, "storage error: {}", e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: gate::sys::io::Error) -> Self {
        if value.kind() == io::ErrorKind::NotFound {
            return Self::NotFound;
        }

        Self::Io(value)
    }
}

pub trait Backend {
    fn put(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error>;
    fn get(&self, hash: &[u8; 32]) -> Result<Vec<u8>, Error>;
    fn exists(&self, hash: &[u8; 32]) -> Result<bool, Error>;
    fn delete(&self, hash: &[u8; 32]) -> Result<(), Error>;
    fn list(&self) -> Result<Vec<[u8; 32]>, Error>;
}
