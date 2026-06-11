use gate::sys::{io, vec::Vec};

#[derive(Debug)]
pub enum Error {
    NotFound,
    Io(io::Error),
    Other(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotFound => write!(f, "blob not found"),
            Error::Io(e) => write!(f, "I/O: {}", e),
            Error::Other(e) => write!(f, "{}", e),
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
    fn overwrite(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error>;
    fn exists(&self, hash: &[u8; 32]) -> Result<bool, Error>;
    fn delete(&self, hash: &[u8; 32]) -> Result<(), Error>;
    fn list(&self) -> Result<Vec<[u8; 32]>, Error>;
}
