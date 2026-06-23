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
            Self::NotFound => write!(f, "blob not found"),
            Self::Io(e) => write!(f, "I/O: {}", e),
            Self::Other(e) => write!(f, "{}", e),
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
    fn save_manifest(&self, data: &[u8]) -> Result<(), Error>;
    fn load_manifest(&self) -> Result<Vec<u8>, Error>;

    fn put_blob(&self, address: &[u8; 32], data: &[u8]) -> Result<(), Error>;
    fn get_blob(&self, address: &[u8; 32]) -> Result<Vec<u8>, Error>;
    fn exists_blob(&self, address: &[u8; 32]) -> Result<bool, Error>;
    fn delete_blob(&self, address: &[u8; 32]) -> Result<(), Error>;
    fn list_blobs(&self) -> Result<Vec<[u8; 32]>, Error>;
}
