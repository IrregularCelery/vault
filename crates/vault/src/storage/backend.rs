//! The [`Backend`] trait and its shared [`Error`] type.

use crate::transport;

use gate::sys::{borrow::Cow, io, vec::Vec};

/// Errors returned by [`Backend`] operations.
#[derive(Debug)]
pub enum Error {
    /// The manifest or blob does not exist.
    NotFound,

    /// An I/O error.
    Io(io::Error),

    /// An error from the remote transport backend.
    Transport(transport::Error),

    /// Specific message error.
    Other(Cow<'static, str>),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "blob not found"),
            Self::Io(e) => write!(f, "I/O: {}", e),
            Self::Transport(e) => write!(f, "transport: {}", e),
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

impl From<transport::Error> for Error {
    fn from(value: transport::Error) -> Self {
        Self::Transport(value)
    }
}

/// Abstract interface for blob and manifest persistence.
///
/// Blobs are immutable once written. If an address already exists, [`Backend::put_blob`] is
/// a silent no-op.
pub trait Backend {
    /// Persists the serialized, encrypted manifest. Must be atomic where possible.
    fn save_manifest(&self, data: &[u8]) -> Result<(), Error>;

    /// Reads the encrypted manifest bytes.
    fn load_manifest(&self) -> Result<Vec<u8>, Error>;

    /// Stores `data` at the content-addressed `address`.
    ///
    /// Silent no-op if a blob at `address` already exists.
    fn put_blob(&self, address: &[u8; 32], data: &[u8]) -> Result<(), Error>;

    /// Retrieves the raw encrypted bytes of the blob at `address`.
    fn get_blob(&self, address: &[u8; 32]) -> Result<Vec<u8>, Error>;

    /// Returns whether a blob exists at `address` without reading its contents.
    fn exists_blob(&self, address: &[u8; 32]) -> Result<bool, Error>;

    /// Removes the blob at `address`. Must be idempotent, no error if already absent.
    fn delete_blob(&self, address: &[u8; 32]) -> Result<(), Error>;

    /// Returns all stored blob addresses. Order is unspecified.
    fn list_blobs(&self) -> Result<Vec<[u8; 32]>, Error>;
}
