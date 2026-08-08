//! The [`Backend`] trait and its shared [`Error`] type.

use crate::transport;

use gate::{
    codec::binary,
    sys::{borrow::Cow, io, vec::Vec},
};

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

/// Identifies a single storable item.
///
/// The variant determines how an item is written:
/// - [`Key::Manifest`]: mutable and always overwritten.
/// - [`Key::Blob`]: content-addressed , immutable once written, and create-if-absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Key {
    /// The single, mutable manifest item.
    Manifest,

    /// An immutable, content-addressed chunk blob at its 32-byte address.
    Blob([u8; 32]),
}

impl Key {
    /// Serializes this key's discriminant and payload to a [`binary::Writer`].
    pub fn write_to(&self, writer: &mut binary::Writer) {
        match self {
            Key::Manifest => writer.write_u8(0),
            Key::Blob(address) => {
                writer.write_u8(1);
                writer.write_bytes(address);
            }
        }
    }

    /// Deserializes a key from a [`binary::Reader`].
    ///
    /// # Errors
    ///
    /// - [`binary::Error::Other`]: If the leading discriminant byte doesn't match a known variant.
    pub fn read_from(reader: &mut binary::Reader) -> Result<Self, binary::Error> {
        Ok(match reader.read_u8()? {
            0 => Key::Manifest,
            1 => Key::Blob(*reader.read_bytes()?),
            _ => return Err(binary::Error::Other("unknown `key` tag discriminant")),
        })
    }

    /// Size of this key when serialized (discriminant + payload).
    pub const fn size(&self) -> usize {
        match self {
            Key::Manifest => {
                // 1 for the discriminant
                1
            }
            Key::Blob(_) => {
                // 1 for the discriminant
                // 32 for the address
                1 + 32
            }
        }
    }
}

/// Identifies a listable category of keys.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    /// The category of all [`Key::Blob`]s.
    Blobs,
}

impl Kind {
    /// Serializes this kind's discriminant to a [`binary::Writer`].
    pub fn write_to(&self, writer: &mut binary::Writer) {
        match self {
            Kind::Blobs => writer.write_u8(1),
        }
    }

    /// Deserializes a kind from a [`binary::Reader`].
    ///
    /// # Errors
    ///
    /// - [`binary::Error::Other`]: If the discriminant byte doesn't match a known variant.
    pub fn read_from(reader: &mut binary::Reader) -> Result<Self, binary::Error> {
        Ok(match reader.read_u8()? {
            1 => Kind::Blobs,
            _ => return Err(binary::Error::Other("unknown `kind` tag discriminant")),
        })
    }
}

/// Abstract interface for storage data persistence.
///
/// [`Key::Manifest`] is mutable and is always overwritten.
/// [`Key::Blob`] is always create-if-absent and immutable once written. If an address already
/// exists, [`Backend::put`] is
/// a silent no-op.
pub trait Backend {
    /// Stores an item's `data` with `key`.
    ///
    /// Silent no-op if [`Key::Blob`] address already exists.
    /// Operation for [`Key::Manifest`] always overwrites the `data`.
    fn put(&self, key: Key, data: &[u8]) -> Result<(), Error>;

    /// Retrieves the raw bytes of an item with `key`.
    fn get(&self, key: Key) -> Result<Vec<u8>, Error>;

    /// Returns whether an item exists with `key` without reading its contents.
    fn exists(&self, key: Key) -> Result<bool, Error>;

    /// Removes an item with `key`. Must be idempotent, no error if already absent.
    fn delete(&self, key: Key) -> Result<(), Error>;

    /// Returns all stored item keys. Order is unspecified.
    fn list(&self, kind: Kind) -> Result<Vec<Key>, Error>;
}
