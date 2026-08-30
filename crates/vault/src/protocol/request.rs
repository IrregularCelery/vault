//! Client-to-server requests.

use crate::storage::{Key, Kind};

use super::Error;

use gate::{codec::binary, sys::vec::Vec};

/// A storage operation request from the client to the server.
#[derive(Debug, PartialEq)]
pub enum Request<'a> {
    /// Stores `data` at `key`.
    ///
    /// # Responses
    ///
    /// - [`super::response::Response::Ok`]
    /// - [`super::response::Response::Error`]
    Put {
        /// The key identifying the item to store.
        key: Key,

        /// The bytes to store.
        data: &'a [u8],
    },

    /// Retrieves the raw bytes stored at `key`.
    ///
    /// # Responses
    ///
    /// - [`super::response::Response::Data`]
    /// - [`super::response::Response::NotFound`]
    /// - [`super::response::Response::Error`]
    Get {
        /// The key identifying the item to retrieve.
        key: Key,
    },

    /// Checks whether an item exists at `key` without reading its contents.
    ///
    /// # Responses
    ///
    /// - [`super::response::Response::Exists`]
    /// - [`super::response::Response::Error`]
    Exists {
        /// The key identifying the item to check.
        key: Key,
    },

    /// Deletes the item at `key`.
    ///
    /// # Responses
    ///
    /// - [`super::response::Response::Ok`]
    /// - [`super::response::Response::Error`]
    Delete {
        /// The key identifying the item to delete.
        key: Key,
    },

    /// List all keys in a `kind` category.
    ///
    /// # Responses
    ///
    /// - [`super::response::Response::Keys`]
    /// - [`super::response::Response::Error`]
    List {
        /// The category of keys to list.
        kind: Kind,
    },
}

impl<'a> Request<'a> {
    /// Discriminant tag for [`Request::Put`].
    const TAG_PUT: u8 = 0;
    /// Discriminant tag for [`Request::Get`].
    const TAG_GET: u8 = 1;
    /// Discriminant tag for [`Request::Exists`].
    const TAG_EXISTS: u8 = 2;
    /// Discriminant tag for [`Request::Delete`].
    const TAG_DELETE: u8 = 3;
    /// Discriminant tag for [`Request::List`].
    const TAG_LIST: u8 = 4;

    /// Serializes the request into a binary format.
    ///
    /// # Errors
    ///
    /// - [`Error::Codec`]: If the underlying binary serialization fails (e.g., blob length exceeds
    ///   u32::MAX).
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut writer;

        match self {
            Request::Put { key, data } => {
                // Add `1` for tag
                // Add `4` for data length prefix (u32)
                writer = binary::Writer::with_capacity(1 + key.size() + 4 + data.len());
                writer.write_u8(Self::TAG_PUT);
                key.write_to(&mut writer);
                writer.write_blob(data)?;
            }
            Request::Get { key } => {
                // Add `1` for tag
                writer = binary::Writer::with_capacity(1 + key.size());
                writer.write_u8(Self::TAG_GET);
                key.write_to(&mut writer);
            }
            Request::Exists { key } => {
                // Add `1` for tag
                writer = binary::Writer::with_capacity(1 + key.size());
                writer.write_u8(Self::TAG_EXISTS);
                key.write_to(&mut writer);
            }
            Request::Delete { key } => {
                // Add `1` for tag
                writer = binary::Writer::with_capacity(1 + key.size());
                writer.write_u8(Self::TAG_DELETE);
                key.write_to(&mut writer);
            }
            Request::List { kind } => {
                // Add `1` for tag
                // Add `1` for kind
                writer = binary::Writer::with_capacity(1 + 1);
                writer.write_u8(Self::TAG_LIST);
                kind.write_to(&mut writer);
            }
        }

        Ok(writer.finish())
    }

    /// Deserializes a request from a raw bytes format.
    ///
    /// # Errors
    ///
    /// - [`Error::Codec`]: If the underlying binary deserialization fails (e.g., `data` is empty).
    /// - [`Error::UnknownTag`]: If the leading tag does not match a valid request variant.
    pub fn deserialize(data: &'a [u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::Codec(binary::Error::Other("empty message")));
        }

        let mut reader = binary::Reader::new(data);
        let tag = reader.read_u8()?;

        Ok(match tag {
            Self::TAG_PUT => Self::Put {
                key: Key::read_from(&mut reader)?,
                data: reader.read_blob()?,
            },
            Self::TAG_GET => Self::Get {
                key: Key::read_from(&mut reader)?,
            },
            Self::TAG_EXISTS => Self::Exists {
                key: Key::read_from(&mut reader)?,
            },
            Self::TAG_DELETE => Self::Delete {
                key: Key::read_from(&mut reader)?,
            },
            Self::TAG_LIST => Self::List {
                kind: Kind::read_from(&mut reader)?,
            },
            other => return Err(Error::UnknownTag(other)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gate::sys::macros::vec;

    #[test]
    fn request_variants_roundtrip() {
        let requests = vec![
            Request::Put {
                key: Key::Blob([9u8; 32]),
                data: &[4, 5],
            },
            Request::Get {
                key: Key::Blob([1u8; 32]),
            },
            Request::Exists {
                key: Key::Blob([2u8; 32]),
            },
            Request::Delete {
                key: Key::Blob([3u8; 32]),
            },
            Request::List { kind: Kind::Blob },
            Request::Put {
                key: Key::Index(1),
                data: &[4, 5],
            },
            Request::Get { key: Key::Index(2) },
            Request::Exists { key: Key::Index(3) },
            Request::Delete { key: Key::Index(4) },
        ];

        for request in requests {
            let serialized = request.serialize().unwrap();
            let deserialized = Request::deserialize(&serialized).unwrap();

            assert_eq!(request, deserialized);
        }
    }

    #[test]
    fn deserialize_empty_message() {
        assert!(matches!(
            Request::deserialize(&[]),
            Err(Error::Codec(binary::Error::Other("empty message")))
        ));
    }

    #[test]
    fn deserialize_unknown_tag() {
        assert!(matches!(
            Request::deserialize(&[255]),
            Err(Error::UnknownTag(255))
        ));
    }
}
