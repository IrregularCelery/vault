//! Client-to-server requests.

use super::Error;

use gate::{codec::binary, sys::vec::Vec};

/// A storage operation request from the client to the server.
#[derive(Debug, PartialEq)]
pub enum Request<'a> {
    /// Overwrite the manifest blob with `data`.
    SaveManifest {
        /// The serialized, encrypted manifest bytes to persist.
        data: &'a [u8],
    },

    /// Retrieve the manifest blob.
    LoadManifest,

    /// Store `data` at the content-addressed `address`. No-op if already exists.
    PutBlob {
        /// The 32-byte content address of the blob.
        address: [u8; 32],

        /// The encrypted blob bytes to store.
        data: &'a [u8],
    },

    /// Retrieve the encrypted blob at `address`.
    GetBlob {
        /// The 32-byte content address of the blob.
        address: [u8; 32],
    },

    /// Check whether a blob exists at `address` without reading its contents.
    ExistsBlob {
        /// The 32-byte content address of the blob.
        address: [u8; 32],
    },

    /// Delete the blob at `address`. Idempotent, no error if absent.
    DeleteBlob {
        /// The 32-byte content address of the blob.
        address: [u8; 32],
    },

    /// List all blob addresses.
    ListBlobs,
}

impl<'a> Request<'a> {
    /// Discriminant tag for [`Request::SaveManifest`].
    const TAG_SAVE_MANIFEST: u8 = 0;
    /// Discriminant tag for [`Request::LoadManifest`].
    const TAG_LOAD_MANIFEST: u8 = 1;
    /// Discriminant tag for [`Request::PutBlob`].
    const TAG_PUT_BLOB: u8 = 2;
    /// Discriminant tag for [`Request::GetBlob`].
    const TAG_GET_BLOB: u8 = 3;
    /// Discriminant tag for [`Request::ExistsBlob`].
    const TAG_EXISTS_BLOB: u8 = 4;
    /// Discriminant tag for [`Request::DeleteBlob`].
    const TAG_DELETE_BLOB: u8 = 5;
    /// Discriminant tag for [`Request::ListBlobs`].
    const TAG_LIST_BLOB: u8 = 6;

    /// Serializes the request into a binary format.
    ///
    /// # Errors
    ///
    /// - [`Error::Codec`]: If the underlying binary serialization fails (e.g., blob length exceeds
    ///   u32::MAX).
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut writer;

        match self {
            Request::SaveManifest { data } => {
                // Add `1` for tag
                // Add `4` for data length prefix (u32)
                writer = binary::Writer::with_capacity(1 + 4 + data.len());
                writer.write_u8(Self::TAG_SAVE_MANIFEST);
                writer.write_blob(data)?;
            }
            Request::LoadManifest => {
                // `1` for tag
                writer = binary::Writer::with_capacity(1);
                writer.write_u8(Self::TAG_LOAD_MANIFEST);
            }
            Request::PutBlob { address, data } => {
                // Add `1` for tag
                // Add `32` for address
                // Add `4` for data length prefix (u32)
                writer = binary::Writer::with_capacity(1 + 32 + 4 + data.len());
                writer.write_u8(Self::TAG_PUT_BLOB);
                writer.write_bytes(address);
                writer.write_blob(data)?;
            }
            Request::GetBlob { address } => {
                // Add `1` for tag
                // Add `32` for address
                writer = binary::Writer::with_capacity(1 + 32);
                writer.write_u8(Self::TAG_GET_BLOB);
                writer.write_bytes(address);
            }
            Request::ExistsBlob { address } => {
                // Add `1` for tag
                // Add `32` for address
                writer = binary::Writer::with_capacity(1 + 32);
                writer.write_u8(Self::TAG_EXISTS_BLOB);
                writer.write_bytes(address);
            }
            Request::DeleteBlob { address } => {
                // Add `1` for tag
                // Add `32` for address
                writer = binary::Writer::with_capacity(1 + 32);
                writer.write_u8(Self::TAG_DELETE_BLOB);
                writer.write_bytes(address);
            }
            Request::ListBlobs => {
                // `1` for tag
                writer = binary::Writer::with_capacity(1);
                writer.write_u8(Self::TAG_LIST_BLOB);
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
            Self::TAG_SAVE_MANIFEST => Self::SaveManifest {
                data: reader.read_blob()?,
            },
            Self::TAG_LOAD_MANIFEST => Self::LoadManifest {},
            Self::TAG_PUT_BLOB => Self::PutBlob {
                address: *reader.read_bytes()?,
                data: reader.read_blob()?,
            },
            Self::TAG_GET_BLOB => Self::GetBlob {
                address: *reader.read_bytes()?,
            },
            Self::TAG_EXISTS_BLOB => Self::ExistsBlob {
                address: *reader.read_bytes()?,
            },
            Self::TAG_DELETE_BLOB => Self::DeleteBlob {
                address: *reader.read_bytes()?,
            },
            Self::TAG_LIST_BLOB => Self::ListBlobs {},
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
            Request::SaveManifest { data: &[1, 2, 3] },
            Request::LoadManifest,
            Request::PutBlob {
                address: [9u8; 32],
                data: &[4, 5],
            },
            Request::GetBlob { address: [1u8; 32] },
            Request::ExistsBlob { address: [2u8; 32] },
            Request::DeleteBlob { address: [3u8; 32] },
            Request::ListBlobs,
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
