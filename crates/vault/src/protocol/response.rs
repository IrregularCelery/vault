//! Server-to-client responses.

use crate::protocol::Error;

use gate::{
    codec::binary,
    sys::{
        string::{String, ToString},
        vec::Vec,
    },
};

/// A storage operation response from the server to a client.
#[derive(Debug, PartialEq)]
pub enum Response {
    /// The request succeeded with no data to return.
    ///
    /// # Requests
    ///
    /// - [`super::request::Request::SaveManifest`]
    /// - [`super::request::Request::PutBlob`]
    /// - [`super::request::Request::DeleteBlob`]
    Ok,

    /// The requested manifest blob. Contains the raw encrypted bytes.
    ///
    /// # Requests
    ///
    /// - [`super::request::Request::LoadManifest`]
    Manifest(Vec<u8>),

    /// The list of all blob addresses.
    ///
    /// # Requests
    ///
    /// - [`super::request::Request::ListBlobs`]
    Addresses(Vec<[u8; 32]>),

    /// The requested blob's raw encrypted bytes.
    ///
    /// # Requests
    ///
    /// - [`super::request::Request::GetBlob`]
    Blob(Vec<u8>),

    /// Whether the queried blob exists.
    ///
    /// # Requests
    ///
    /// - [`super::request::Request::ExistsBlob`]
    Exists(bool),

    /// The requested path was not found.
    ///
    /// # Requests
    ///
    /// - [`super::request::Request::LoadManifest`]
    /// - [`super::request::Request::GetBlob`]
    NotFound,

    /// A server-side error occurred.
    ///
    /// # Requests
    ///
    /// - All [`super::request::Request`] variants can return error.
    Error(String),
}

impl Response {
    /// Discriminant tag for [`Response::Ok`].
    const TAG_OK: u8 = 0;
    /// Discriminant tag for [`Response::Manifest`].
    const TAG_MANIFEST: u8 = 1;
    /// Discriminant tag for [`Response::Addresses`].
    const TAG_ADDRESSES: u8 = 2;
    /// Discriminant tag for [`Response::Blob`].
    const TAG_BLOB: u8 = 3;
    /// Discriminant tag for [`Response::Exists`].
    const TAG_EXISTS: u8 = 4;
    /// Discriminant tag for [`Response::NotFound`].
    const TAG_NOT_FOUND: u8 = 5;
    /// Discriminant tag for [`Response::Error`].
    const TAG_ERROR: u8 = 6;

    /// Serializes the response into a binary format.
    ///
    /// # Errors
    ///
    /// - [`Error::Codec`]: If the underlying binary serialization fails (e.g., blob length exceeds
    ///   u32::MAX).
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut writer;

        match self {
            Response::Ok => {
                // `1` for tag
                writer = binary::Writer::with_capacity(1);
                writer.write_u8(Self::TAG_OK);
            }
            Response::Manifest(payload) => {
                // Add `1` for tag
                // Add `4` for data length prefix (u32)
                writer = binary::Writer::with_capacity(1 + 4 + payload.len());
                writer.write_u8(Self::TAG_MANIFEST);
                writer.write_blob(payload)?;
            }
            Response::Addresses(payload) => {
                // Add `1` for tag
                // Add `4` for data length prefix (u32)
                // Multiply `32` since addresses are 32 bytes each
                writer = binary::Writer::with_capacity(1 + 4 + payload.len() * 32);
                writer.write_u8(Self::TAG_ADDRESSES);
                writer.write_u32(payload.len() as u32);

                for address in payload.iter() {
                    writer.write_bytes(address);
                }
            }
            Response::Blob(payload) => {
                // Add `1` for tag
                // Add `4` for data length prefix (u32)
                writer = binary::Writer::with_capacity(1 + 4 + payload.len());
                writer.write_u8(Self::TAG_BLOB);
                writer.write_blob(payload)?;
            }
            Response::Exists(payload) => {
                // Add `1` for tag
                // Add `1` for bool value
                writer = binary::Writer::with_capacity(1 + 1);
                writer.write_u8(Self::TAG_EXISTS);
                writer.write_bool(*payload);
            }
            Response::NotFound => {
                // `1` for tag
                writer = binary::Writer::with_capacity(1);
                writer.write_u8(Self::TAG_NOT_FOUND);
            }
            Response::Error(payload) => {
                // Add `1` for tag
                // Add `4` for data length prefix (u32)
                writer = binary::Writer::with_capacity(1 + 4 + payload.len());
                writer.write_u8(Self::TAG_ERROR);
                writer.write_str(payload)?;
            }
        }

        Ok(writer.finish())
    }

    /// Deserializes a response from a raw bytes format.
    ///
    /// # Errors
    ///
    /// - [`Error::Codec`]: If the underlying binary deserialization fails (e.g., `data` is empty).
    /// - [`Error::UnknownTag`]: If the leading tag does not match a valid response variant.
    pub fn deserialize(data: &[u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::Codec(binary::Error::Other("empty message")));
        }

        let mut reader = binary::Reader::new(data);
        let tag = reader.read_u8()?;

        Ok(match tag {
            Self::TAG_OK => Self::Ok,
            Self::TAG_MANIFEST => {
                let manifest = reader.read_blob()?;

                Self::Manifest(manifest.to_vec())
            }
            Self::TAG_ADDRESSES => {
                let count = reader.read_u32()? as usize;
                let mut addresses = Vec::with_capacity(count);

                for _ in 0..count {
                    let address: [u8; 32] = *reader.read_bytes()?;

                    addresses.push(address);
                }

                Self::Addresses(addresses)
            }
            Self::TAG_BLOB => {
                let blob = reader.read_blob()?;

                Self::Blob(blob.to_vec())
            }
            Self::TAG_EXISTS => {
                let exists = reader.read_bool()?;

                Self::Exists(exists)
            }
            Self::TAG_NOT_FOUND => Self::NotFound,
            Self::TAG_ERROR => {
                let error = reader.read_str()?;

                Self::Error(error.to_string())
            }
            other => return Err(Error::UnknownTag(other)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gate::sys::macros::vec;

    #[test]
    fn response_variants_roundtrip() {
        let responses = vec![
            Response::Ok,
            Response::Manifest(vec![1, 2]),
            Response::Addresses(vec![[1u8; 32], [2u8; 32]]),
            Response::Blob(vec![3, 4]),
            Response::Exists(true),
            Response::Exists(false),
            Response::NotFound,
            Response::Error("damn! نشد".into()),
        ];

        for response in responses {
            let serialized = response.serialize().unwrap();
            let deserialized = Response::deserialize(&serialized).unwrap();

            assert_eq!(response, deserialized);
        }
    }

    #[test]
    fn deserialize_empty_message() {
        assert!(matches!(
            Response::deserialize(&[]),
            Err(Error::Codec(binary::Error::Other("empty message")))
        ));
    }

    #[test]
    fn deserialize_unknown_tag() {
        assert!(matches!(
            Response::deserialize(&[255]),
            Err(Error::UnknownTag(255))
        ));
    }
}
