//! Server-to-client responses.

use crate::{protocol::Error, storage::Key};

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
    /// - [`super::request::Request::Put`]
    /// - [`super::request::Request::Delete`]
    Ok,

    /// The list of all keys matching the requested [`super::request::Request::List`] kind.
    ///
    /// # Requests
    ///
    /// - [`super::request::Request::List`]
    Keys(Vec<Key>),

    /// The requested item's raw bytes.
    ///
    /// # Requests
    ///
    /// - [`super::request::Request::Get`]
    Data(Vec<u8>),

    /// Whether the queried key exists.
    ///
    /// # Requests
    ///
    /// - [`super::request::Request::Exists`]
    Exists(bool),

    /// The requested key was not found.
    ///
    /// # Requests
    ///
    /// - [`super::request::Request::Get`]
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
    /// Discriminant tag for [`Response::Keys`].
    const TAG_KEYS: u8 = 1;
    /// Discriminant tag for [`Response::Data`].
    const TAG_DATA: u8 = 2;
    /// Discriminant tag for [`Response::Exists`].
    const TAG_EXISTS: u8 = 3;
    /// Discriminant tag for [`Response::NotFound`].
    const TAG_NOT_FOUND: u8 = 4;
    /// Discriminant tag for [`Response::Error`].
    const TAG_ERROR: u8 = 5;

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
            Response::Keys(payload) => {
                // Add `1` for tag
                // Add `4` for data length prefix (u32)
                // Multiply by `33` as an estimate since keys are at most 32 bytes each + 1
                // for their discriminant
                writer = binary::Writer::with_capacity(1 + 4 + payload.len() * 33);
                writer.write_u8(Self::TAG_KEYS);
                writer.write_u32(payload.len() as u32);

                for key in payload.iter() {
                    key.write_to(&mut writer);
                }
            }
            Response::Data(payload) => {
                // Add `1` for tag
                // Add `4` for data length prefix (u32)
                writer = binary::Writer::with_capacity(1 + 4 + payload.len());
                writer.write_u8(Self::TAG_DATA);
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
            Self::TAG_KEYS => {
                let count = reader.read_u32()? as usize;
                let mut keys = Vec::with_capacity(count);

                for _ in 0..count {
                    let key = Key::read_from(&mut reader)?;

                    keys.push(key);
                }

                Self::Keys(keys)
            }
            Self::TAG_DATA => {
                let blob = reader.read_blob()?;

                Self::Data(blob.to_vec())
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
            Response::Keys(vec![Key::Blob([1u8; 32]), Key::Blob([2u8; 32])]),
            Response::Keys(vec![Key::Index(69)]),
            Response::Data(vec![3, 4]),
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
