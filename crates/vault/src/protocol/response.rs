use super::Error;

use gate::{
    codec::binary,
    sys::{
        string::{String, ToString},
        vec::Vec,
    },
};

#[derive(Debug, PartialEq)]
pub enum Response {
    Ok,
    Manifest(Vec<u8>),
    Addresses(Vec<[u8; 32]>),
    Blob(Vec<u8>),
    Exists(bool),
    NotFound,
    Error(String),
}

impl Response {
    const TAG_OK: u8 = 0;
    const TAG_MANIFEST: u8 = 1;
    const TAG_ADDRESSES: u8 = 2;
    const TAG_BLOB: u8 = 3;
    const TAG_EXISTS: u8 = 4;
    const TAG_NOT_FOUND: u8 = 5;
    const TAG_ERROR: u8 = 6;

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
                writer.write_u8(*payload as u8);
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

    pub fn deserialize(data: &[u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::Codec(binary::Error::Other("empty message")));
        }

        let mut reader = binary::Reader::new(&data);
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
