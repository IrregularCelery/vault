use gate::{codec::binary, sys::vec::Vec};

#[derive(Debug)]
pub enum Error {
    Codec(binary::Error),
    UnknownTag(u8),
}

impl From<binary::Error> for Error {
    fn from(value: binary::Error) -> Self {
        Self::Codec(value)
    }
}

#[derive(Debug, PartialEq)]
pub enum Request<'a> {
    SaveManifest { data: &'a [u8] },
    LoadManifest,
    PutBlob { address: [u8; 32], data: &'a [u8] },
    GetBlob { address: [u8; 32] },
    ExistsBlob { address: [u8; 32] },
    DeleteBlob { address: [u8; 32] },
    ListBlobs,
}

impl<'a> Request<'a> {
    const TAG_SAVE_MANIFEST: u8 = 0;
    const TAG_LOAD_MANIFEST: u8 = 1;
    const TAG_PUT_BLOB: u8 = 2;
    const TAG_GET_BLOB: u8 = 3;
    const TAG_EXISTS_BLOB: u8 = 4;
    const TAG_DELETE_BLOB: u8 = 5;
    const TAG_LIST_BLOB: u8 = 6;

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
    use gate::sys::macros::vec;

    use super::*;

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
