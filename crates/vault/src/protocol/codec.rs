use gate::{codec::binary, sys::vec::Vec};

pub const PROTOCOL_VERSION: u16 = 1;
pub const DOMAIN_PROTOCOL: &[u8] = b"vault::protocol";

#[derive(Debug)]
pub enum Error {
    Codec(binary::Error),
    UnsupportedProtocolVersion(u16),
    UnknownTag(u8),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(e) => write!(f, "codec: {}", e),
            Self::UnsupportedProtocolVersion(v) => write!(f, "unsupported protocol version: {}", v),
            Self::UnknownTag(t) => write!(f, "unknown tag: {}", t),
        }
    }
}

impl From<binary::Error> for Error {
    fn from(value: binary::Error) -> Self {
        Self::Codec(value)
    }
}

#[derive(Debug, PartialEq)]
pub struct ClientInit {
    pub signing_key: [u8; 32],
    pub exchange_key: [u8; 32],

    pub timestamp: u64,

    pub signature: [u8; 64],
}

impl ClientInit {
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        // `+ 2` for the PROTOCOL_VERSION bytes (u16)
        let mut writer = binary::Writer::with_capacity(core::mem::size_of::<ClientInit>() + 2);

        // TODO: Add client verison too.
        writer.write_u16(PROTOCOL_VERSION);
        writer.write_bytes(&self.signing_key);
        writer.write_bytes(&self.exchange_key);
        writer.write_u64(self.timestamp);
        writer.write_bytes(&self.signature);

        Ok(writer.finish())
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, Error> {
        // `+ 2` for the PROTOCOL_VERSION bytes (u16)
        if data.len() != core::mem::size_of::<ClientInit>() + 2 {
            return Err(Error::Codec(binary::Error::Other(
                "Corrupted `client init` was found",
            )));
        }

        let mut reader = binary::Reader::new(data);

        let protocol_version = reader.read_u16()?;

        if protocol_version != PROTOCOL_VERSION {
            return Err(Error::UnsupportedProtocolVersion(protocol_version));
        }

        let signing_key = *reader.read_bytes()?;
        let exchange_key = *reader.read_bytes()?;
        let timestamp = reader.read_u64()?;
        let signature = *reader.read_bytes()?;

        Ok(Self {
            signing_key,
            exchange_key,
            timestamp,
            signature,
        })
    }

    pub fn build_signing_message(&self, protocol_hash: &[u8; 32]) -> [u8; 121] {
        // `+ 2` for the `PROTOCOL_VERSION` bytes (u16)
        // `- 64` to ignore `signature` field
        // `+ 32` for the `protocol_hash`
        let mut out = [0u8; DOMAIN_PROTOCOL.len() + 2 + (core::mem::size_of::<Self>() - 64) + 32];
        let mut offset = 0;

        let mut append = |slice: &[u8]| {
            let len = slice.len();

            out[offset..offset + len].copy_from_slice(slice);
            offset += len;
        };

        append(DOMAIN_PROTOCOL);
        append(&PROTOCOL_VERSION.to_be_bytes());
        append(&self.signing_key);
        append(&self.exchange_key);
        append(&self.timestamp.to_be_bytes());
        append(protocol_hash);

        out
    }
}
