//! Shared protocol codec types, and the [`ClientInit`] handshake message.

use gate::{codec::binary, sys::vec::Vec};

/// Current protocol version. Incrementing this is a breaking change for older clients.
pub const PROTOCOL_VERSION: u16 = 1;
/// Domain tag included in the [`ClientInit`] signing message.
pub const DOMAIN_PROTOCOL: &[u8] = b"vault::protocol";

/// Errors that can occur while processing protocol messages.
#[derive(Debug)]
pub enum Error {
    /// A binary serialization or deserialization error.
    Codec(binary::Error),

    /// The protocol version field does not match [`PROTOCOL_VERSION`]. The value is the version
    /// that was actually found.
    UnsupportedProtocolVersion(u16),

    /// A request or response tag byte did not match any of the known variants.
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

/// The first application-level message sent by the client after the a successful handshake.
///
/// Authenticates the client's identity by signing a fixed-layout message that binds the protocol
/// version and public keys. The handshake hash binding ties the signature to this
/// specific transport session, preventing replay across sessions.
#[derive(Debug, PartialEq)]
pub struct ClientInit {
    /// The client's public signing key.
    pub signing_key: [u8; 32],

    /// The client's public exchange key.
    pub exchange_key: [u8; 32],

    /// Unix timestamp (seconds) at the time of the message.
    pub timestamp: u64,

    /// The signature over `build_signing_message(handshake_hash)`, binding this identity claim
    /// to the specific transport session.
    pub signature: [u8; 64],
}

impl ClientInit {
    /// Serializes [`ClientInit`] with a leading `u16` protocol version tag.
    ///
    /// # Errors
    ///
    /// - No errors can occur at this stage
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

    /// Deserializes and validates the protocol version.
    ///
    /// # Errors
    ///
    /// - [`Error::Codec`]: If `data` has the wrong format or is corrupted.
    /// - [`Error::UnsupportedProtocolVersion`]: If the version field does not match
    ///   [`PROTOCOL_VERSION`]
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

    /// Constructs the exact byte sequence that the client signs and the server verifies.
    ///
    /// Fixed 121-byte layout:
    /// `DOMAIN_PROTOCOL || PROTOCOL_VERSION || signing_key || exchange_key || timestamp || handshake_hash`
    ///
    /// Including the handshake hash ties the signature to the specific transport session,
    /// preventing any replayed [`ClientInit`] from authenticating on a different connection.
    pub fn build_signing_message(&self, handshake_hash: &[u8; 32]) -> [u8; 121] {
        // `+ 2` for the `PROTOCOL_VERSION` bytes (u16)
        // `- 64` to ignore `signature` field
        // `+ 32` for the `handshake_hash`
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
        append(handshake_hash);

        out
    }
}
