//! The [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
//!
//!   XX:
//!     -> e
//!     <- e, ee, s, es
//!     -> s, se

use crate::transport::{Backend, Error};

use gate::{
    sys::{io, macros::vec, vec::Vec},
    transport::noise::{Builder, HandshakeState, TransportState},
};

/// Full Noise protocol parameter string.
///
/// Encodes:
///
/// - pattern: `XX` (mutual authentication, both parties transmit their static keys)
/// - key exchange: `25519` (X25519 ephemeral and static keys)
/// - cipher: `ChaChaPoly` (ChaCha20-Poly1305 AEAD)
/// - hash: `BLAKE2s` (transcript hashing)
const PARAMETERS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
/// Maximum plaintext payload per Noise transport message.
/// Noise's hard ceiling is `u16::MAX` (65535) bytes per message; 16 bytes are consumed by
/// the AEAD tag, leaving 65519 bytes of usable payload.
const MESSAGE_SIZE: usize = u16::MAX as usize - 16; // 16-byte AEAD tag

/// A Noise XX transport wrapping a bidirectional byte stream.
///
/// Messages may exceed Noise's 65535-byte limit but large payloads are split into multiple Noise
/// messages, with the first one carrying a 4-byte big-endian total length prefix.
pub struct Transport<S: io::Read + io::Write> {
    /// The underlying byte stream. Handles all reads and writes.
    stream: S,

    /// The Noise state machine after the handshake completes.
    state: TransportState,

    /// The remote peer's verified X25519 static public key, extracted from the Noise handshake.
    /// On the client side this is the server's key and on the server side it is the client's key.
    peer_static_key: [u8; 32],

    /// The Noise handshake transcript hash, identical on both sides after a successful handshake.
    handshake_hash: [u8; 32],
}

impl<S: io::Read + io::Write> Transport<S> {
    /// Completes the Noise XX handshake as the `responder` (server side).
    ///
    /// Message order:
    ///
    /// `  <- e`                (receive)
    /// `  -> e, ee, s, es`     (send)
    /// `  <- s, se`            (receive)
    ///
    /// On success, `peer_static_key` holds the client's verified X25519 static key.
    pub fn accept(mut stream: S, local_private_key: &[u8; 32]) -> Result<Self, Error> {
        let params = PARAMETERS
            .parse()
            .map_err(|_| Error::Handshake("invalid Noise parameters"))?;
        let mut handshake = Builder::new(params)
            .local_private_key(local_private_key)
            .map_err(|_| Error::Handshake("local private key is already set"))?
            .build_responder()
            .map_err(|_| Error::Handshake("failed to build responder"))?;
        let mut buf = vec![0u8; MESSAGE_SIZE + 16]; // 16-byte AEAD tag

        // First message: responder receives
        read_handshake_message(&mut handshake, &mut stream, &mut buf)?;

        // Second message: responder sends
        write_handshake_message(&mut handshake, &mut stream, &mut buf)?;

        // Third message: responder receives
        read_handshake_message(&mut handshake, &mut stream, &mut buf)?;

        let peer_static_key = handshake
            .get_remote_static()
            .and_then(|k| k.try_into().ok())
            .ok_or(Error::Handshake("no remote static key after XX handshake"))?;
        let handshake_hash = handshake
            .get_handshake_hash()
            .try_into()
            .map_err(|_| Error::Handshake("invalid length for handshake hash"))?;
        let state = handshake
            .into_transport_mode()
            .map_err(|_| Error::Handshake("failed to enter transport mode"))?;

        Ok(Self {
            stream,
            state,
            peer_static_key,
            handshake_hash,
        })
    }

    /// Completes the Noise XX handshake as the `initiator` (client side).
    ///
    /// Message order:
    ///
    /// `  -> e`                (send)
    /// `  <- e, ee, s, es`     (receive)
    /// `  -> s, se`            (send)
    ///
    /// On success, `peer_static_key` holds the server's verified X25519 static key.
    pub fn connect(mut stream: S, local_private_key: &[u8; 32]) -> Result<Self, Error> {
        let params = PARAMETERS
            .parse()
            .map_err(|_| Error::Handshake("invalid Noise parameters"))?;
        let mut handshake = Builder::new(params)
            .local_private_key(local_private_key)
            .map_err(|_| Error::Handshake("local private key is already set"))?
            .build_initiator()
            .map_err(|_| Error::Handshake("failed to build initiator"))?;
        let mut buf = vec![0u8; MESSAGE_SIZE + 16]; // 16-byte AEAD tag

        // First message: initiator sends
        write_handshake_message(&mut handshake, &mut stream, &mut buf)?;

        // Second message: initiator receives
        read_handshake_message(&mut handshake, &mut stream, &mut buf)?;

        // Third message: initiator sends
        write_handshake_message(&mut handshake, &mut stream, &mut buf)?;

        let peer_static_key = handshake
            .get_remote_static()
            .and_then(|k| k.try_into().ok())
            .ok_or(Error::Handshake("no remote static key after XX handshake"))?;
        let handshake_hash = handshake
            .get_handshake_hash()
            .try_into()
            .map_err(|_| Error::Handshake("invalid length for handshake hash"))?;
        let state = handshake
            .into_transport_mode()
            .map_err(|_| Error::Handshake("failed to enter transport mode"))?;

        Ok(Self {
            stream,
            state,
            peer_static_key,
            handshake_hash,
        })
    }
}

impl<S: io::Read + io::Write> Backend for Transport<S> {
    /// Encrypts and sends `data` as one or more Noise transport messages.
    ///
    /// The first message contains a 4-byte big-endian total length prefix, followed by up to
    /// [`MESSAGE_SIZE`] - 4 bytes of payload. Any remaining data is split into subsequent
    /// [`MESSAGE_SIZE`]-byte messages.
    fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        // The first chunk has 4 bytes reserved for the data length prefix
        let first_chunk_len = core::cmp::min(data.len(), MESSAGE_SIZE - 4);
        let (first, second) = data.split_at(first_chunk_len);

        let mut first_chunk = Vec::with_capacity(4 + first.len());
        let total_len = u32::try_from(data.len()).map_err(|_| Error::MessageTooLarge)?;

        first_chunk.extend_from_slice(&total_len.to_be_bytes());
        first_chunk.extend_from_slice(first);

        let mut message = vec![0u8; MESSAGE_SIZE + 16]; // 16-byte AEAD tag
        let len = self
            .state
            .write_message(&first_chunk, &mut message)
            .map_err(|_| Error::Handshake("Noise write message failed"))?;

        stream_write(&mut self.stream, &message[..len])?;

        for chunk in second.chunks(MESSAGE_SIZE) {
            let len = self
                .state
                .write_message(chunk, &mut message)
                .map_err(|_| Error::Handshake("Noise write message failed"))?;

            stream_write(&mut self.stream, &message[..len])?;
        }

        Ok(())
    }

    /// Receives and decrypts a message, reassembling it from multiple Noise messages.
    ///
    /// Reads the 4-byte length `total_len` prefix from the first message, then continues reading
    /// messages until exactly that many bytes are accumulated.
    fn recv(&mut self) -> Result<Vec<u8>, Error> {
        let first = stream_read(&mut self.stream)?;
        let mut message = vec![0u8; MESSAGE_SIZE + 16]; // 16-byte AEAD tag
        let len = self
            .state
            .read_message(&first, &mut message)
            .map_err(|_| Error::Handshake("Noise read message failed"))?;

        if len < 4 {
            return Err(Error::Handshake("corrupted message: missing length prefix"));
        }

        // `len` is stored as u32 (4 bytes)
        let total_len = u32::from_be_bytes(message[..4].try_into().unwrap()) as usize;
        // TODO: `total_len` should probably be checked.
        let mut data = Vec::with_capacity(total_len);

        data.extend_from_slice(&message[4..len]);

        while data.len() < total_len {
            // If subsequent chunks drop mid-loop, `stream_read` throws `Error::Closed`
            let chunk = stream_read(&mut self.stream).map_err(|e| match e {
                Error::Closed => Error::Handshake("corrupted message: unexpected truncation"),
                other => other,
            })?;
            let len = self
                .state
                .read_message(&chunk, &mut message)
                .map_err(|_| Error::Handshake("Noise read message failed"))?;

            data.extend_from_slice(&message[..len]);
        }

        if data.len() > total_len {
            return Err(Error::Handshake(
                "corrupted message: received more data than expected",
            ));
        }

        Ok(data)
    }

    /// The remote peer's verified long-term static public key / identifier.
    ///
    /// For `Noise`: remote X25519 static public key.
    fn peer_static_key(&self) -> [u8; 32] {
        self.peer_static_key
    }

    fn handshake_hash(&self) -> [u8; 32] {
        self.handshake_hash
    }
}

/// Writes `data` to `stream` with a 2-byte big-endian length prefix, then flushes.
fn stream_write<W: io::Write>(stream: &mut W, data: &[u8]) -> Result<(), Error> {
    let len = data.len() as u16;

    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()?;

    Ok(())
}

/// Reads a 2-byte big-endian length prefix from `stream`, then reads exactly that many bytes.
fn stream_read<R: io::Read>(stream: &mut R) -> Result<Vec<u8>, Error> {
    // `len` is stored as u16 (2 bytes)
    let mut len_buf = [0u8; 2];

    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(Error::Closed);
        }
        Err(e) => return Err(Error::Io(e)),
    }

    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];

    match stream.read_exact(&mut buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(Error::Handshake("unexpected end of message"));
        }
        Err(e) => return Err(Error::Io(e)),
    }

    Ok(buf)
}

/// Writes a single Noise handshake message to `stream` with an empty payload.
fn write_handshake_message(
    handshake: &mut HandshakeState,
    stream: &mut impl io::Write,
    buf: &mut [u8],
) -> Result<(), Error> {
    let len = handshake
        .write_message(&[], buf)
        .map_err(|_| Error::Handshake("handshake write message failed"))?;

    stream_write(stream, &buf[..len])
}

/// Reads and processes a single Noise handshake message from `stream`.
fn read_handshake_message(
    handshake: &mut HandshakeState,
    stream: &mut impl io::Read,
    buf: &mut [u8],
) -> Result<(), Error> {
    let message = stream_read(stream)?;

    handshake
        .read_message(&message, buf)
        .map_err(|_| Error::Handshake("handshake read message failed"))?;

    Ok(())
}
