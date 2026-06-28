//! The Noise Protocol Framework (https://noiseprotocol.org/noise.html)
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

const PARAMETERS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
// Noise message size is 65535 (u16::MAX)
const MESSAGE_SIZE: usize = u16::MAX as usize - 16; // 16-byte AEAD tag

pub struct Transport<S: io::Read + io::Write> {
    stream: S,
    state: TransportState,
    peer_static_key: [u8; 32],
    handshake_hash: [u8; 32],
}

impl<S: io::Read + io::Write> Transport<S> {
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

    fn peer_static_key(&self) -> [u8; 32] {
        self.peer_static_key
    }

    fn handshake_hash(&self) -> [u8; 32] {
        self.handshake_hash
    }
}

fn stream_write<W: io::Write>(stream: &mut W, data: &[u8]) -> Result<(), Error> {
    let len = data.len() as u16;

    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()?;

    Ok(())
}

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

fn write_handshake_message(
    handshake: &mut HandshakeState,
    stream: &mut impl io::Write,
    buf: &mut [u8],
) -> Result<(), Error> {
    let len = handshake
        .write_message(&[], buf)
        .map_err(|_| Error::Handshake("initiator write message failed"))?;

    stream_write(stream, &buf[..len])
}

fn read_handshake_message(
    handshake: &mut HandshakeState,
    stream: &mut impl io::Read,
    buf: &mut [u8],
) -> Result<(), Error> {
    let message = stream_read(stream)?;

    handshake
        .read_message(&message, buf)
        .map_err(|_| Error::Handshake("initiator read message failed"))?;

    Ok(())
}
