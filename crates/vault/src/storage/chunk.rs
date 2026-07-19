//! Streaming file chunker and per-chunk key/address derivation.
//!
//! Large files are split into fixed-size chunks of up to [`CHUNK_SIZE`] bytes (4 MiB).
//! Each chunk gets an independent content-derived address and a unique per-chunk encryption key.

use gate::{
    crypto::blake3,
    sys::{io, macros::vec, vec::Vec},
};

/// Maximum size of a single chunk in bytes (4 MiB).
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// BLAKE3 domain tag used when deriving a per-chunk encryption key.
/// Separates chunk key derivation from the address derivation, ensuring the two are
/// independent even though they are derived from the same plaintext.
const DOMAIN_CHUNK_KEY: &[u8] = b"vault::chunk";

/// Errors that can occur while reading or processing chunks.
#[derive(Debug)]
pub enum Error {
    /// An I/O error.
    Io(io::Error),

    /// The source ended before a complete fixed-size read could be satisfied.
    UnexpectedEof,

    /// Specific message error.
    Other(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {}", e),
            Self::UnexpectedEof => write!(f, "unexpected end of file"),
            Self::Other(e) => write!(f, "{}", e),
        }
    }
}

/// A single chunk of borrowed raw (pre-encryption) file data.
#[derive(Debug)]
pub struct Chunk<'a> {
    /// The raw plaintext bytes of this chunk.
    pub data: &'a [u8],
}

impl<'a> Chunk<'a> {
    // TODO: Why not derive the `address` and the `key` hashes right as the instance is created,
    // avoiding two data reads.

    /// Crates a new [`Chunk`] and wraps `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Derives the content-addressed storage key for this chunk.
    ///
    /// Computed as `BLAKE3(key=encryption_key, chunk_data)`. Keying with the user's encryption key
    /// prevents cross-user address collisions for identical plaintext content.
    pub fn address(&self, encryption_key: &[u8; 32]) -> [u8; 32] {
        *blake3::keyed_hash(encryption_key, self.data).as_bytes()
    }

    /// Derives a unique per-chunk encryption key.
    ///
    /// Computed as `BLAKE3(key=encryption_key, DOMAIN_CHUNK_KEY || chunk_data)`.
    /// The domain tag distinguishes this key from the address hash, ensuring the two are
    /// independent even though they are derived from the same plaintext.
    pub fn key(&self, encryption_key: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(encryption_key);

        hasher.update(DOMAIN_CHUNK_KEY);
        hasher.update(self.data);

        *hasher.finalize().as_bytes()
    }
}

/// An iterator-style reader that yields successive [`Chunk`]s from an [`io::Read`] source.
pub struct Chunks<R: io::Read> {
    /// The source being read and split into chunks.
    reader: R,

    /// Reusable 4 MiB scratch buffer. Each call to `next_chunk` fills this buffer
    /// before returning a [`Chunk`].
    buf: Vec<u8>,
}

impl<R: io::Read> Chunks<R> {
    /// Creates a new chunker reading from `reader` with an allocated [`CHUNK_SIZE`] buffer.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: vec![0u8; CHUNK_SIZE],
        }
    }

    /// Reads the next chunk and returns it.
    ///
    /// Returns `Ok(None)` at end-of-file, `Ok(Some(chunk))` when data is available.
    pub fn next_chunk(&mut self) -> Result<Option<Chunk<'_>>, Error> {
        let mut total = 0;

        loop {
            match self.reader.read(&mut self.buf[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;

                    if total == CHUNK_SIZE {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue, // EINTR, retry
                Err(e) => return Err(Error::Io(e)),
            }
        }

        if total == 0 {
            return Ok(None);
        }

        Ok(Some(Chunk::new(&self.buf[..total])))
    }
}
