use gate::{
    crypto::blake3,
    sys::{io, macros::vec, vec::Vec},
};

pub const CHUNK_SIZE: usize = 4 * 1024 * 1024; // Each chunk's max capacity is 4 MiB

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Other(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O: {}", e),
            Error::Other(e) => write!(f, "{}", e),
        }
    }
}

#[derive(Debug)]
pub struct Chunk<'a> {
    pub data: &'a [u8],
}

impl<'a> Chunk<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn address(&self, encryption_key: &[u8; 32]) -> [u8; 32] {
        *blake3::keyed_hash(encryption_key, self.data).as_bytes()
    }
}

pub struct Chunks<R: io::Read> {
    reader: R,
    buf: Vec<u8>,
}

impl<R: io::Read> Chunks<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: vec![0u8; CHUNK_SIZE],
        }
    }

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
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Io(e)),
            }
        }

        if total == 0 {
            return Ok(None);
        }

        Ok(Some(Chunk::new(&self.buf[..total])))
    }
}
