use gate::sys::{macros::vec, vec::Vec};

pub const CHUNK_SIZE: usize = 4 * 1024 * 1024; // Each chunk's max capacity is 4 MiB

#[derive(Debug)]
pub struct Chunk {
    data: Vec<u8>,
}

impl Chunk {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

pub fn split(bytes: &[u8]) -> Vec<Chunk> {
    if bytes.is_empty() {
        return vec![Chunk::new(vec![])];
    }

    bytes
        .chunks(CHUNK_SIZE)
        .map(|c| Chunk::new(c.to_vec()))
        .collect()
}

// TODO: This approach is absolutely atrocious and must be re-written as a streaming re-assembler
pub fn reassemble(chunks: &[Chunk]) -> Vec<u8> {
    let total = chunks.iter().map(|c| c.data.len()).sum();
    let mut out = Vec::with_capacity(total);

    for chunk in chunks {
        out.extend_from_slice(&chunk.data);
    }

    out
}
