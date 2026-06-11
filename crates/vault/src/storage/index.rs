//! Encrpted index as file manifest
//!
//! Binary serialization format (big-endian):
//!
//!   [4-bytes] entry_count (u32)
//!   each entry:
//!     [2-bytes]           path_len (u16)
//!     [path_len bytes]    path (UTF-8)
//!     [8-bytes]           size (u64)
//!     [8-bytes]           modified (u64)
//!     [4-bytes]           chunk_count (u32)
//!     each address:
//!       [32-bytes]        hash

use crate::crypto::cipher::{Error as CipherError, decrypt, encrypt};

use gate::{
    crypto::blake3,
    sys::{
        collections::btree_map::BTreeMap,
        string::{String, ToString},
        vec::Vec,
    },
};

const DOMAIN_INDEX: &[u8] = b"vault::index";

#[derive(Debug)]
pub enum Error {
    Cipher(CipherError),
    Corrupted(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Cipher(e) => write!(f, "cipher: {}", e),
            Error::Corrupted(e) => write!(f, "corrupted index: {}", e),
        }
    }
}

impl From<CipherError> for Error {
    fn from(value: CipherError) -> Self {
        Self::Cipher(value)
    }
}

#[derive(Debug, PartialEq)]
pub struct Entry {
    pub addresses: Vec<[u8; 32]>,
    pub size: u64,
    pub modified: u64,
}

#[derive(Debug, PartialEq)]
pub struct Index {
    pub entries: BTreeMap<String, Entry>,
}

impl Index {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, path: impl Into<String>, entry: Entry) {
        self.entries.insert(path.into(), entry);
    }

    pub fn get(&self, path: &str) -> Option<&Entry> {
        self.entries.get(path)
    }

    pub fn addresses(&self) -> Vec<[u8; 32]> {
        self.entries
            .values()
            .flat_map(|e| e.addresses.iter().copied())
            .collect()
    }

    pub fn remove(&mut self, path: &str) -> Option<Entry> {
        self.entries.remove(path)
    }

    pub fn address(public_key: &[u8; 32]) -> [u8; 32] {
        let mut input = Vec::with_capacity(12 + 32); // 12-bytes for the DOMAIN_INDEX size

        input.extend_from_slice(DOMAIN_INDEX);
        input.extend_from_slice(public_key);

        // storage key for the index blob
        *blake3::hash(&input).as_bytes()
    }

    pub fn serialize(&self) -> Vec<u8> {
        fn write_u16(buf: &mut Vec<u8>, value: u16) {
            buf.extend_from_slice(&value.to_be_bytes());
        }
        fn write_u32(buf: &mut Vec<u8>, value: u32) {
            buf.extend_from_slice(&value.to_be_bytes());
        }
        fn write_u64(buf: &mut Vec<u8>, value: u64) {
            buf.extend_from_slice(&value.to_be_bytes());
        }

        let mut buf = Vec::new();

        write_u32(&mut buf, self.entries.len() as u32);

        for (path, entry) in &self.entries {
            let path_bytes = path.as_bytes();

            write_u16(&mut buf, path_bytes.len() as u16);

            buf.extend_from_slice(path_bytes);

            write_u64(&mut buf, entry.size);
            write_u64(&mut buf, entry.modified);
            write_u32(&mut buf, entry.addresses.len() as u32);

            for hash in &entry.addresses {
                buf.extend_from_slice(hash);
            }
        }

        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, Error> {
        fn read_u16(data: &[u8], current: &mut usize) -> Result<u16, Error> {
            let end = *current + 2;

            if end > data.len() {
                return Err(Error::Corrupted("unexpected end reading u16"));
            }

            let mut bytes = [0u8; 2];

            bytes.copy_from_slice(&data[*current..end]);

            *current = end;

            Ok(u16::from_be_bytes(bytes))
        }

        fn read_u32(data: &[u8], current: &mut usize) -> Result<u32, Error> {
            let end = *current + 4;

            if end > data.len() {
                return Err(Error::Corrupted("unexpected end reading u32"));
            }

            let mut bytes = [0u8; 4];

            bytes.copy_from_slice(&data[*current..end]);

            *current = end;

            Ok(u32::from_be_bytes(bytes))
        }

        fn read_u64(data: &[u8], current: &mut usize) -> Result<u64, Error> {
            let end = *current + 8;

            if end > data.len() {
                return Err(Error::Corrupted("unexpected end reading u64"));
            }

            let mut bytes = [0u8; 8];

            bytes.copy_from_slice(&data[*current..end]);

            *current = end;

            Ok(u64::from_be_bytes(bytes))
        }

        fn read_str(data: &[u8], current: &mut usize, len: usize) -> Result<String, Error> {
            let end = *current + len;

            if end > data.len() {
                return Err(Error::Corrupted("unexpected end reading string"));
            }

            let string = core::str::from_utf8(&data[*current..end])
                .map_err(|_| Error::Corrupted("invalid UTF-8 in path"))?
                .to_string();

            *current = end;

            Ok(string)
        }

        fn read_hash(data: &[u8], current: &mut usize) -> Result<[u8; 32], Error> {
            let end = *current + 32; // Hashes are 32 bytes

            if end > data.len() {
                return Err(Error::Corrupted("unexpected end reading hash"));
            }

            let mut hash = [0u8; 32];

            hash.copy_from_slice(&data[*current..end]);

            *current = end;

            Ok(hash)
        }

        let mut current = 0usize;
        let entry_count = read_u32(data, &mut current)? as usize;
        let mut entries = BTreeMap::new();

        for _ in 0..entry_count {
            let path_len = read_u16(data, &mut current)? as usize;
            let path = read_str(data, &mut current, path_len)?;
            let size = read_u64(data, &mut current)?;
            let modified = read_u64(data, &mut current)?;
            let chunk_count = read_u32(data, &mut current)? as usize;
            let mut addresses = Vec::with_capacity(chunk_count);

            for _ in 0..chunk_count {
                let hash = read_hash(data, &mut current)?;

                addresses.push(hash);
            }

            entries.insert(
                path,
                Entry {
                    addresses,
                    size,
                    modified,
                },
            );
        }

        Ok(Self { entries })
    }

    pub fn lock(&self, encryption_key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let plaintext = self.serialize();

        Ok(encrypt(encryption_key, &plaintext)?)
    }

    pub fn unlock(blob: &[u8], encryption_key: &[u8; 32]) -> Result<Self, Error> {
        let plaintext = decrypt(encryption_key, blob)?;

        Self::deserialize(&plaintext)
    }
}

impl Default for Index {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use gate::sys::macros::vec;

    use super::*;

    fn sample() -> Index {
        let mut index = Index::new();

        index.insert(
            "music/song.mp4",
            Entry {
                addresses: vec![[0xABu8; 32], [0xCDu8; 32]],
                size: 5_000_000, // 5MB > 4MiB hence the two chunks
                modified: 1_700_000_000,
            },
        );

        index.insert(
            "photos/image.jpg",
            Entry {
                addresses: vec![[0xEFu8; 32]],
                size: 2_048,
                modified: 1_710_000_000,
            },
        );

        index
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let original = sample();
        let bytes = original.serialize();
        let restored = Index::deserialize(&bytes).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn lock_unlock_roundtrip() {
        let key = [0x55u8; 32];
        let original = sample();
        let blob = original.lock(&key).unwrap();
        let restored = Index::unlock(&blob, &key).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn wrong_key() {
        let blob = sample().lock(&[0x55u8; 32]).unwrap();

        assert!(Index::unlock(&blob, &[0x00u8; 32]).is_err());
    }

    #[test]
    fn empty_index() {
        let index = Index::new();
        let key = [0x01u8; 32];
        let blob = index.lock(&key).unwrap();
        let restored = Index::unlock(&blob, &key).unwrap();

        assert_eq!(restored.entries.len(), 0);
    }

    #[test]
    fn deterministic_address() {
        let public_key = [0xFFu8; 32];

        assert_eq!(Index::address(&public_key), Index::address(&public_key));
    }

    #[test]
    fn different_addresses() {
        let key1 = Index::address(&[0x01u8; 32]);
        let key2 = Index::address(&[0x02u8; 32]);

        assert_ne!(key1, key2);
    }

    #[test]
    fn insert_remove() {
        let mut index = Index::new();

        index.insert(
            "file.txt",
            Entry {
                addresses: vec![[0u8; 32]],
                size: 100,
                modified: 0,
            },
        );

        assert!(index.get("file.txt").is_some());

        index.remove("file.txt");

        assert!(index.get("file.txt").is_none());
    }

    #[test]
    fn all_chunk_hashes() {
        let index = sample();
        let hashes = index.addresses();

        // Sample has 2 + 1 = 3 chunk hashes
        assert_eq!(hashes.len(), 3);
    }
}
