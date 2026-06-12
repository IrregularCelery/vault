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
//!     [8-bytes]           trashed (u64, 0 = live, unix timestapms = trashed)
//!     [4-bytes]           chunk_count (u32)
//!     each address:
//!       [32-bytes]        hash

use crate::crypto::cipher::{Error as CipherError, decrypt, encrypt};

use gate::{
    crypto::blake3,
    sys::{
        collections::btree_map::BTreeMap,
        string::{String, ToString},
        time::{SystemTime, UNIX_EPOCH},
        vec::Vec,
    },
};

const DOMAIN_INDEX: &[u8] = b"vault::index";

#[derive(Debug)]
pub enum Error {
    Cipher(CipherError),
    Corrupted(&'static str),
    NotFound,
    NotTrashed,
    AlreadyTrashed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Cipher(e) => write!(f, "cipher: {}", e),
            Error::Corrupted(e) => write!(f, "corrupted index: {}", e),
            Error::NotFound => write!(f, "file not found"),
            Error::NotTrashed => write!(f, "file is not in the trash"),
            Error::AlreadyTrashed => write!(f, "file is already in the trash"),
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
    pub trashed: u64,
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
        self.entries.get(path).filter(|e| e.trashed == 0)
    }

    pub fn addresses(&self) -> Vec<[u8; 32]> {
        self.entries
            .values()
            .filter(|e| e.trashed == 0)
            .flat_map(|e| e.addresses.iter().copied())
            .collect()
    }

    pub fn addresses_trashed(&self) -> Vec<[u8; 32]> {
        self.entries
            .values()
            .filter(|e| e.trashed != 0)
            .flat_map(|e| e.addresses.iter().copied())
            .collect()
    }

    pub fn remove(&mut self, path: &str) -> Option<Entry> {
        self.entries.remove(path)
    }

    pub fn trash(&mut self, path: &str) -> Result<(), Error> {
        let entry = self.entries.get_mut(path).ok_or(Error::NotFound)?;

        if entry.trashed != 0 {
            return Err(Error::AlreadyTrashed);
        }

        entry.trashed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1); // 1 instead of 0 so it's never mistaken for "live"

        Ok(())
    }

    pub fn restore(&mut self, path: &str) -> Result<(), Error> {
        let entry = self.entries.get_mut(path).ok_or(Error::NotFound)?;

        if entry.trashed == 0 {
            return Err(Error::NotTrashed);
        }

        entry.trashed = 0;

        Ok(())
    }

    pub fn purge(&mut self, path: &str) -> Result<Vec<[u8; 32]>, Error> {
        match self.entries.get(path) {
            None => return Err(Error::NotFound),
            Some(e) if e.trashed == 0 => return Err(Error::NotTrashed),
            _ => {
                if let Some(entry) = self.entries.remove(path) {
                    let live = self.addresses();

                    return Ok(entry
                        .addresses
                        .into_iter()
                        .filter(|a| !live.contains(a))
                        .collect());
                }
            }
        }

        Err(Error::NotFound)
    }

    pub fn purge_all(&mut self) -> Vec<[u8; 32]> {
        let live = self.addresses();
        let paths: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, v)| v.trashed != 0)
            .map(|(k, _)| k.to_string())
            .collect();
        let mut trashed_addresses = Vec::new();

        for path in paths {
            if let Some(entry) = self.entries.remove(&path) {
                for address in entry.addresses {
                    if !live.contains(&address) && !trashed_addresses.contains(&address) {
                        trashed_addresses.push(address);
                    }
                }
            }
        }

        trashed_addresses
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
            write_u64(&mut buf, entry.trashed);
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
            let trashed = read_u64(data, &mut current)?;
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
                    trashed,
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

pub struct Properties {
    pub size: u64,
    pub chunk_count: usize,
    pub modified: u64,
    pub trashed: u64,
}

#[cfg(test)]
mod tests {
    use gate::sys::macros::vec;

    use super::*;

    fn index() -> Index {
        let mut index = Index::new();

        index.insert(
            "music/song.mp3",
            Entry {
                addresses: vec![[0xABu8; 32], [0xCDu8; 32]],
                size: 5_000_000, // 5MB > 4MiB hence the two chunks
                modified: 1_700_000_000,
                trashed: 0,
            },
        );

        index.insert(
            "photos/image.png",
            Entry {
                addresses: vec![[0xEFu8; 32]],
                size: 2_048,
                modified: 1_710_000_000,
                trashed: 0,
            },
        );

        index
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let index = index();
        let bytes = index.serialize();
        let deserialized = Index::deserialize(&bytes).unwrap();

        assert_eq!(index, deserialized);
    }

    #[test]
    fn serialize_deserialize_trashed_roundtrip() {
        let mut index = index();

        index.trash("photos/image.png").unwrap();

        let deserialized = Index::deserialize(&index.serialize()).unwrap();

        assert_eq!(index, deserialized);
        assert_ne!(
            deserialized
                .entries
                .get("photos/image.png")
                .unwrap()
                .trashed,
            0
        );
    }

    #[test]
    fn lock_unlock_roundtrip() {
        let key = [0x55u8; 32];
        let index = index();
        let locked = index.lock(&key).unwrap();
        let unlocked = Index::unlock(&locked, &key).unwrap();

        assert_eq!(index, unlocked);
    }

    #[test]
    fn trash_and_restore_roundtrip() {
        let mut index = index();

        index.trash("photos/image.png").unwrap();

        assert!(index.get("photos/image.png").is_none());
        assert_ne!(index.entries.get("photos/image.png").unwrap().trashed, 0,);

        index.restore("photos/image.png").unwrap();

        assert!(index.get("photos/image.png").is_some());
        assert_eq!(index.entries.get("photos/image.png").unwrap().trashed, 0);
    }

    #[test]
    fn wrong_key() {
        let locked = index().lock(&[0x55u8; 32]).unwrap();

        assert!(Index::unlock(&locked, &[0x00u8; 32]).is_err());
    }

    #[test]
    fn empty_index() {
        let index = Index::new();
        let key = [0x01u8; 32];
        let locked = index.lock(&key).unwrap();
        let unlocked = Index::unlock(&locked, &key).unwrap();

        assert_eq!(unlocked.entries.len(), 0);
    }

    #[test]
    fn get_returns_none_trashed() {
        let mut index = index();

        index.trash("photos/image.png").unwrap();

        assert!(index.get("photos/image.png").is_none());
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
    fn addresses_excludes_trashed() {
        let mut index = index();

        index.trash("photos/image.png").unwrap();

        // Only the 2 chunks from `music/song.mp3`, ignored the one chunk of `photos/image.png`
        assert_eq!(index.addresses().len(), 2);
        assert_eq!(index.addresses_trashed().len(), 1);
    }

    #[test]
    fn purge_returns_trashed_addresses() {
        let mut index = index();

        index.trash("photos/image.png").unwrap();

        let deleted = index.purge("photos/image.png").unwrap();

        assert_eq!(deleted, vec![[0xEFu8; 32]]);
        assert!(!index.entries.contains_key("photos/image.png"));
    }

    #[test]
    fn purge_skips_live_shared_addresses() {
        let mut index = Index::new();
        let shared_addr = [0xAAu8; 32];

        index.insert(
            "a",
            Entry {
                addresses: vec![shared_addr],
                size: 1,
                modified: 0,
                trashed: 0,
            },
        );
        index.insert(
            "b",
            Entry {
                addresses: vec![shared_addr],
                size: 1,
                modified: 0,
                trashed: 0,
            },
        );
        index.trash("b").unwrap();

        let deleted = index.purge("b").unwrap();

        assert!(deleted.is_empty());
        assert!(index.get("a").is_some());
    }

    #[test]
    fn purge_rejects_live_entry() {
        let mut index = index();

        // Cannot purge a live entry
        assert!(index.purge("music/song.mp3").is_err());
    }

    #[test]
    fn purge_all_clears_trash() {
        let mut index = index();

        index.trash("photos/image.png").unwrap();
        index.trash("music/song.mp3").unwrap();

        let deleted = index.purge_all();

        assert!(index.entries.is_empty());
        assert_eq!(deleted.len(), 3); // 2 from song + 1 from image
    }

    #[test]
    fn insert_remove_roundtrip() {
        let mut index = Index::new();

        index.insert(
            "file.txt",
            Entry {
                addresses: vec![[0u8; 32]],
                size: 100,
                modified: 0,
                trashed: 0,
            },
        );

        assert!(index.get("file.txt").is_some());

        index.remove("file.txt");

        assert!(index.get("file.txt").is_none());
    }

    #[test]
    fn all_chunk_hashes() {
        let index = index();
        let hashes = index.addresses();

        // Sample has 2 + 1 = 3 chunk hashes
        assert_eq!(hashes.len(), 3);
    }
}
