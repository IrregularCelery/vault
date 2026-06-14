//! Encrypted manifest as blob index lookup
//!
//! Binary serialization format (big-endian):
//!
//!   [2-bytes] version (u16)
//!   [4-bytes] entry_count (u32)
//!   each entry:
//!     [2-bytes]           path_len (u16)
//!     [path_len bytes]    path (UTF-8)
//!     [60-bytes]          encrypted_pfk (per-file key, 12 (nonce) + 16 (encryption tag) + 32 (key))
//!     [8-bytes]           size (u64)
//!     [8-bytes]           modified (u64)
//!     [8-bytes]           trashed (u64, 0 = live, unix timestapms = trashed)
//!     [4-bytes]           chunk_count (u32)
//!     each address:
//!       [32-bytes]        hash

use crate::crypto::cipher::{self, decrypt, encrypt};

use gate::{
    crypto::blake3,
    sys::{
        collections::btree_map::BTreeMap,
        string::String,
        time::{SystemTime, UNIX_EPOCH},
        vec::Vec,
    },
};

const MANIFEST_VERSION: u16 = 1;
const DOMAIN_MANIFEST: &[u8] = b"vault::manifest";

#[derive(Debug)]
pub enum Error {
    Cipher(cipher::Error),
    Corrupted(&'static str),
    UnsupportedVersion(u16),
    NotFound,
    NotTrashed,
    AlreadyTrashed,
    Tampered,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cipher(e) => write!(f, "cipher: {}", e),
            Self::Corrupted(e) => write!(f, "corrupted manifest: {}", e),
            Self::UnsupportedVersion(v) => write!(f, "unsupported manifest version: {}", v),
            Self::NotFound => write!(f, "file not found"),
            Self::NotTrashed => write!(f, "file is not in the trash"),
            Self::AlreadyTrashed => write!(f, "file is already in the trash"),
            Self::Tampered => write!(f, "tampered manifest"),
        }
    }
}

impl From<cipher::Error> for Error {
    fn from(value: cipher::Error) -> Self {
        match value {
            cipher::Error::InvalidSignature => Self::Tampered,
            other => Self::Cipher(other),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Entry {
    pub encrypted_pfk: [u8; 60],
    pub addresses: Vec<[u8; 32]>,
    pub size: u64,
    pub modified: u64,
    pub trashed: u64,
}

#[derive(Debug, PartialEq)]
pub struct Manifest {
    pub entries: BTreeMap<String, Entry>,
}

impl Manifest {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, path: &str, entry: Entry) {
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

    pub fn rename(&mut self, old_path: &str, new_path: &str) -> Result<(), Error> {
        let entry = self.entries.remove(old_path).ok_or(Error::NotFound)?;

        self.entries.insert(new_path.into(), entry);

        Ok(())
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
            .map(|(k, _)| k.into())
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
        let mut input = Vec::with_capacity(DOMAIN_MANIFEST.len() + 32);

        input.extend_from_slice(DOMAIN_MANIFEST);
        input.extend_from_slice(public_key);

        // storage key for the manifest blob
        *blake3::hash(&input).as_bytes()
    }

    pub fn derive_pfk(encryption_key: &[u8; 32], content_hash: &[u8; 32]) -> [u8; 32] {
        *blake3::keyed_hash(encryption_key, content_hash).as_bytes()
    }

    pub fn encrypt_pfk(pfk: &[u8; 32], encryption_key: &[u8; 32]) -> Result<[u8; 60], Error> {
        let encrypted = encrypt(encryption_key, pfk)?;
        let mut array = [0u8; 60];

        array.copy_from_slice(&encrypted);

        Ok(array)
    }

    pub fn decrypt_pfk(pfk: &[u8], encryption_key: &[u8; 32]) -> Result<[u8; 32], Error> {
        let decrypted = decrypt(encryption_key, pfk)?;

        if decrypted.len() != 32 {
            return Err(Error::Corrupted("invalid length for per-file key"));
        }

        let mut key = [0u8; 32];

        key.copy_from_slice(&decrypted);

        Ok(key)
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

        write_u16(&mut buf, MANIFEST_VERSION);
        write_u32(&mut buf, self.entries.len() as u32);

        for (path, entry) in &self.entries {
            let path_bytes = path.as_bytes();

            write_u16(&mut buf, path_bytes.len() as u16);

            buf.extend_from_slice(path_bytes);
            buf.extend_from_slice(&entry.encrypted_pfk);

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

        fn read_bytes<const N: usize>(data: &[u8], current: &mut usize) -> Result<[u8; N], Error> {
            let end = *current + N;

            if end > data.len() {
                return Err(Error::Corrupted("unexpected end reading bytes"));
            }

            let bytes = data[*current..end]
                .try_into()
                .map_err(|_| Error::Corrupted("failed to convert to array"))?;

            *current = end;

            Ok(bytes)
        }

        fn read_str(data: &[u8], current: &mut usize, len: usize) -> Result<String, Error> {
            let end = *current + len;

            if end > data.len() {
                return Err(Error::Corrupted("unexpected end reading string"));
            }

            let string = core::str::from_utf8(&data[*current..end])
                .map_err(|_| Error::Corrupted("invalid UTF-8 in path"))?
                .into();

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
        let version = read_u16(data, &mut current)?;

        // NOTE: If we ever bump the version, this should gracefully handle data migration.
        if version != MANIFEST_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        let entry_count = read_u32(data, &mut current)? as usize;
        let mut entries = BTreeMap::new();

        for _ in 0..entry_count {
            let path_len = read_u16(data, &mut current)? as usize;
            let path = read_str(data, &mut current, path_len)?;
            let encrypted_pfk = read_bytes(data, &mut current)?; // 12 (nonce) + 16 (tag) + 32
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
                    encrypted_pfk,
                    addresses,
                    size,
                    modified,
                    trashed,
                },
            );
        }

        Ok(Self { entries })
    }

    pub fn lock(
        &self,
        encryption_key: &[u8; 32],
        sign: impl Fn(&[u8]) -> [u8; 64],
    ) -> Result<Vec<u8>, Error> {
        let plaintext = self.serialize();
        let locked = cipher::lock(encryption_key, &plaintext, sign)?;

        Ok(locked)
    }

    pub fn unlock(
        blob: &[u8],
        encryption_key: &[u8; 32],
        verify: impl Fn(&[u8], &[u8; 64]) -> bool,
    ) -> Result<Self, Error> {
        let unlocked = cipher::unlock(encryption_key, blob, verify)?;

        Self::deserialize(&unlocked)
    }
}

impl Default for Manifest {
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

    fn manifest() -> Manifest {
        let mut manifest = Manifest::new();

        manifest.insert(
            "music/song.mp3",
            Entry {
                encrypted_pfk: [0x12; 60],
                addresses: vec![[0xABu8; 32], [0xCDu8; 32]],
                size: 5_000_000, // 5MB > 4MiB hence the two chunks
                modified: 1_700_000_000,
                trashed: 0,
            },
        );

        manifest.insert(
            "photos/image.png",
            Entry {
                encrypted_pfk: [0x12; 60],
                addresses: vec![[0xEFu8; 32]],
                size: 2_048,
                modified: 1_710_000_000,
                trashed: 0,
            },
        );

        manifest
    }

    fn sign(data: &[u8]) -> [u8; 64] {
        let mut sig = [0u8; 64];

        // XOR the first 64 bytes of data into the signature so tampering is detectable
        for (i, &b) in data.iter().take(64).enumerate() {
            sig[i] = b ^ 0xAB;
        }

        sig
    }

    fn verify(data: &[u8], sig: &[u8; 64]) -> bool {
        sign(data) == *sig
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let manifest = manifest();
        let bytes = manifest.serialize();
        let deserialized = Manifest::deserialize(&bytes).unwrap();

        assert_eq!(manifest, deserialized);
    }

    #[test]
    fn serialize_deserialize_trashed_roundtrip() {
        let mut manifest = manifest();

        manifest.trash("photos/image.png").unwrap();

        let deserialized = Manifest::deserialize(&manifest.serialize()).unwrap();

        assert_eq!(manifest, deserialized);
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
    fn insert_remove_roundtrip() {
        let mut manifest = Manifest::new();

        manifest.insert(
            "file.txt",
            Entry {
                encrypted_pfk: [0x12; 60],
                addresses: vec![[0u8; 32]],
                size: 100,
                modified: 0,
                trashed: 0,
            },
        );

        assert!(manifest.get("file.txt").is_some());

        manifest.trash("file.txt").unwrap();

        assert!(manifest.get("file.txt").is_none());
    }

    #[test]
    fn lock_unlock_roundtrip() {
        let key = [0x55u8; 32];
        let manifest = manifest();
        let locked = manifest.lock(&key, sign).unwrap();
        let unlocked = Manifest::unlock(&locked, &key, verify).unwrap();

        assert_eq!(manifest, unlocked);
    }

    #[test]
    fn trash_and_restore_roundtrip() {
        let mut manifest = manifest();

        manifest.trash("photos/image.png").unwrap();

        assert!(manifest.get("photos/image.png").is_none());
        assert_ne!(manifest.entries.get("photos/image.png").unwrap().trashed, 0,);

        manifest.restore("photos/image.png").unwrap();

        assert!(manifest.get("photos/image.png").is_some());
        assert_eq!(manifest.entries.get("photos/image.png").unwrap().trashed, 0);
    }

    #[test]
    fn pfk_encrypt_decrypt_roundtrip() {
        let encryption_key = [0x69u8; 32];
        let content_hash = [0x12u8; 32];
        let pfk = Manifest::derive_pfk(&encryption_key, &content_hash);
        let encrypted = Manifest::encrypt_pfk(&pfk, &encryption_key).unwrap();
        let decrypted = Manifest::decrypt_pfk(&encrypted, &encryption_key).unwrap();

        assert_eq!(pfk, decrypted);
    }

    #[test]
    fn pfk_wrong_key() {
        let encryption_key = [0x69u8; 32];
        let content_hash = [0x12u8; 32];
        let pfk = Manifest::derive_pfk(&encryption_key, &content_hash);
        let encrypted = Manifest::encrypt_pfk(&pfk, &encryption_key).unwrap();
        let decrypted = Manifest::decrypt_pfk(&encrypted, &[0x67; 32]);

        assert!(decrypted.is_err());
    }

    #[test]
    fn version_mismatch() {
        let manifest = manifest();
        let mut bytes = manifest.serialize();

        // Change the version bytes
        bytes[0] = 0xFF;
        bytes[1] = 0xFF;

        let deserialized = Manifest::deserialize(&bytes);

        assert!(matches!(
            deserialized,
            Err(Error::UnsupportedVersion(0xFFFF))
        ));
    }

    #[test]
    fn wrong_key() {
        let locked = manifest().lock(&[0x55u8; 32], sign).unwrap();

        assert!(Manifest::unlock(&locked, &[0x00u8; 32], verify).is_err());
    }

    #[test]
    fn empty_manifest() {
        let manifest = Manifest::new();
        let key = [0x01u8; 32];
        let locked = manifest.lock(&key, sign).unwrap();
        let unlocked = Manifest::unlock(&locked, &key, verify).unwrap();

        assert_eq!(unlocked.entries.len(), 0);
    }

    #[test]
    fn rename() {
        let mut manifest = manifest();

        manifest
            .rename("photos/image.png", "photos/image_renamed.png")
            .unwrap();

        assert!(manifest.get("photos/image.png").is_none());
        assert!(manifest.get("photos/image_renamed.png").is_some());
    }

    #[test]
    fn rename_not_found() {
        let mut manifest = manifest();
        let renamed = manifest.rename("nonexistent.txt", "nonexistent_renamed.txt");

        assert!(matches!(renamed, Err(Error::NotFound)));
    }

    #[test]
    fn get_returns_none_trashed() {
        let mut manifest = manifest();

        manifest.trash("photos/image.png").unwrap();

        assert!(manifest.get("photos/image.png").is_none());
    }

    #[test]
    fn deterministic_address() {
        let public_key = [0xFFu8; 32];

        assert_eq!(
            Manifest::address(&public_key),
            Manifest::address(&public_key)
        );
    }

    #[test]
    fn different_addresses() {
        let key1 = Manifest::address(&[0x01u8; 32]);
        let key2 = Manifest::address(&[0x02u8; 32]);

        assert_ne!(key1, key2);
    }

    #[test]
    fn addresses_excludes_trashed() {
        let mut manifest = manifest();

        manifest.trash("photos/image.png").unwrap();

        // Only the 2 chunks from `music/song.mp3`, ignored the one chunk of `photos/image.png`
        assert_eq!(manifest.addresses().len(), 2);
        assert_eq!(manifest.addresses_trashed().len(), 1);
    }

    #[test]
    fn purge_returns_trashed_addresses() {
        let mut manifest = manifest();

        manifest.trash("photos/image.png").unwrap();

        let deleted = manifest.purge("photos/image.png").unwrap();

        assert_eq!(deleted, vec![[0xEFu8; 32]]);
        assert!(!manifest.entries.contains_key("photos/image.png"));
    }

    #[test]
    fn purge_skips_live_shared_addresses() {
        let mut manifest = Manifest::new();
        let shared_addr = [0xAAu8; 32];

        manifest.insert(
            "a",
            Entry {
                encrypted_pfk: [0x12; 60],
                addresses: vec![shared_addr],
                size: 1,
                modified: 0,
                trashed: 0,
            },
        );
        manifest.insert(
            "b",
            Entry {
                encrypted_pfk: [0x12; 60],
                addresses: vec![shared_addr],
                size: 1,
                modified: 0,
                trashed: 0,
            },
        );
        manifest.trash("b").unwrap();

        let deleted = manifest.purge("b").unwrap();

        assert!(deleted.is_empty());
        assert!(manifest.get("a").is_some());
    }

    #[test]
    fn purge_rejects_live_entry() {
        let mut manifest = manifest();

        // Cannot purge a live entry
        assert!(manifest.purge("music/song.mp3").is_err());
    }

    #[test]
    fn purge_all_clears_trash() {
        let mut manifest = manifest();

        manifest.trash("photos/image.png").unwrap();
        manifest.trash("music/song.mp3").unwrap();

        let deleted = manifest.purge_all();

        assert!(manifest.entries.is_empty());
        assert_eq!(deleted.len(), 3); // 2 from song + 1 from image
    }

    #[test]
    fn all_chunk_hashes() {
        let manifest = manifest();
        let hashes = manifest.addresses();

        // Sample has 2 + 1 = 3 chunk hashes
        assert_eq!(hashes.len(), 3);
    }
}
