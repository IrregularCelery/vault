//! Encrypted manifest as blob index lookup
//!
//! Binary serialization format (big-endian):
//!
//!   [2-bytes] version (u16)
//!   [4-bytes] entry_count (u32)
//!   each entry:
//!     [2-bytes]             path_len (u16)
//!     [path_len bytes]      path (UTF-8)
//!     [4-bytes]             chunk_count (u32)
//!     each chunk:
//!       [32-bytes]          address (hash)
//!       [60-bytes]          encrypted_key (nonce=12 + tag=16 + key=32)
//!     [4-bytes]             version_count
//!     each version:
//!       [4-bytes]             chunk_count
//!       each chunk:
//!         [32-bytes]          address
//!         [60-bytes]          encrypted_key
//!       [8-bytes]             size
//!       [8-bytes]             modified
//!     [8-bytes]             size (u64)
//!     [8-bytes]             modified (u64)
//!     [8-bytes]             trashed (u64, 0 = live, unix timestapms = trashed)

use crate::crypto::cipher;

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
    VersionNotFound,
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
            Self::VersionNotFound => write!(f, "version not found"),
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

#[derive(Debug, PartialEq, Clone)]
pub struct EntryChunk {
    pub address: [u8; 32],
    pub encrypted_key: [u8; 60], // 12 (nonce) + 16 (tag) + 32 (key)
}

#[derive(Debug, PartialEq)]
pub struct Version {
    pub chunks: Vec<EntryChunk>,
    pub size: u64,
    pub modified: u64,
}

#[derive(Debug, PartialEq)]
pub struct Entry {
    pub chunks: Vec<EntryChunk>,
    pub versions: Vec<Version>,
    pub size: u64,
    pub modified: u64,
    pub trashed: u64,
}

impl Entry {
    pub fn push_version(&mut self, new_chunks: Vec<EntryChunk>, new_size: u64, new_modified: u64) {
        let snapshot = Version {
            chunks: core::mem::take(&mut self.chunks),
            size: self.size,
            modified: self.modified,
        };

        self.versions.push(snapshot);
        self.chunks = new_chunks;
        self.size = new_size;
        self.modified = new_modified;
    }
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
            .flat_map(|e| {
                e.chunks.iter().map(|c| c.address).chain(
                    e.versions
                        .iter()
                        .flat_map(|v| v.chunks.iter().map(|c| c.address)),
                )
            })
            .collect()
    }

    pub fn addresses_trashed(&self) -> Vec<[u8; 32]> {
        self.entries
            .values()
            .filter(|e| e.trashed != 0)
            .flat_map(|e| {
                e.chunks.iter().map(|c| c.address).chain(
                    e.versions
                        .iter()
                        .flat_map(|v| v.chunks.iter().map(|c| c.address)),
                )
            })
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

    pub fn drop_version(&mut self, path: &str, index: usize) -> Result<Vec<[u8; 32]>, Error> {
        let entry = self.entries.get_mut(path).ok_or(Error::NotFound)?;

        if index >= entry.versions.len() {
            return Err(Error::VersionNotFound);
        }

        let dropped = entry.versions.remove(index);
        let still_referenced: Vec<[u8; 32]> = entry
            .chunks
            .iter()
            .map(|c| c.address)
            .chain(
                entry
                    .versions
                    .iter()
                    .flat_map(|v| v.chunks.iter().map(|c| c.address)),
            )
            .collect();
        let live = self.addresses();

        Ok(dropped
            .chunks
            .into_iter()
            .map(|c| c.address)
            .filter(|a| !still_referenced.contains(a) && !live.contains(a))
            .collect())
    }

    pub fn purge(&mut self, path: &str) -> Result<Vec<[u8; 32]>, Error> {
        match self.entries.get(path) {
            None => return Err(Error::NotFound),
            Some(e) if e.trashed == 0 => return Err(Error::NotTrashed),
            _ => {}
        }

        if let Some(entry) = self.entries.remove(path) {
            let live = self.addresses();
            let all_addresses = entry.chunks.iter().map(|c| c.address).chain(
                entry
                    .versions
                    .iter()
                    .flat_map(|v| v.chunks.iter().map(|c| c.address)),
            );

            return Ok(all_addresses.filter(|a| !live.contains(a)).collect());
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
        let mut purged = Vec::new();

        for path in paths {
            if let Some(entry) = self.entries.remove(&path) {
                let all = entry.chunks.into_iter().map(|c| c.address).chain(
                    entry
                        .versions
                        .into_iter()
                        .flat_map(|v| v.chunks.into_iter().map(|c| c.address)),
                );

                for address in all {
                    if !live.contains(&address) && !purged.contains(&address) {
                        purged.push(address);
                    }
                }
            }
        }

        purged
    }

    pub fn address(public_key: &[u8; 32]) -> [u8; 32] {
        let mut input = Vec::with_capacity(DOMAIN_MANIFEST.len() + 32);

        input.extend_from_slice(DOMAIN_MANIFEST);
        input.extend_from_slice(public_key);

        // storage key for the manifest blob
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
        fn write_chunks(buf: &mut Vec<u8>, chunks: &[EntryChunk]) {
            write_u32(buf, chunks.len() as u32);

            for c in chunks {
                buf.extend_from_slice(&c.address);
                buf.extend_from_slice(&c.encrypted_key);
            }
        }

        let mut buf = Vec::new();

        write_u16(&mut buf, MANIFEST_VERSION);
        write_u32(&mut buf, self.entries.len() as u32);

        for (path, entry) in &self.entries {
            let path_bytes = path.as_bytes();

            write_u16(&mut buf, path_bytes.len() as u16);

            buf.extend_from_slice(path_bytes);

            write_chunks(&mut buf, &entry.chunks);
            write_u32(&mut buf, entry.versions.len() as u32);

            for version in &entry.versions {
                write_chunks(&mut buf, &version.chunks);
                write_u64(&mut buf, version.size);
                write_u64(&mut buf, version.modified);
            }

            write_u64(&mut buf, entry.size);
            write_u64(&mut buf, entry.modified);
            write_u64(&mut buf, entry.trashed);
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
        fn read_chunks(data: &[u8], current: &mut usize) -> Result<Vec<EntryChunk>, Error> {
            let count = read_u32(data, current)? as usize;
            let mut chunks = Vec::with_capacity(count);

            for _ in 0..count {
                let address = read_bytes(data, current)?;
                let encrypted_key = read_bytes(data, current)?;

                chunks.push(EntryChunk {
                    address,
                    encrypted_key,
                });
            }

            Ok(chunks)
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
            let chunks = read_chunks(data, &mut current)?;
            let version_count = read_u32(data, &mut current)? as usize;
            let mut versions = Vec::with_capacity(version_count);

            for _ in 0..version_count {
                let chunks = read_chunks(data, &mut current)?;
                let size = read_u64(data, &mut current)?;
                let modified = read_u64(data, &mut current)?;

                versions.push(Version {
                    chunks,
                    size,
                    modified,
                });
            }

            let size = read_u64(data, &mut current)?;
            let modified = read_u64(data, &mut current)?;
            let trashed = read_u64(data, &mut current)?;

            entries.insert(
                path,
                Entry {
                    chunks,
                    versions,
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
    pub chunk_count: usize,
    pub size: u64,
    pub modified: u64,
    pub trashed: u64,
    pub version_count: usize,
}

pub struct VersionProperties {
    pub index: usize,
    pub chunk_count: usize,
    pub size: u64,
    pub modified: u64,
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
                chunks: vec![
                    EntryChunk {
                        address: [0xABu8; 32],
                        encrypted_key: [0xFF; 60],
                    },
                    EntryChunk {
                        address: [0xCDu8; 32],
                        encrypted_key: [0xFF; 60],
                    },
                ],
                versions: Vec::new(),
                size: 5_000_000, // 5MB > 4MiB hence the two chunks
                modified: 1_700_000_000,
                trashed: 0,
            },
        );

        manifest.insert(
            "photos/image.png",
            Entry {
                chunks: vec![EntryChunk {
                    address: [0xEFu8; 32],
                    encrypted_key: [0xFF; 60],
                }],
                versions: Vec::new(),
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
    fn entry_push_version() {
        let mut manifest = Manifest::new();

        manifest.insert(
            "file",
            Entry {
                chunks: vec![EntryChunk {
                    address: [0xAAu8; 32],
                    encrypted_key: [0xFF; 60],
                }],
                size: 10,
                modified: 100,
                trashed: 0,
                versions: Vec::new(),
            },
        );

        let entry = manifest.entries.get_mut("file").unwrap();

        entry.push_version(
            vec![EntryChunk {
                address: [0xBBu8; 32],
                encrypted_key: [0xFF; 60],
            }],
            20,
            200,
        );

        let entry = manifest.entries.get("file").unwrap();

        // Active is the new state
        assert_eq!(
            entry.chunks,
            vec![EntryChunk {
                address: [0xBBu8; 32],
                encrypted_key: [0xFF; 60]
            }]
        );
        assert_eq!(entry.size, 20);
        assert_eq!(entry.modified, 200);

        // Previous version holds the old state
        assert_eq!(entry.versions.len(), 1);
        assert_eq!(
            entry.versions[0].chunks,
            vec![EntryChunk {
                address: [0xAAu8; 32],
                encrypted_key: [0xFF; 60]
            }]
        );
        assert_eq!(entry.versions[0].size, 10);
        assert_eq!(entry.versions[0].modified, 100);
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
    fn serialize_deserialize_with_versions_roundtrip() {
        let mut manifest = Manifest::new();

        manifest.insert(
            "file",
            Entry {
                chunks: vec![EntryChunk {
                    address: [0xBBu8; 32],
                    encrypted_key: [0xFF; 60],
                }],
                size: 20,
                modified: 200,
                trashed: 0,
                versions: vec![Version {
                    chunks: vec![EntryChunk {
                        address: [0xAAu8; 32],
                        encrypted_key: [0xFF; 60],
                    }],
                    size: 10,
                    modified: 100,
                }],
            },
        );

        let bytes = manifest.serialize();
        let deserialized = Manifest::deserialize(&bytes).unwrap();

        assert_eq!(manifest, deserialized);
    }

    #[test]
    fn insert_remove_roundtrip() {
        let mut manifest = Manifest::new();

        manifest.insert(
            "file.txt",
            Entry {
                chunks: vec![EntryChunk {
                    address: [0u8; 32],
                    encrypted_key: [0xFF; 60],
                }],
                versions: Vec::new(),
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
    fn addresses_includes_all_version_chunks() {
        let mut manifest = Manifest::new();

        manifest.insert(
            "file",
            Entry {
                chunks: vec![EntryChunk {
                    address: [0xBBu8; 32],
                    encrypted_key: [0xFF; 60],
                }],
                size: 20,
                modified: 200,
                trashed: 0,
                versions: vec![Version {
                    chunks: vec![EntryChunk {
                        address: [0xAAu8; 32],
                        encrypted_key: [0xFF; 60],
                    }],
                    size: 10,
                    modified: 100,
                }],
            },
        );

        let addrs = manifest.addresses();

        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&[0xAAu8; 32]));
        assert!(addrs.contains(&[0xBBu8; 32]));
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
        let shared_addr = EntryChunk {
            address: [0xAAu8; 32],
            encrypted_key: [0xFF; 60],
        };

        manifest.insert(
            "a",
            Entry {
                chunks: vec![shared_addr.clone()],
                versions: Vec::new(),
                size: 1,
                modified: 0,
                trashed: 0,
            },
        );
        manifest.insert(
            "b",
            Entry {
                chunks: vec![shared_addr],
                versions: Vec::new(),
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
    fn all_chunk_addresses() {
        let manifest = manifest();
        let addresses = manifest.addresses();

        // Sample has 2 + 1 = 3 chunk addresses
        assert_eq!(addresses.len(), 3);
    }

    #[test]
    fn drop_version() {
        let mut manifest = Manifest::new();

        manifest.insert(
            "file",
            Entry {
                chunks: vec![EntryChunk {
                    address: [0xBBu8; 32],
                    encrypted_key: [0xFF; 60],
                }],
                size: 20,
                modified: 200,
                trashed: 0,
                versions: vec![Version {
                    chunks: vec![EntryChunk {
                        address: [0xAAu8; 32],
                        encrypted_key: [0xFF; 60],
                    }],
                    size: 10,
                    modified: 100,
                }],
            },
        );

        let dropped = manifest.drop_version("file", 0).unwrap();

        assert_eq!(dropped, vec![[0xAAu8; 32]]);
        assert!(manifest.entries.get("file").unwrap().versions.is_empty());
    }

    #[test]
    fn drop_version_skips_address_shared_with_active() {
        let mut manifest = Manifest::new();
        let shared = EntryChunk {
            address: [0xAAu8; 32],
            encrypted_key: [0xFF; 60],
        };

        manifest.insert(
            "file",
            Entry {
                chunks: vec![shared.clone()],
                size: 10,
                modified: 200,
                trashed: 0,
                versions: vec![Version {
                    chunks: vec![shared],
                    size: 10,
                    modified: 100,
                }],
            },
        );

        let dropped = manifest.drop_version("file", 0).unwrap();

        // Must not delete the address since active still uses it
        assert!(dropped.is_empty());
    }
}
