//! Encrypted manifest as blob index lookup.
//!
//! Binary serialization format (big-endian):
//!
//!   [2-byte] version (u16)
//!   [4-byte] entry_count (u32)
//!   each entry:
//!     [2-byte]             path_len (u16)
//!     [path_len bytes]      path (UTF-8)
//!     [4-byte]             chunk_count (u32)
//!     each chunk:
//!       [32-byte]          address (hash)
//!       [60-byte]          encrypted_key (nonce=12 + tag=16 + key=32)
//!     [4-byte]             version_count
//!     each version:
//!       [4-byte]             chunk_count
//!       each chunk:
//!         [32-byte]          address
//!         [60-byte]          encrypted_key
//!       [8-byte]             size
//!       [8-byte]             modified
//!     [8-byte]             size (u64)
//!     [8-byte]             modified (u64)
//!     [8-byte]             trashed (u64, 0 = live, unix timestapms = trashed)

use crate::crypto::cipher;

use gate::{
    codec::binary,
    crypto::blake3,
    sys::{collections::btree_map::BTreeMap, string::String, time, vec::Vec},
};

/// Binary format version tag written at the start of every serialized manifest.
const MANIFEST_VERSION: u16 = 1;
/// BLAKE3 domain tag used to derive the storage address of a user's manifest blob
/// from their public signing key.
const DOMAIN_MANIFEST: &str = "vault::manifest";

/// Errors that can occur when processing a [`Manifest`].
#[derive(Debug)]
pub enum Error {
    /// An encryption or decryption error.
    Cipher(cipher::Error),

    /// A binary serialisation or deserialisation error.
    Codec(binary::Error),

    /// The leading version field does not match [`MANIFEST_VERSION`]. The value is the version
    /// that was actually found.
    UnsupportedManifestVersion(u16),

    /// The requested path does not exist in the manifest.
    NotFound,

    /// A [`Manifest::restore`] was attempted on an entry that is not currently trashed.
    NotTrashed,

    /// A [`Manifest::trash`] was attempted on an entry that has already been trashed.
    AlreadyTrashed,

    /// The requested version index doesn not exist for an entry.
    VersionNotFound,

    /// The manifest's signature did not match the ciphertext, the blob was tampered with.
    Tampered,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cipher(e) => write!(f, "cipher: {}", e),
            Self::Codec(e) => write!(f, "codec: {}", e),
            Self::UnsupportedManifestVersion(v) => write!(f, "unsupported manifest version: {}", v),
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

impl From<binary::Error> for Error {
    fn from(value: binary::Error) -> Self {
        Self::Codec(value)
    }
}

/// A reference to one content-addressed encrypted chunk within an entry.
#[derive(Debug, PartialEq, Clone)]
pub struct EntryChunk {
    /// Content-addressed storage key for this chunk's encrypted blob (32-byte BLAKE3 hash).
    pub address: [u8; 32],

    /// The Per-chunk plaintext encryption key, itself encrypted using user's encryption key.
    /// Layout: `nonce (12) || key ciphertext (32) || tag (16)` = 60 bytes.
    pub encrypted_key: [u8; 60],
}

/// A snapshot of a previous file revision, created when a file at a path is overwritten.
#[derive(Debug, PartialEq)]
pub struct Version {
    /// List of chunks for this revision.
    pub chunks: Vec<EntryChunk>,

    /// Total plaintext size of this version in bytes.
    pub size: u64,

    /// Unix timestamp (seconds) when this version was written.
    pub modified: u64,
}

/// Metadata and chunk references for a single file tracked by the manifest.
#[derive(Debug, PartialEq)]
pub struct Entry {
    /// List of chunks for the currently active (latest) revision of this file.
    pub chunks: Vec<EntryChunk>,

    /// Chronologically ordered list of previous revisions, oldest first.
    /// The active revision is not included here.
    pub versions: Vec<Version>,

    /// Total plaintext size of the active revision in bytes.
    pub size: u64,

    /// Unix timestamp (seconds) of the last write to the active revision.
    pub modified: u64,

    /// `0` if the entry is live. A non-zero value is the Unix timestamp when the entry was
    /// moved to the trash, and is used to distinguish "live" from "trashed".
    pub trashed: u64,
}

impl Entry {
    /// Snapshots the current state into a new [`Version`] and installs `new_chunks` as active.
    ///
    /// The current chunks, size, and modified timestamp are appended to `self.versions`
    /// before being replaced, preserving full linear history.
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

// TODO: Perhaps it's better not to hold the entire user's manifest in memory?

/// The file index, mapping virtual paths to their versioned chunk lists.
///
/// Tracks current chunks, historical versions, timestamps, size, and a soft-delete (trash)
/// timestamp per entry. Serialized, encrypted, and signed before being persisted to
/// the storage backend.
#[derive(Debug, PartialEq)]
pub struct Manifest {
    /// All tracked file entries, keyed by their virtual path (e.g. `"photos/image.png"`).
    /// Includes both live and trashed entries.
    pub entries: BTreeMap<String, Entry>,
}

impl Manifest {
    /// Creates an empty manifest with no entries.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Inserts or replaces the entry at `path`.
    /// Overwrites any existing entry without versioning. Must call [`Entry::push_version`] beofre
    /// inserting to preserve history.
    pub fn insert(&mut self, path: &str, entry: Entry) {
        self.entries.insert(path.into(), entry);
    }

    /// Returns the live (non-trashed) entry at `path`, or `None` if absent or trashed.
    pub fn get(&self, path: &str) -> Option<&Entry> {
        self.entries.get(path).filter(|e| e.trashed == 0)
    }

    /// Collects all blob addresses referenced by live (non-trashed) entries, including their
    /// version history.
    ///
    /// Any address absent from this set is safe to delete during garbage collection and cleanups.
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

    /// Collects all blob addresses referenced by trashed entries and their version history.
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

    /// Moves the entry from `old_path` to `new_path`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]: If `old_path` is absent.
    pub fn rename(&mut self, old_path: &str, new_path: &str) -> Result<(), Error> {
        let entry = self.entries.remove(old_path).ok_or(Error::NotFound)?;

        self.entries.insert(new_path.into(), entry);

        Ok(())
    }

    /// Marks an entry as trashed.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::AlreadyTrashed`]: If the entry is already trashed.
    pub fn trash(&mut self, path: &str) -> Result<(), Error> {
        let entry = self.entries.get_mut(path).ok_or(Error::NotFound)?;

        if entry.trashed != 0 {
            return Err(Error::AlreadyTrashed);
        }

        // `1` instead of `0` so it's never mistaken for "live"
        entry.trashed = time::current_secs().unwrap_or(1);

        Ok(())
    }

    /// Untrashes an entry, making it live again.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::NotTrashed`]: If the entry is not currently trashed.
    pub fn restore(&mut self, path: &str) -> Result<(), Error> {
        let entry = self.entries.get_mut(path).ok_or(Error::NotFound)?;

        if entry.trashed == 0 {
            return Err(Error::NotTrashed);
        }

        entry.trashed = 0;

        Ok(())
    }

    /// Removes the version at `index` from `path`'s history.
    ///
    /// Returns the blob addresses that are now unreferenced and safe to delete.
    /// Addresses still referenced by the active version or other files are excluded.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::VersionNotFound`]: If the version index didn't exist.
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

    /// Permanently removes a trashed entry from the manifest.
    ///
    /// Returns the blob addresses that are no longer referenced by any live entry.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::NotTrashed`]: If the entry is not currently trashed.
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

    /// Permanently removes all trashed entries and returns all now-unreferenced addresses.
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

    /// Derives a storage manifest address from a `public_signing_key`.
    ///
    /// Computed as `BLAKE3(context=DOMAIN_MANIFEST, public_signing_key)`.
    pub fn address(public_signing_key: &[u8; 32]) -> [u8; 32] {
        // storage key for the manifest blob
        blake3::derive_key(DOMAIN_MANIFEST, public_signing_key)
    }

    /// Serializes the manifest into the binary wire format described in the module doc.
    ///
    /// # Errors
    ///
    /// - [`Error::Codec`]: If serialization process fails.
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        // Estimated size for each entry, 2 chunks, no versions
        let mut writer = binary::Writer::with_capacity(self.entries.len() * 256);

        writer.write_u16(MANIFEST_VERSION);
        writer.write_u32(self.entries.len() as u32);

        for (path, entry) in &self.entries {
            writer.write_str_u16(path).map_err(|_| {
                Error::Codec(binary::Error::Other(
                    "path string size bounds exceeds u16 limits",
                ))
            })?;
            writer.write_u32(entry.chunks.len() as u32);

            for chunk in &entry.chunks {
                writer.write_bytes(&chunk.address);
                writer.write_bytes(&chunk.encrypted_key);
            }

            writer.write_u32(entry.versions.len() as u32);

            for version in &entry.versions {
                writer.write_u32(version.chunks.len() as u32);

                for version_chunk in &version.chunks {
                    writer.write_bytes(&version_chunk.address);
                    writer.write_bytes(&version_chunk.encrypted_key);
                }

                writer.write_u64(version.size);
                writer.write_u64(version.modified);
            }

            writer.write_u64(entry.size);
            writer.write_u64(entry.modified);
            writer.write_u64(entry.trashed);
        }

        Ok(writer.finish())
    }

    /// Deserializes from the binary wire format described in the module doc.
    ///
    /// # Errors
    ///
    /// - [`Error::Codec`]: If deserialization process fails.
    /// - [`Error::UnsupportedManifestVersion`]: If the leading version field does not match
    ///   [`MANIFEST_VERSION`].
    pub fn deserialize(data: &[u8]) -> Result<Self, Error> {
        let mut reader = binary::Reader::new(data);
        let version = reader.read_u16()?;

        // NOTE: If we ever bump the version, this should gracefully handle data migration.
        if version != MANIFEST_VERSION {
            return Err(Error::UnsupportedManifestVersion(version));
        }

        let entry_count = reader.read_u32()? as usize;
        let mut entries = BTreeMap::new();

        for _ in 0..entry_count {
            let path = reader.read_str_u16()?;
            let chunk_count = reader.read_u32()? as usize;

            if chunk_count * 92 /* address + encrypted_key */ > reader.remaining() {
                return Err(Error::Codec(binary::Error::Other(
                    "chunk count specifies more data than what remains in the buffer",
                )));
            }

            let mut chunks = Vec::with_capacity(chunk_count);

            for _ in 0..chunk_count {
                chunks.push(EntryChunk {
                    address: *reader.read_bytes()?,
                    encrypted_key: *reader.read_bytes()?,
                });
            }

            let version_count = reader.read_u32()? as usize;
            let mut versions = Vec::with_capacity(version_count);

            for _ in 0..version_count {
                let version_chunk_count = reader.read_u32()? as usize;

                if version_chunk_count * 92 /* address + encrypted_key */ > reader.remaining() {
                    return Err(Error::Codec(binary::Error::Other(
                        "chunk count specifies more data than what remains in the buffer",
                    )));
                }

                let mut version_chunks = Vec::with_capacity(version_chunk_count);

                for _ in 0..version_chunk_count {
                    version_chunks.push(EntryChunk {
                        address: *reader.read_bytes()?,
                        encrypted_key: *reader.read_bytes()?,
                    });
                }

                let size = reader.read_u64()?;
                let modified = reader.read_u64()?;

                versions.push(Version {
                    chunks: version_chunks,
                    size,
                    modified,
                });
            }

            let size = reader.read_u64()?;
            let modified = reader.read_u64()?;
            let trashed = reader.read_u64()?;

            entries.insert(
                path.into(),
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

    /// Serializes, encrypts, and signs the manifest.
    ///
    /// The signature covers the ciphertext, not the plaintext.
    ///
    /// # Errors
    ///
    /// - [`Error::Cipher`]: If encryption process fails.
    /// - [`Error::Codec`]: If serialization process fails.
    pub fn lock(
        &self,
        encryption_key: &[u8; 32],
        sign: impl Fn(&[u8]) -> [u8; 64],
    ) -> Result<Vec<u8>, Error> {
        let plaintext = self.serialize()?;
        let locked = cipher::lock(encryption_key, &plaintext, sign)?;

        Ok(locked)
    }

    /// Verifies the signature and decrypts the manifest blob, then deserializes it.
    ///
    /// # Errors
    ///
    /// - [`Error::Cipher`]: If decryption process fails.
    /// - [`Error::Codec`]: If deserialization process fails.
    /// - [`Error::Tampered`]: If signature verification fails.
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

/// File entry metadata.
pub struct Properties {
    /// Number of content-addressed chunks in the active revision.
    pub chunk_count: usize,

    /// Total plaintext size of the active revision in bytes.
    pub size: u64,

    /// Unix timestamp (seconds) of the last write to this entry.
    pub modified: u64,

    /// `0` if live, or the Unix timestamp when the entry was trashed.
    pub trashed: u64,

    /// Number of historical revisions stored for this entry (not counting the active one).
    pub version_count: usize,
}

/// Historical version metadata.
pub struct VersionProperties {
    /// Index of this version within the entry's `versions` list.
    pub index: usize,

    /// Number of chunks in this version.
    pub chunk_count: usize,

    /// Total plaintext size of this revision in bytes.
    pub size: u64,

    /// Unix timestamp (seconds) when this revision was written.
    pub modified: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    use gate::sys::macros::vec;

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
        let bytes = manifest.serialize().unwrap();
        let deserialized = Manifest::deserialize(&bytes).unwrap();

        assert_eq!(manifest, deserialized);
    }

    #[test]
    fn serialize_deserialize_trashed_roundtrip() {
        let mut manifest = manifest();

        manifest.trash("photos/image.png").unwrap();

        let deserialized = Manifest::deserialize(&manifest.serialize().unwrap()).unwrap();

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

        let bytes = manifest.serialize().unwrap();
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
        let mut bytes = manifest.serialize().unwrap();

        // Change the version bytes
        bytes[0] = 0xFF;
        bytes[1] = 0xFF;

        let deserialized = Manifest::deserialize(&bytes);

        assert!(matches!(
            deserialized,
            Err(Error::UnsupportedManifestVersion(0xFFFF))
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
        let public_signing_key = [0xFFu8; 32];

        assert_eq!(
            Manifest::address(&public_signing_key),
            Manifest::address(&public_signing_key)
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
