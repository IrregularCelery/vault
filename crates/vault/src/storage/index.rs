//! Encrypted, sharded index mapping virtual paths to their versioned chunk lists.
//!
//! The full "path->[`Entry`]" mapping is partitioned into [`SHARD_COUNT`] independently encrypted,
//! signed, and persisted shards. A path is deterministically assigned to a shard via
//! [`Index::shard_of`] so the same path always lands in the same shard without ever needing to be
//! tracked anywhere else. Mutating a single entry therefore only requires re-serializing,
//! re-encrypting, and rewriting the one shard it belongs to, rather than the entire index.
//! Shard assignment is salted with a key derived from the user's encryption key so that shard
//! numbers can't be correlated across different users' vaults.
//!
//! Binary serialization format for a single shard (big-endian):
//!
//!   [2-byte] version (u16)
//!   [4-byte] entry_count (u32)
//!   each entry:
//!     [2-byte]             path_len (u16)
//!     [path_len bytes]     path (UTF-8)
//!     [4-byte]             chunk_count (u32)
//!     each chunk:
//!       [32-byte]          address (hash)
//!       [60-byte]          encrypted_key (nonce=12 + key=32 + tag=16)
//!     [4-byte]             version_count
//!     each version:
//!       [4-byte]           chunk_count
//!       each chunk:
//!         [32-byte]        address
//!         [60-byte]        encrypted_key
//!       [8-byte]           size
//!       [8-byte]           modified
//!     [8-byte]             size (u64)
//!     [8-byte]             modified (u64)
//!     [8-byte]             trashed (u64, 0 = live, unix timestamps = trashed)

use crate::{
    crypto::{cipher, hash},
    storage::SHARD_COUNT,
};

use gate::{
    codec::binary,
    sys::{
        collections::{btree_map::BTreeMap, btree_set::BTreeSet},
        rc::Rc,
        time,
        vec::Vec,
    },
};

/// Binary format version tag written at the start of every serialized shard.
const INDEX_VERSION: u16 = 1;
/// BLAKE3 domain tag used to derive a user's storage root address from their public signing key.
const DOMAIN_INDEX: &str = "vault::index";
/// BLAKE3 domain tag used to derive the shard a path is assigned to.
const DOMAIN_SHARD: &str = "vault::shard";
/// BLAKE3 domain tag used to derive the user-specific shard key from their encryption key.
const DOMAIN_SHARD_KEY: &str = "vault::shard_key";

/// Errors that can occur when processing an [`Index`] or its shards.
#[derive(Debug)]
pub enum Error {
    /// An encryption or decryption error.
    Cipher(cipher::Error),

    /// A binary serialization or deserialization error.
    Codec(binary::Error),

    /// The leading version field does not match [`INDEX_VERSION`]. The value is the version
    /// that was actually found.
    UnsupportedIndexVersion(u16),

    /// The requested path does not exist in the index.
    NotFound,

    /// The requested version index does not exist for an entry.
    VersionNotFound,

    /// A [`Index::rename`] was attempted onto a new path that already has an entry.
    AlreadyExists,

    /// A [`Index::restore`] was attempted on an entry that is not currently trashed.
    NotTrashed,

    /// A [`Index::trash`] was attempted on an entry that has already been trashed.
    AlreadyTrashed,

    /// The shard's signature did not match the ciphertext, the blob was tampered with.
    Tampered,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cipher(e) => write!(f, "cipher: {}", e),
            Self::Codec(e) => write!(f, "codec: {}", e),
            Self::UnsupportedIndexVersion(v) => write!(f, "unsupported index version: {}", v),
            Self::NotFound => write!(f, "file not found"),
            Self::VersionNotFound => write!(f, "version not found"),
            Self::AlreadyExists => write!(f, "a file already exists at the new path"),
            Self::NotTrashed => write!(f, "file is not in the trash"),
            Self::AlreadyTrashed => write!(f, "file is already in the trash"),
            Self::Tampered => write!(f, "tampered index shard"),
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
#[derive(Debug, Clone, PartialEq)]
pub struct Version {
    /// List of chunks for this revision.
    pub chunks: Vec<EntryChunk>,

    /// Total plaintext size of this version in bytes.
    pub size: u64,

    /// Unix timestamp (seconds) when this version was written.
    pub modified: u64,
}

/// Metadata and chunk references for a single file tracked by the index.
#[derive(Debug, Clone, PartialEq)]
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

/// The in-memory, lazily populated view of tracked paths. Has at most [`SHARD_COUNT`]
/// independently encrypted shards.
///
/// [`Index::entries`] only holds entries from the shards that have been needed so far, not the
/// entire vault.
#[derive(Debug)]
pub struct Index {
    /// All tracked file entries currently loaded, keyed by their virtual path (e.g.
    /// `"photos/image.png"`). Includes both live and trashed entries, across every loaded shard.
    entries: BTreeMap<Rc<str>, Entry>,

    /// User-specific key derived from the user's encryption key, used to salt shard assignment.
    /// This ensures shard numbers are unique per user, preventing cross-user correlation.
    shard_key: [u8; 32],

    /// Reverse index of paths assigned to shards. Mirrors `entries`'s keys, scoped by shard.
    /// Only exists as a derived lookup cache, never serialized.
    shard_paths: BTreeMap<u16, BTreeSet<Rc<str>>>,

    /// Shards that have been loaded from storage and are therefore fully represented in
    /// [`Index::entries`].
    loaded: Vec<u16>,

    /// Shards with entries added, changed, or removed since the last flush, and need to be
    /// rewritten.
    dirty: Vec<u16>,
}

impl Index {
    /// Creates an empty index with no entries loaded.
    pub fn new(encryption_key: &[u8; 32]) -> Self {
        Self {
            entries: BTreeMap::new(),
            shard_key: hash::derive_key(DOMAIN_SHARD_KEY, encryption_key),
            shard_paths: BTreeMap::new(),
            // `loaded` and `dirty` are only ever as big as `SHARD_COUNT`
            loaded: Vec::with_capacity(SHARD_COUNT as usize),
            dirty: Vec::with_capacity(SHARD_COUNT as usize),
        }
    }

    /// Returns a reference to the entry at `path`, live or trashed, or `None` if absent.
    pub fn entry(&self, path: &str) -> Option<&Entry> {
        self.entries.get(path)
    }

    /// Returns a mutable reference to the entry at `path`, live or trashed, or `None` if absent.
    pub fn entry_mut(&mut self, path: &str) -> Option<&mut Entry> {
        self.entries.get_mut(path)
    }

    /// Returns whether an entry (live or trashed) exists at `path`.
    pub fn contains(&self, path: &str) -> bool {
        self.entries.contains_key(path)
    }

    /// Returns an iterator over all of the entries.
    pub fn iter(&self) -> impl Iterator<Item = (&Rc<str>, &Entry)> {
        self.entries.iter()
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Deterministically assigns `path` to a shard number/id.
    pub fn shard_of(&self, path: &str) -> u16 {
        let mut hasher = hash::Hasher::new_keyed(&self.shard_key);

        hasher.update(DOMAIN_SHARD.as_bytes());
        hasher.update(path.as_bytes());

        let hash = hasher.finalize();
        let n = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);

        (n % SHARD_COUNT as u32) as u16
    }

    /// Returns whether `shard` currently has no entries.
    pub fn is_shard_empty(&self, shard: u16) -> bool {
        !self.shard_paths.contains_key(&shard)
    }

    /// Marks `shard` as loaded. This should only be called once `shard`'s entries have been merged
    /// into [`Index::entries`].
    pub fn mark_loaded(&mut self, shard: u16) {
        if !self.loaded.contains(&shard) {
            self.loaded.push(shard);
        }
    }

    /// Returns whether `shard` has been loaded from storage yet (i.e. whether its entries are
    /// currently present in [`Index::entries`]).
    pub fn is_loaded(&self, shard: u16) -> bool {
        self.loaded.contains(&shard)
    }

    /// Marks the shard containing `path` as dirty, so it's rewritten on the next flush.
    /// All of [`Index`]'s own mutating methods already call this internally; call it directly
    /// after directly mutating [`Index::entries`].
    pub fn mark_dirty(&mut self, path: &str) {
        let shard = self.shard_of(path);

        if !self.dirty.contains(&shard) {
            self.dirty.push(shard);
        }
    }

    /// Returns a snapshot of the shards pending a rewrite, without clearing their dirty status.
    /// Shards can individually be cleared from the list via [`Index::clear_dirty`].
    pub fn dirty_shards(&self) -> Vec<u16> {
        self.dirty.clone()
    }

    /// Clears the dirty flag for a single shard, once it's been confirmed persisted (or
    /// deleted). This only affects the one shard it's given, leaving any other still-dirty shards
    /// untouched.
    pub fn clear_dirty(&mut self, shard: u16) {
        self.dirty.retain(|&s| s != shard);
    }

    /// Replaces (or removes, if `entry` is `None`) the entry at `path`. Used for when a flush
    /// fails and an in-memory mutation needs to be rolled back to a known-good snapshot.
    /// Doesn't touch dirty tracking, whatever [`Index::mark_dirty`] call was already made for
    /// `path` before the mutation being undone is what makes sure the shard gets retried on the
    /// next flush.
    pub fn restore_entry(&mut self, path: &str, entry: Option<Entry>) {
        match entry {
            Some(entry) => {
                let entry_path = Rc::from(path);

                self.track_path(&entry_path);
                self.entries.insert(entry_path, entry);
            }
            None => {
                self.entries.remove(path);
                self.untrack_path(path);
            }
        }
    }

    /// Inserts or replaces the entry at `path`.
    /// Overwrites any existing entry without versioning. Must call [`Entry::push_version`] before
    /// inserting to preserve history. Internally marks the touched shard dirty.
    pub fn insert(&mut self, path: &str, entry: Entry) {
        let entry_path = Rc::from(path);

        self.track_path(&entry_path);
        self.entries.insert(entry_path, entry);
        self.mark_dirty(path);
    }

    /// Returns the live (non-trashed) entry at `path`, or `None` if absent or trashed.
    pub fn get(&self, path: &str) -> Option<&Entry> {
        self.entries.get(path).filter(|e| e.trashed == 0)
    }

    /// Collects all blob addresses referenced by every entry, live or trashed, including their
    /// version history.
    pub fn addresses(&self) -> Vec<[u8; 32]> {
        self.entries
            .values()
            .flat_map(|e| {
                e.chunks.iter().map(|c| c.address).chain(
                    e.versions
                        .iter()
                        .flat_map(|v| v.chunks.iter().map(|c| c.address)),
                )
            })
            .collect()
    }

    /// Collects all blob addresses referenced by live (non-trashed) entries, including their
    /// version history.
    pub fn addresses_live(&self) -> Vec<[u8; 32]> {
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
    /// - [`Error::AlreadyExists`]: If `new_path` already exists.
    pub fn rename(&mut self, old_path: &str, new_path: &str) -> Result<(), Error> {
        if self.entries.contains_key(new_path) {
            return Err(Error::AlreadyExists);
        }

        let entry = self.entries.remove(old_path).ok_or(Error::NotFound)?;

        self.untrack_path(old_path);

        let new_entry_path = Rc::from(new_path);

        self.track_path(&new_entry_path);
        self.entries.insert(new_entry_path, entry);

        self.mark_dirty(old_path);
        self.mark_dirty(new_path);

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

        self.mark_dirty(path);

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

        self.mark_dirty(path);

        Ok(())
    }

    /// Removes the version at `version_index` from `path`'s history.
    ///
    /// Returns the blob addresses that are now unreferenced and safe to delete.
    /// Addresses still referenced by the active version or other files are excluded.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::VersionNotFound`]: If the version index doesn't exist.
    pub fn drop_version(
        &mut self,
        path: &str,
        version_index: usize,
    ) -> Result<Vec<[u8; 32]>, Error> {
        let entry = self.entries.get_mut(path).ok_or(Error::NotFound)?;

        if version_index >= entry.versions.len() {
            return Err(Error::VersionNotFound);
        }

        let dropped = entry.versions.remove(version_index);
        let referenced = self.addresses();

        self.mark_dirty(path);

        Ok(dropped
            .chunks
            .into_iter()
            .map(|c| c.address)
            .filter(|a| !referenced.contains(a))
            .collect())
    }

    /// Permanently removes a trashed entry from the index.
    ///
    /// Returns the blob addresses that are no longer referenced by any entry.
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
            self.untrack_path(path);
            self.mark_dirty(path);

            let referenced = self.addresses(); // Entry was already removed, so this excludes it
            let all_addresses = entry.chunks.iter().map(|c| c.address).chain(
                entry
                    .versions
                    .iter()
                    .flat_map(|v| v.chunks.iter().map(|c| c.address)),
            );

            return Ok(all_addresses.filter(|a| !referenced.contains(a)).collect());
        }

        Err(Error::NotFound)
    }

    /// Permanently removes all trashed entries and returns all now-unreferenced addresses.
    pub fn purge_all(&mut self) -> Vec<[u8; 32]> {
        let live = self.addresses_live();
        let paths: Vec<Rc<str>> = self
            .entries
            .iter()
            .filter(|(_, v)| v.trashed != 0)
            .map(|(k, _)| Rc::clone(k))
            .collect();
        let mut purged = Vec::new();

        for path in paths {
            if let Some(entry) = self.entries.remove(&path) {
                self.untrack_path(&path);
                self.mark_dirty(&path);

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

    /// Derives a user address from a `public_signing_key`.
    ///
    /// Computed as `BLAKE3(context=DOMAIN_INDEX, public_signing_key)`.
    pub fn address(public_signing_key: &[u8; 32]) -> [u8; 32] {
        hash::derive_key(DOMAIN_INDEX, public_signing_key)
    }

    /// Serializes the entries belonging to `shard` into the binary format described in
    /// the module doc.
    ///
    /// # Errors
    ///
    /// - [`Error::Codec`]: If serialization process fails (e.g., a path string's size exceeds u16).
    pub fn serialize_shard(&self, shard: u16) -> Result<Vec<u8>, Error> {
        let entries: Vec<(&Rc<str>, &Entry)> = self
            .shard_paths
            .get(&shard)
            .into_iter()
            .flat_map(|paths| paths.iter())
            .filter_map(|path| self.entries.get_key_value(path))
            .collect();

        // Estimated size for each entry, 2 chunks, no versions
        let mut writer = binary::Writer::with_capacity(entries.len() * 256);

        writer.write_u16(INDEX_VERSION);
        writer.write_u32(entries.len() as u32);

        for (path, entry) in entries {
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

    /// Deserializes a shard from the binary format described in the module doc and merges its
    /// entries into [`Index::entries`]. Does not mark the shard dirty.
    ///
    /// # Errors
    ///
    /// - [`Error::Codec`]: If deserialization process fails.
    /// - [`Error::UnsupportedIndexVersion`]: If the leading version field does not match
    ///   [`INDEX_VERSION`].
    pub fn deserialize_shard(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut reader = binary::Reader::new(data);
        let version = reader.read_u16()?;

        // NOTE: If we ever bump the version, this should gracefully handle data migration.
        if version != INDEX_VERSION {
            return Err(Error::UnsupportedIndexVersion(version));
        }

        let entry_count = reader.read_u32()? as usize;

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

            let entry_path = Rc::from(path);

            self.track_path(&entry_path);
            self.entries.insert(
                entry_path,
                Entry {
                    chunks,
                    versions,
                    size,
                    modified,
                    trashed,
                },
            );
        }

        Ok(())
    }

    /// Serializes, encrypts, and signs `shard`.
    ///
    /// The signature covers the ciphertext, not the plaintext.
    ///
    /// # Errors
    ///
    /// - [`Error::Cipher`]: If encryption process fails.
    /// - [`Error::Codec`]: If serialization process fails.
    pub fn lock_shard(
        &self,
        shard: u16,
        encryption_key: &[u8; 32],
        sign: impl Fn(&[u8]) -> [u8; 64],
    ) -> Result<Vec<u8>, Error> {
        let plaintext = self.serialize_shard(shard)?;
        let locked = cipher::lock(encryption_key, &plaintext, sign)?;

        Ok(locked)
    }

    /// Verifies the signature and decrypts a shard blob, then deserializes it and merges its
    /// entries into [`Index::entries`].
    ///
    /// # Errors
    ///
    /// - [`Error::Cipher`]: If decryption process fails.
    /// - [`Error::Codec`]: If deserialization process fails.
    /// - [`Error::Tampered`]: If signature verification fails.
    pub fn unlock_shard(
        &mut self,
        encryption_key: &[u8; 32],
        blob: &[u8],
        verify: impl Fn(&[u8], &[u8; 64]) -> bool,
    ) -> Result<(), Error> {
        let unlocked = cipher::unlock(encryption_key, blob, verify)?;

        self.deserialize_shard(&unlocked)
    }

    /// Registers `path` under its shard.
    fn track_path(&mut self, path: &Rc<str>) {
        self.shard_paths
            .entry(self.shard_of(path))
            .or_default()
            .insert(Rc::clone(path));
    }

    /// Unregisters `path` from its shard.
    fn untrack_path(&mut self, path: &str) {
        let shard = self.shard_of(path);

        if let Some(paths) = self.shard_paths.get_mut(&shard) {
            paths.remove(path);

            if paths.is_empty() {
                self.shard_paths.remove(&shard);
            }
        }
    }
}

impl PartialEq for Index {
    // dirty-shard tracking is persistence-flush tracking, not part of the index's logical content,
    // so it's excluded from the equality.
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

/// File entry metadata.
#[derive(Debug, PartialEq)]
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
#[derive(Debug, PartialEq)]
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

    use gate::sys::{
        macros::{format, vec},
        string::String,
    };

    fn index(key: &[u8; 32]) -> Index {
        let mut index = Index::new(key);

        index.insert(
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

        index.insert(
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

        index
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

    fn roundtrip(index: &Index, key: &[u8; 32]) -> Index {
        let mut restored = Index::new(key);

        for shard in 0..SHARD_COUNT {
            let bytes = index.serialize_shard(shard).unwrap();

            restored.deserialize_shard(&bytes).unwrap();
        }

        restored
    }

    #[test]
    fn shard_of_is_deterministic_for_the_same_user() {
        let key = [0xFF; 32];
        let index = Index::new(&key);

        assert_eq!(
            index.shard_of("same/path.txt"),
            index.shard_of("same/path.txt")
        );
    }

    #[test]
    fn shard_of_is_unique_per_user() {
        let key1 = [0x01u8; 32];
        let index1 = Index::new(&key1);
        let key2 = [0x02u8; 32];
        let index2 = Index::new(&key2);

        assert_ne!(index1.shard_of("path"), index2.shard_of("path"));
    }

    #[test]
    fn shard_of_is_bounded() {
        let key = [0xFF; 32];
        let index = Index::new(&key);

        for path in [
            "a",
            "b",
            "music/song.mp3",
            "",
            "very/deeply/nested/path.bin",
        ] {
            assert!(index.shard_of(path) < SHARD_COUNT);
        }
    }

    #[test]
    fn loaded_tracking() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);

        assert!(!index.is_loaded(5));

        index.mark_loaded(5);

        assert!(index.is_loaded(5));
        assert!(!index.is_loaded(6));

        // Idempotent
        index.mark_loaded(5);

        assert!(index.is_loaded(5));
    }

    #[test]
    fn mark_dirty_only_marks_the_affected_shard() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);

        index.mark_dirty("file");

        assert_eq!(index.dirty_shards(), vec![index.shard_of("file")]);
    }

    #[test]
    fn insert_marks_its_shard_dirty() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);

        index.insert(
            "file",
            Entry {
                chunks: Vec::new(),
                versions: Vec::new(),
                size: 0,
                modified: 0,
                trashed: 0,
            },
        );

        assert_eq!(index.dirty_shards(), vec![index.shard_of("file")]);
    }

    #[test]
    fn unrelated_mutation_does_not_dirty_other_shards() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);

        index.insert(
            "a",
            Entry {
                chunks: Vec::new(),
                versions: Vec::new(),
                size: 0,
                modified: 0,
                trashed: 0,
            },
        );

        let shard_a = index.shard_of("a");
        let mut other = String::from("b");
        let mut i = 0;

        // Find a path guaranteed to land in a different shard than "a"
        while index.shard_of(&other) == shard_a {
            other = format!("b{}", i);
            i += 1;
        }

        index.clear_dirty(shard_a); // Clear the dirty state from inserting "a" to simulate flushing
        index.insert(
            &other,
            Entry {
                chunks: Vec::new(),
                versions: Vec::new(),
                size: 0,
                modified: 0,
                trashed: 0,
            },
        );

        assert_eq!(index.dirty_shards(), vec![index.shard_of(&other)]);
    }

    #[test]
    fn serialize_shard_only_includes_that_shards_entries() {
        let key = [0xFF; 32];
        let index = index(&key);

        for path in index.entries.keys() {
            let shard = index.shard_of(path);
            let mut restored = Index::new(&key);

            restored
                .deserialize_shard(&index.serialize_shard(shard).unwrap())
                .unwrap();

            assert!(restored.entries.contains_key(path));

            // No entry from a different shard leaked in
            for other_path in restored.entries.keys() {
                assert_eq!(index.shard_of(other_path), shard);
            }
        }
    }

    #[test]
    fn is_shard_empty() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);

        index.insert(
            "solo",
            Entry {
                chunks: Vec::new(),
                versions: Vec::new(),
                size: 0,
                modified: 0,
                trashed: 1,
            },
        );

        let shard = index.shard_of("solo");

        assert!(!index.is_shard_empty(shard));

        index.purge("solo").unwrap();

        assert!(index.is_shard_empty(shard));
    }

    #[test]
    fn entry_push_version() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);

        index.insert(
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

        let entry = index.entries.get_mut("file").unwrap();

        entry.push_version(
            vec![EntryChunk {
                address: [0xBBu8; 32],
                encrypted_key: [0xFF; 60],
            }],
            20,
            200,
        );

        let entry = index.entries.get("file").unwrap();

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
        let key = [0xFF; 32];
        let index = index(&key);

        assert_eq!(index, roundtrip(&index, &key));
    }

    #[test]
    fn serialize_deserialize_trashed_roundtrip() {
        let key = [0xFF; 32];
        let mut index = index(&key);

        index.trash("photos/image.png").unwrap();

        let restored = roundtrip(&index, &key);

        assert_eq!(index, restored);
        assert_ne!(restored.entries.get("photos/image.png").unwrap().trashed, 0);
    }

    #[test]
    fn serialize_deserialize_with_versions_roundtrip() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);

        index.insert(
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

        let shard = index.shard_of("file");
        let bytes = index.serialize_shard(shard).unwrap();
        let mut restored = Index::new(&key);

        restored.deserialize_shard(&bytes).unwrap();

        assert_eq!(index, restored);
    }

    #[test]
    fn insert_remove_roundtrip() {
        let key = [0xFF; 32];
        let mut index = index(&key);

        index.insert(
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

        assert!(index.get("file.txt").is_some());

        index.trash("file.txt").unwrap();

        assert!(index.get("file.txt").is_none());
    }

    #[test]
    fn lock_unlock_roundtrip() {
        let key = [0x55u8; 32];
        let index = index(&key);
        let mut restored = Index::new(&key);

        for shard in 0..SHARD_COUNT {
            let locked = index.lock_shard(shard, &key, sign).unwrap();

            restored.unlock_shard(&key, &locked, verify).unwrap();
        }

        assert_eq!(index, restored);
    }

    #[test]
    fn trash_and_restore_roundtrip() {
        let key = [0xFF; 32];
        let mut index = index(&key);

        index.trash("photos/image.png").unwrap();

        assert!(index.get("photos/image.png").is_none());
        assert_ne!(index.entries.get("photos/image.png").unwrap().trashed, 0,);

        index.restore("photos/image.png").unwrap();

        assert!(index.get("photos/image.png").is_some());
        assert_eq!(index.entries.get("photos/image.png").unwrap().trashed, 0);
    }

    #[test]
    fn version_mismatch() {
        let key = [0xFF; 32];
        let mut index = index(&key);

        index.insert(
            "file",
            Entry {
                chunks: Vec::new(),
                versions: Vec::new(),
                size: 0,
                modified: 0,
                trashed: 0,
            },
        );

        let shard = index.shard_of("file");
        let mut bytes = index.serialize_shard(shard).unwrap();

        // Change the version bytes
        bytes[0] = 0xFF;
        bytes[1] = 0xFF;

        let mut restored = Index::new(&key);
        let result = restored.deserialize_shard(&bytes);

        assert!(matches!(
            result,
            Err(Error::UnsupportedIndexVersion(0xFFFF))
        ));
    }

    #[test]
    fn wrong_key() {
        let key = [0xFF; 32];
        let index = index(&key);
        let shard = index.shard_of("music/song.mp3");
        let locked = index.lock_shard(shard, &[0x55u8; 32], sign).unwrap();
        let mut restored = Index::new(&key);

        assert!(
            restored
                .unlock_shard(&[0x00u8; 32], &locked, verify)
                .is_err()
        );
    }

    #[test]
    fn empty_shard() {
        let key = [0x01u8; 32];
        let index = Index::new(&key);
        let locked = index.lock_shard(0, &key, sign).unwrap();
        let mut restored = Index::new(&key);

        restored.unlock_shard(&key, &locked, verify).unwrap();

        assert_eq!(restored.entries.len(), 0);
    }

    #[test]
    fn rename() {
        let key = [0xFF; 32];
        let mut index = index(&key);

        index
            .rename("photos/image.png", "photos/image_renamed.png")
            .unwrap();

        assert!(index.get("photos/image.png").is_none());
        assert!(index.get("photos/image_renamed.png").is_some());
    }

    #[test]
    fn rename_not_found() {
        let key = [0xFF; 32];
        let mut index = index(&key);
        let renamed = index.rename("nonexistent.txt", "nonexistent_renamed.txt");

        assert!(matches!(renamed, Err(Error::NotFound)));
    }

    #[test]
    fn rename_rejects_existing_new_path() {
        let key = [0xFF; 32];
        let mut index = index(&key);

        let renamed = index.rename("music/song.mp3", "photos/image.png");

        assert!(matches!(renamed, Err(Error::AlreadyExists)));
        // Nothing was touched
        assert!(index.get("music/song.mp3").is_some());
        assert!(index.get("photos/image.png").is_some());
    }

    #[test]
    fn get_returns_none_trashed() {
        let key = [0xFF; 32];
        let mut index = index(&key);

        index.trash("photos/image.png").unwrap();

        assert!(index.get("photos/image.png").is_none());
    }

    #[test]
    fn deterministic_address() {
        let public_signing_key = [0xFFu8; 32];

        assert_eq!(
            Index::address(&public_signing_key),
            Index::address(&public_signing_key)
        );
    }

    #[test]
    fn different_addresses() {
        let key1 = Index::address(&[0x01u8; 32]);
        let key2 = Index::address(&[0x02u8; 32]);

        assert_ne!(key1, key2);
    }

    #[test]
    fn addresses_includes_all_version_chunks() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);

        index.insert(
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

        let addrs = index.addresses_live();

        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&[0xAAu8; 32]));
        assert!(addrs.contains(&[0xBBu8; 32]));
    }

    #[test]
    fn addresses_excludes_trashed() {
        let key = [0xFF; 32];
        let mut index = index(&key);

        index.trash("photos/image.png").unwrap();

        // Only the 2 chunks from `music/song.mp3`, ignored the one chunk of `photos/image.png`
        assert_eq!(index.addresses_live().len(), 2);
        assert_eq!(index.addresses_trashed().len(), 1);
    }

    #[test]
    fn purge_returns_trashed_addresses() {
        let key = [0xFF; 32];
        let mut index = index(&key);

        index.trash("photos/image.png").unwrap();

        let deleted = index.purge("photos/image.png").unwrap();

        assert_eq!(deleted, vec![[0xEFu8; 32]]);
        assert!(!index.entries.contains_key("photos/image.png"));
    }

    #[test]
    fn purge_skips_live_shared_addresses() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);
        let shared_addr = EntryChunk {
            address: [0xAAu8; 32],
            encrypted_key: [0xFF; 60],
        };

        index.insert(
            "a",
            Entry {
                chunks: vec![shared_addr.clone()],
                versions: Vec::new(),
                size: 1,
                modified: 0,
                trashed: 0,
            },
        );
        index.insert(
            "b",
            Entry {
                chunks: vec![shared_addr],
                versions: Vec::new(),
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
    fn purge_skips_address_still_used_by_a_trashed_entry() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);
        let shared = EntryChunk {
            address: [0xAAu8; 32],
            encrypted_key: [0xFF; 60],
        };

        index.insert(
            "a",
            Entry {
                chunks: vec![shared.clone()],
                versions: Vec::new(),
                size: 1,
                modified: 0,
                trashed: 0,
            },
        );
        index.insert(
            "b",
            Entry {
                chunks: vec![shared],
                versions: Vec::new(),
                size: 1,
                modified: 0,
                trashed: 0,
            },
        );

        index.trash("a").unwrap();
        index.trash("b").unwrap();

        let deleted = index.purge("a").unwrap();

        // "b" is trashed but not yet purged, and still references the shared chunk, therefore
        // no chunks should be deleted
        assert!(deleted.is_empty());
    }

    #[test]
    fn purge_rejects_live_entry() {
        let key = [0xFF; 32];
        let mut index = index(&key);

        // Cannot purge a live entry
        assert!(index.purge("music/song.mp3").is_err());
    }

    #[test]
    fn purge_all_clears_trash() {
        let key = [0xFF; 32];
        let mut index = index(&key);

        index.trash("photos/image.png").unwrap();
        index.trash("music/song.mp3").unwrap();

        let deleted = index.purge_all();

        assert!(index.entries.is_empty());
        assert_eq!(deleted.len(), 3); // 2 from song + 1 from image
    }

    #[test]
    fn all_chunk_addresses() {
        let key = [0xFF; 32];
        let index = index(&key);
        let addresses = index.addresses_live();

        // Sample has 2 + 1 = 3 chunk addresses
        assert_eq!(addresses.len(), 3);
    }

    #[test]
    fn drop_version() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);

        index.insert(
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

        let dropped = index.drop_version("file", 0).unwrap();

        assert_eq!(dropped, vec![[0xAAu8; 32]]);
        assert!(index.entries.get("file").unwrap().versions.is_empty());
    }

    #[test]
    fn drop_version_skips_address_shared_with_active() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);
        let shared = EntryChunk {
            address: [0xAAu8; 32],
            encrypted_key: [0xFF; 60],
        };

        index.insert(
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

        let dropped = index.drop_version("file", 0).unwrap();

        // Must not delete the address since active still uses it
        assert!(dropped.is_empty());
    }

    #[test]
    fn drop_version_skips_address_still_used_by_a_trashed_entry() {
        let key = [0xFF; 32];
        let mut index = Index::new(&key);
        let shared = EntryChunk {
            address: [0xAAu8; 32],
            encrypted_key: [0xFF; 60],
        };

        index.insert(
            "a",
            Entry {
                chunks: vec![EntryChunk {
                    address: [0xBBu8; 32],
                    encrypted_key: [0xFF; 60],
                }],
                versions: vec![Version {
                    chunks: vec![shared.clone()],
                    size: 1,
                    modified: 0,
                }],
                size: 1,
                modified: 0,
                trashed: 0,
            },
        );
        index.insert(
            "b",
            Entry {
                chunks: vec![shared],
                versions: Vec::new(),
                size: 1,
                modified: 0,
                trashed: 0,
            },
        );

        index.trash("b").unwrap();

        let dropped = index.drop_version("a", 0).unwrap();

        // "b" (trashed, unpurged) still references the chunk, which must not be reported
        // as droppable
        assert!(dropped.is_empty());
    }
}
