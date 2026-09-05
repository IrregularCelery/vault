//! The primary API surface of the vault.
//!
//! A [`Vault`] owns an [`Identity`] and a [`storage::Backend`] and exposes high-level file
//! operations: put, get, version history, rename, trash/restore/purge, and integrity verification.
//!
//! Index shards are loaded lazily: [`Vault::open`] does no storage I/O at all. Each index shard is
//! only retrieved and decrypted from storage the first time a path that falls into it is actually
//! touched, then kept cached in memory. (see [`Vault::ensure_shard`]).
//!
//! Every mutating method updates the in-memory index and then flushes only the shards that are
//! marked dirty back to the storage before returning.

use crate::{
    crypto::cipher,
    identity::Identity,
    storage::{
        self, Key, Kind,
        chunk::{self, Chunks},
        index::{self, Index, Properties, VersionProperties},
    },
};

use gate::sys::{
    borrow::Cow,
    io,
    macros::format,
    string::{String, ToString},
    time,
    vec::Vec,
};

/// Errors from vault-level file operations.
#[derive(Debug)]
pub enum Error {
    /// A blob or index shard storage operation failed.
    Storage(storage::Error),

    /// An AEAD encryption or decryption error (wrong key, corrupted data, etc.).
    Cipher(cipher::Error),

    /// An error from the chunker, most likely an I/O error.
    Chunk(chunk::Error),

    /// An index-level error.
    Index(index::Error),

    /// An I/O error most likely while writing decrypted plaintext to the writer.
    Io(io::Error),

    /// The requested file path does not exist in the index (or is trashed).
    NotFound,

    /// The requested version index is out of bounds for the entry's history.
    VersionNotFound,

    /// A [`Vault::rename`], [`Vault::detach_version`], or [`Vault::detach_version_current`]
    /// was attempted onto a new path that already has an entry.
    AlreadyExists,

    /// A [`Vault::restore`] was attempted on an entry that is not currently trashed.
    NotTrashed,

    /// A [`Vault::trash`] was attempted on an entry that has already been trashed.
    AlreadyTrashed,

    /// A blob's signature did not match, could be an index shard or chunks (including versions).
    Tampered(String),

    /// Specific message error.
    Other(Cow<'static, str>),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage: {}", e),
            Self::Cipher(e) => write!(f, "cipher: {}", e),
            Self::Chunk(e) => write!(f, "chunk: {}", e),
            Self::Index(e) => write!(f, "index: {}", e),
            Self::Io(e) => write!(f, "I/O: {}", e),
            Self::NotFound => write!(f, "file not found"),
            Self::VersionNotFound => write!(f, "version not found"),
            Self::AlreadyExists => write!(f, "a file already exists at the new path"),
            Self::NotTrashed => write!(f, "file is not in the trash"),
            Self::AlreadyTrashed => write!(f, "file is already in the trash"),
            Self::Tampered(e) => write!(f, "tampered blob: {}", e),
            Self::Other(e) => write!(f, "{}", e),
        }
    }
}

impl From<storage::Error> for Error {
    fn from(value: storage::Error) -> Self {
        match value {
            storage::Error::NotFound => Self::NotFound,
            other => Self::Storage(other),
        }
    }
}

impl From<cipher::Error> for Error {
    fn from(value: cipher::Error) -> Self {
        match value {
            cipher::Error::InvalidSignature => Self::Tampered("unknown".into()),
            other => Self::Cipher(other),
        }
    }
}

impl From<chunk::Error> for Error {
    fn from(value: chunk::Error) -> Self {
        Self::Chunk(value)
    }
}

impl From<index::Error> for Error {
    fn from(value: index::Error) -> Self {
        match value {
            index::Error::NotFound => Self::NotFound,
            index::Error::VersionNotFound => Self::VersionNotFound,
            index::Error::AlreadyExists => Self::AlreadyExists,
            index::Error::NotTrashed => Self::NotTrashed,
            index::Error::AlreadyTrashed => Self::AlreadyTrashed,
            other => Self::Index(other),
        }
    }
}

/// An active vault session with a connected storage backend and a lazily-populated index cache.
pub struct Vault<S: storage::Backend> {
    /// The cryptographic identity used to encrypt, decrypt, sign, and verify all blobs and index
    /// shards.
    identity: Identity,

    /// The storage backend.
    storage: S,

    /// The lazily-populated index cache. See the module and [`Index`] docs for more details.
    index: core::cell::RefCell<Index>,
}

impl<S: storage::Backend> Vault<S> {
    /// Opens a new vault with an empty index.
    ///
    /// Shards are lazily loaded into the index when they are actually touched.
    pub fn open(identity: Identity, storage: S) -> Self {
        let encryption_key = &identity.encryption_key();

        Self {
            identity,
            storage,
            index: core::cell::RefCell::new(Index::new(encryption_key)),
        }
    }

    /// Encrypts and stores a file, returning the number of new chunks uploaded.
    ///
    /// The file is split into [`chunk::CHUNK_SIZE`]-byte chunks. Each chunk is addressed by
    /// a keyed BLAKE3 hash of its plaintext, enabling per-user-per-chunk deduplication.
    /// If `path` already exists with different content, the previous version is saved to history
    /// via [`index::Entry::push_version`].
    ///
    /// Returns the number of new chunks written.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading a shard, writing a chunk or flushing the dirty index
    ///   shards fails.
    /// - [`Error::Cipher`]: If chunk or index encryption fails.
    /// - [`Error::Chunk`]: If reading from `reader` fails.
    /// - [`Error::Index`]: If loading or encrypting the dirty index shard fails.
    /// - [`Error::Tampered`]: If the dirty index shard's signature is invalid.
    pub fn put(&mut self, path: &str, reader: impl io::Read, size: u64) -> Result<usize, Error> {
        self.ensure_shard_for(path)?;

        let mut chunks = Chunks::new(reader);
        let mut entry_chunks = Vec::new();

        while let Some(chunk) = chunks.next_chunk()? {
            let address = chunk.address(&self.identity.encryption_key());
            let key = chunk.key(&self.identity.encryption_key());
            let encrypted_chunk_key = cipher::encrypt(&self.identity.encryption_key(), &key)?;
            let mut encrypted_key = [0u8; 60];

            encrypted_key.copy_from_slice(&encrypted_chunk_key);

            // Redundant check but we keep it in case a storage::Backend::put() didn't do the check
            // though not entirely useless since we can avoid calling an unnecessary `cipher::lock()`
            if !self.storage.exists(Key::Blob(address))? {
                let encrypted =
                    cipher::lock(&key, chunk.data, |message| self.identity.sign(message))?;

                self.storage.put(Key::Blob(address), &encrypted)?;
            }

            entry_chunks.push(index::EntryChunk {
                address,
                encrypted_key,
            });
        }

        let new_addresses: Vec<[u8; 32]> = entry_chunks.iter().map(|c| c.address).collect();

        enum Action {
            NoOp,
            Restore,
            NewVersion,
            Insert,
        }

        let action = match self.index.get_mut().entry(path) {
            Some(existing) => {
                let existing_addresses: Vec<[u8; 32]> =
                    existing.chunks.iter().map(|c| c.address).collect();

                if existing_addresses == new_addresses {
                    if existing.trashed == 0 {
                        Action::NoOp
                    } else {
                        Action::Restore
                    }
                } else {
                    Action::NewVersion
                }
            }
            None => Action::Insert,
        };

        if matches!(action, Action::NoOp) {
            return Ok(0);
        }

        let chunk_count = entry_chunks.len();
        let modified = time::current_secs().unwrap_or(0);

        self.mutate_and_flush(&[path], move |index| match action {
            Action::NoOp => unreachable!("returned early above"),
            Action::Restore => {
                let existing = index.entry_mut(path).expect("already checked above");

                existing.trashed = 0;

                index.mark_dirty(path);

                Ok(0)
            }
            Action::NewVersion => {
                let existing = index.entry_mut(path).expect("already checked above");

                existing.push_version(entry_chunks, size, modified);

                // NOTE: It's debatable whether this should gracefully restore the `path`, or return
                // an error instead.
                existing.trashed = 0;

                index.mark_dirty(path);

                Ok(chunk_count)
            }
            Action::Insert => {
                index.insert(
                    path,
                    index::Entry {
                        chunks: entry_chunks,
                        versions: Vec::new(),
                        size,
                        modified,
                        trashed: 0,
                    },
                );

                Ok(chunk_count)
            }
        })
    }

    /// Decrypts and streams the current version of `path` into `writer` then returns the total
    /// number of plaintext bytes written.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading a chunk blob or the touched index shard fails.
    /// - [`Error::Cipher`]: If chunk or index decryption fails.
    /// - [`Error::Io`]: If writing to `writer` fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::Tampered`]: If signature verification fails.
    /// - [`Error::Other`]: If wrong size chunk encryption key is found.
    pub fn get(&self, path: &str, writer: &mut impl io::Write) -> Result<u64, Error> {
        self.ensure_shard_for(path)?;

        let index = self.index.borrow();
        let entry = index.get(path).ok_or(Error::NotFound)?;

        self.decrypt_chunks(path, &entry.chunks, writer)
    }

    /// Returns version metadata for all historical revisions of `path`, oldest first, or `None`
    /// if `path` is absent.
    ///
    /// Includes versions of trashed entries.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading the touched index shard fails.
    /// - [`Error::Index`]: If the touched index shard's decryption or deserialization fails.
    /// - [`Error::Tampered`]: If the touched index shard's signature is invalid.
    pub fn versions(&self, path: &str) -> Result<Option<Vec<VersionProperties>>, Error> {
        self.ensure_shard_for(path)?;

        Ok(self.index.borrow().entry(path).map(|e| {
            e.versions
                .iter()
                .enumerate()
                .map(|(i, v)| VersionProperties {
                    index: i,
                    chunk_count: v.chunks.len(),
                    size: v.size,
                    modified: v.modified,
                })
                .collect()
        }))
    }

    /// Decrypts and streams a specific historical version of `path` into `writer`.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading a chunk blob or the touched index shard fails.
    /// - [`Error::Cipher`]: If chunk or index decryption fails.
    /// - [`Error::Io`]: If writing to `writer` fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::VersionNotFound`]: If version at `version_index` is absent.
    /// - [`Error::Tampered`]: If signature verification fails.
    /// - [`Error::Other`]: If wrong size chunk encryption key is found.
    pub fn get_version(
        &self,
        path: &str,
        version_index: usize,
        writer: &mut impl io::Write,
    ) -> Result<u64, Error> {
        self.ensure_shard_for(path)?;

        let index = self.index.borrow();

        let entry = index.entry(path).ok_or(Error::NotFound)?;
        let version = entry
            .versions
            .get(version_index)
            .ok_or(Error::VersionNotFound)?;

        self.decrypt_chunks(path, &version.chunks, writer)
    }

    /// Rolls `path` back to historical version at `version_index`, pushing the current state into
    /// history.
    ///
    /// The target version is removed from the version list and becomes the active revision.
    /// The previously-active state is appended to the end of the version list.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading or encrypting the touched index shard fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::VersionNotFound`]: If version at `version_index` is absent.
    /// - [`Error::Tampered`]: If the touched index shard's signature is invalid.
    pub fn revert(&mut self, path: &str, version_index: usize) -> Result<(), Error> {
        self.ensure_shard_for(path)?;
        self.mutate_and_flush(&[path], |index| {
            let entry = index.entry_mut(path).ok_or(Error::NotFound)?;

            if version_index >= entry.versions.len() {
                return Err(Error::VersionNotFound);
            }

            let current = index::Version {
                chunks: core::mem::take(&mut entry.chunks),
                size: entry.size,
                modified: entry.modified,
            };
            let target = entry.versions.remove(version_index);

            entry.chunks = target.chunks;
            entry.size = target.size;
            entry.modified = target.modified;
            entry.versions.push(current);

            index.mark_dirty(path);

            Ok(())
        })
    }

    /// Permanently drops a historical version and deletes its now-unreferenced blobs.
    ///
    /// Addresses still referenced by the active version or other files are preserved. Since that
    /// check needs to go through every file, this method loads every index shard rather than just
    /// the one with `path` in it.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading or encrypting any index shard fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::VersionNotFound`]: If version at `version_index` is absent.
    /// - [`Error::Tampered`]: If any index shard's signature is invalid.
    pub fn drop_version(&mut self, path: &str, version_index: usize) -> Result<(), Error> {
        self.ensure_all_shards()?;

        let dropped =
            self.mutate_and_flush(
                &[path],
                |index| Ok(index.drop_version(path, version_index)?),
            )?;

        for address in dropped {
            self.storage.delete(Key::Blob(address))?;
        }

        Ok(())
    }

    /// Replaces the active version with the most recent historical version.
    ///
    /// Active chunks that are no longer referenced are deleted from storage.
    /// If no historical versions exist, the file is deleted entirely. This needs to go through
    /// every file in the vault to know what's still referenced, so it needs to load every index
    /// shard rather than just the one with `path` in it.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading or encrypting any index shard fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::Tampered`]: If any index shard's signature is invalid.
    pub fn drop_version_current(&mut self, path: &str) -> Result<(), Error> {
        self.ensure_all_shards()?;

        let has_no_versions = self
            .index
            .borrow()
            .entry(path)
            .ok_or(Error::NotFound)?
            .versions
            .is_empty();

        if has_no_versions {
            return self.delete(path);
        }

        let dropped_chunks = self.mutate_and_flush(&[path], |index| {
            let entry = index.entry_mut(path).ok_or(Error::NotFound)?;
            let latest_version = entry.versions.remove(entry.versions.len() - 1);
            let dropped_chunks = core::mem::replace(&mut entry.chunks, latest_version.chunks);

            entry.size = latest_version.size;
            entry.modified = latest_version.modified;

            index.mark_dirty(path);

            let referenced: Vec<[u8; 32]> = index.addresses();

            Ok(dropped_chunks
                .into_iter()
                .map(|c| c.address)
                .filter(|a| !referenced.contains(a))
                .collect::<Vec<[u8; 32]>>())
        })?;

        for address in dropped_chunks {
            self.storage.delete(Key::Blob(address))?;
        }

        Ok(())
    }

    /// Moves a historical version out of `path`'s history into a new independent file at `new_path`.
    ///
    /// No blobs are copied, only index references are updated. Both paths become independently
    /// readable and writable after the call.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading or encrypting a touched index shard fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::VersionNotFound`]: If version at `version_index` is absent.
    /// - [`Error::AlreadyExists`]: If `new_path` already exists.
    /// - [`Error::Tampered`]: If a touched index shard's signature is invalid.
    pub fn detach_version(
        &mut self,
        path: &str,
        new_path: &str,
        version_index: usize,
    ) -> Result<(), Error> {
        self.ensure_shard_for(path)?;
        self.ensure_shard_for(new_path)?;
        self.mutate_and_flush(&[path, new_path], |index| {
            if index.contains(new_path) {
                return Err(Error::AlreadyExists);
            }

            let entry = index.entry_mut(path).ok_or(Error::NotFound)?;

            if version_index >= entry.versions.len() {
                return Err(Error::VersionNotFound);
            }

            let detached = entry.versions.remove(version_index);

            index.mark_dirty(path);
            index.insert(
                new_path,
                index::Entry {
                    chunks: detached.chunks,
                    versions: Vec::new(),
                    size: detached.size,
                    modified: detached.modified,
                    trashed: 0,
                },
            );

            Ok(())
        })
    }

    /// Moves the active version of `path` to `new_path` and makees the most recent historical
    /// version the new active revision.
    ///
    /// Equivalent to [`Vault::rename`] when no historical versions exist. (this also makes
    /// the entry live if trashed)
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading or encrypting a touched index shard fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::AlreadyExists`]: If `new_path` already exists.
    /// - [`Error::Tampered`]: If a touched index shard's signature is invalid.
    pub fn detach_version_current(&mut self, path: &str, new_path: &str) -> Result<(), Error> {
        self.ensure_shard_for(path)?;
        self.ensure_shard_for(new_path)?;

        self.mutate_and_flush(&[path, new_path], |index| {
            if index.contains(new_path) {
                return Err(Error::AlreadyExists);
            }

            let entry = index.entry_mut(path).ok_or(Error::NotFound)?;

            if entry.versions.is_empty() {
                index.rename(path, new_path)?;

                if let Some(detached) = index.entry_mut(new_path) {
                    detached.trashed = 0;
                    index.mark_dirty(new_path);
                }

                return Ok(());
            }

            let latest_version = entry.versions.remove(entry.versions.len() - 1);
            let chunks = core::mem::replace(&mut entry.chunks, latest_version.chunks);
            let size = core::mem::replace(&mut entry.size, latest_version.size);
            let modified = core::mem::replace(&mut entry.modified, latest_version.modified);

            index.mark_dirty(path);
            index.insert(
                new_path,
                index::Entry {
                    chunks,
                    versions: Vec::new(),
                    size,
                    modified,
                    trashed: 0,
                },
            );

            Ok(())
        })
    }

    /// Renames `old_path` to `new_path` in the index. Index manipulation only, no blobs are
    /// touched. A no-op if both `old_path` and `new_path` are identical.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading or encrypting a touched index shard fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::AlreadyExists`]: If `new_path` already exists.
    /// - [`Error::Tampered`]: If a touched index shard's signature is invalid.
    pub fn rename(&mut self, old_path: &str, new_path: &str) -> Result<(), Error> {
        if old_path == new_path {
            return Ok(());
        }

        self.ensure_shard_for(old_path)?;
        self.ensure_shard_for(new_path)?;
        self.mutate_and_flush(&[old_path, new_path], |index| {
            Ok(index.rename(old_path, new_path)?)
        })
    }

    /// Soft-deletes `path`, moving it to the trash. Blobs are retained and the entry can be
    /// recovered with [`Vault::restore`].
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading or encrypting the touched index shard fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::AlreadyTrashed`]: If the `path` is already trashed.
    /// - [`Error::Tampered`]: If the touched index shard's signature is invalid.
    pub fn trash(&mut self, path: &str) -> Result<(), Error> {
        self.ensure_shard_for(path)?;
        self.mutate_and_flush(&[path], |index| Ok(index.trash(path)?))
    }

    /// Recovers a trashed entry, making it live again.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading or encrypting the touched index shard fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::NotTrashed`]: If the `path` is not currently trashed.
    /// - [`Error::Tampered`]: If the touched index shard's signature is invalid.
    pub fn restore(&mut self, path: &str) -> Result<(), Error> {
        self.ensure_shard_for(path)?;
        self.mutate_and_flush(&[path], |index| Ok(index.restore(path)?))
    }

    /// Permanently removes a trashed entry and deletes its blobs if no longer referenced by any
    /// file. Since that check needs to go through every file, this method loads every index shard
    /// rather than just the one with `path` in it.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading or encrypting any index shard fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::NotTrashed`]: If the `path` is not currently trashed.
    /// - [`Error::Tampered`]: If any index shard's signature is invalid.
    pub fn purge(&mut self, path: &str) -> Result<(), Error> {
        self.ensure_all_shards()?;

        let addresses = self.mutate_and_flush(&[path], |index| Ok(index.purge(path)?))?;

        for address in addresses {
            self.storage.delete(Key::Blob(address))?;
        }

        Ok(())
    }

    /// Purges all trashed entries at once. Returns the total number of blobs deleted.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading or encrypting any index shard fails.
    /// - [`Error::Tampered`]: If any index shard's signature is invalid.
    pub fn cleanup(&mut self) -> Result<usize, Error> {
        self.ensure_all_shards()?;

        let trashed_path: Vec<String> = self
            .index
            .borrow()
            .iter()
            .filter(|(_, v)| v.trashed != 0)
            .map(|(k, _)| k.to_string())
            .collect();
        let path_refs: Vec<&str> = trashed_path.iter().map(|s| s.as_str()).collect();

        let addresses = self.mutate_and_flush(&path_refs, |index| Ok(index.purge_all()))?;
        let removed = addresses.len();

        for address in addresses {
            self.storage.delete(Key::Blob(address))?;
        }

        Ok(removed)
    }

    /// Hard-deletes `path`, trashes it and immediately purges it. Non-recoverable.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading or encrypting an index shard fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::Tampered`]: If an index shard's signature is invalid.
    pub fn delete(&mut self, path: &str) -> Result<(), Error> {
        self.ensure_shard_for(path)?;

        let addresses = self.mutate_and_flush(&[path], |index| {
            match index.trash(path) {
                Ok(()) | Err(index::Error::AlreadyTrashed) => {}
                Err(other) => return Err(other.into()),
            }

            Ok(index.purge(path)?)
        })?;

        for address in addresses {
            self.storage.delete(Key::Blob(address))?;
        }

        Ok(())
    }

    /// Returns a sorted list of paths for all live (non-trashed) entries. Loads every index shard,
    /// since every path in the vault needs to be considered.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading any index shard fails.
    /// - [`Error::Tampered`]: If any index shard's signature is invalid.
    pub fn list(&self) -> Result<Vec<String>, Error> {
        self.ensure_all_shards()?;

        let mut paths: Vec<String> = self
            .index
            .borrow()
            .iter()
            .filter(|(_, v)| v.trashed == 0)
            .map(|(k, _)| k.to_string())
            .collect();

        paths.sort();

        Ok(paths)
    }

    /// Returns a sorted list of paths for all trashed entries. Loads every index shard, since
    /// every path in the vault needs to be considered.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Index`]: If loading any index shard fails.
    /// - [`Error::Tampered`]: If any index shard's signature is invalid.
    pub fn list_trash(&self) -> Result<Vec<String>, Error> {
        self.ensure_all_shards()?;

        let mut paths: Vec<String> = self
            .index
            .borrow()
            .iter()
            .filter(|(_, v)| v.trashed != 0)
            .map(|(k, _)| k.to_string())
            .collect();

        paths.sort();

        Ok(paths)
    }

    /// Returns [`Properties`] metadata for `path`, or `None` if `path` is absent.
    ///
    /// Also returns metadata for trashed entries.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading the touched index shard fails.
    /// - [`Error::Index`]: If the touched index shard's decryption or deserialization fails.
    /// - [`Error::Tampered`]: If the touched index shard's signature is invalid.
    pub fn properties(&self, path: &str) -> Result<Option<Properties>, Error> {
        self.ensure_shard_for(path)?;

        Ok(self.index.borrow().entry(path).map(|e| Properties {
            chunk_count: e.chunks.len(),
            size: e.size,
            modified: e.modified,
            trashed: e.trashed,
            version_count: e.versions.len(),
        }))
    }

    /// Verifies the signatures on all chunks of `path`, including every version.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading a chunk blob or the touched index shard fails.
    /// - [`Error::Cipher`]: If chunk or index decryption fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::Tampered`]: If signature verification fails.
    pub fn verify(&self, path: &str) -> Result<(), Error> {
        self.ensure_shard_for(path)?;

        let index = self.index.borrow();

        let entry = index.entry(path).ok_or(Error::NotFound)?;

        self.verify_entry_chunks(path, &entry.chunks)?;

        for (i, version) in entry.versions.iter().enumerate() {
            self.verify_entry_chunks(
                &format!("{}@v{}", path, i + 1), // Display versions start from 1
                &version.chunks,
            )?;
        }

        Ok(())
    }

    /// Verifies every chunk in the index, live, trashed, and all versions, as well as every
    /// index shard blob itself.
    ///
    /// Returns a sorted, deduplicated list of paths with at least one tampered chunk, plus an
    /// entry per tampered index shard (formatted as `"index shard xxxx"`).
    /// Unlike other methods, this always re-reads and re-verifies every index shard's raw bytes
    /// directly from storage, even ones that are already cached.
    pub fn verify_all(&self) -> Vec<String> {
        let mut tampered = Vec::new();

        // Check the index shards
        if let Ok(keys) = self.storage.list(Kind::Index) {
            for key in keys {
                let Key::Index(shard) = key else { continue };

                if let Ok(blob) = self.storage.get(key)
                    && cipher::unlock(
                        &self.identity.encryption_key(),
                        &blob,
                        |message, signature_bytes| self.identity.verify(message, signature_bytes),
                    )
                    .is_err()
                {
                    tampered.push(format!("index shard {:04x}", shard));
                }

                // Also make sure the shard is loaded into the cache for the chunk-level pass
                // below. A shard already flagged above may fail here too, which is fine, it's
                // already accounted for.
                let _ = self.ensure_shard(shard);
            }
        }

        for (path, entry) in self.index.borrow().iter() {
            if self.verify_entry_chunks(path, &entry.chunks).is_err() {
                tampered.push(path.to_string());
            }

            for (i, version) in entry.versions.iter().enumerate() {
                let path_versioned = format!("{}@v{}", path, i + 1); // Display versions start from 1

                if self
                    .verify_entry_chunks(&path_versioned, &version.chunks)
                    .is_err()
                {
                    tampered.push(path_versioned);
                }
            }
        }

        tampered.sort();
        tampered.dedup();

        tampered
    }

    /// Ensures `shard` is loaded into the in-memory index cache, getting and decrypting it from
    /// storage the first time it's needed. A no-op if the shard is already cached.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading the shard from storage fails for a reason other than the
    ///   shard not existing yet.
    /// - [`Error::Index`]: If the shard's decryption or deserialization fails.
    /// - [`Error::Tampered`]: If the shard's signature is invalid.
    fn ensure_shard(&self, shard: u16) -> Result<(), Error> {
        if self.index.borrow().is_loaded(shard) {
            return Ok(());
        }

        match self.storage.get(Key::Index(shard)) {
            Ok(blob) => {
                self.index
                    .borrow_mut()
                    .unlock_shard(
                        &self.identity.encryption_key(),
                        &blob,
                        |message, signature_bytes| self.identity.verify(message, signature_bytes),
                    )
                    .map_err(|e| match e {
                        index::Error::Tampered => {
                            Error::Tampered(format!("index shard {:04x}", shard))
                        }
                        other => Error::Index(other),
                    })?;
            }
            Err(storage::Error::NotFound) => {}
            Err(e) => return Err(Error::Storage(e)),
        }

        self.index.borrow_mut().mark_loaded(shard);

        Ok(())
    }

    /// Ensures the shard for `path` is loaded into the in-memory index cache. See [`Vault::ensure_shard`].
    fn ensure_shard_for(&self, path: &str) -> Result<(), Error> {
        let shard = self.index.borrow().shard_of(path);

        self.ensure_shard(shard)
    }

    /// Ensures every shard currently present in storage is loaded into the in-memory index cache.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If listing or reading a shard fails.
    /// - [`Error::Index`]: If a shard's decryption or deserialization fails.
    /// - [`Error::Tampered`]: If a shard's signature is invalid.
    fn ensure_all_shards(&self) -> Result<(), Error> {
        for key in self.storage.list(Kind::Index)? {
            let Key::Index(shard) = key else { continue };

            self.ensure_shard(shard)?;
        }

        Ok(())
    }

    /// Decrypts the chunk list for `path` and writes plaintext to `writer`.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading a chunk blob from storage fails.
    /// - [`Error::Cipher`]: If chunk or index decryption fails.
    /// - [`Error::Io`]: If writing to `writer` fails.
    /// - [`Error::Tampered`]: If signature verification fails.
    /// - [`Error::Other`]: If wrong size chunk encryption key is found.
    fn decrypt_chunks(
        &self,
        path: &str,
        chunks: &[index::EntryChunk],
        writer: &mut impl io::Write,
    ) -> Result<u64, Error> {
        let mut size = 0u64;

        for chunk in chunks {
            let chunk_key = cipher::decrypt(&self.identity.encryption_key(), &chunk.encrypted_key)?;
            let key = chunk_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::Other("wrong size chunk encryption key was found".into()))?;
            let blob = self
                .storage
                .get(Key::Blob(chunk.address))
                .map_err(|e| match e {
                    storage::Error::NotFound => Error::Tampered(format!(
                        "{}: referenced chunk is missing from storage",
                        path
                    )),
                    other => Error::Storage(other),
                })?;
            let plaintext = cipher::unlock(&key, &blob, |message, signature_bytes| {
                self.identity.verify(message, signature_bytes)
            })
            .map_err(|e| match e {
                cipher::Error::InvalidSignature => Error::Tampered(path.into()),
                other => Error::Cipher(other),
            })?;

            writer.write_all(&plaintext).map_err(Error::Io)?;

            size += plaintext.len() as u64;
        }

        Ok(size)
    }

    /// Verifies signatures on a chunk list.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading a chunk blob from storage fails.
    /// - [`Error::Cipher`]: If chunk or index decryption fails.
    /// - [`Error::Tampered`]: If signature verification fails.
    fn verify_entry_chunks(&self, path: &str, chunks: &[index::EntryChunk]) -> Result<(), Error> {
        for chunk in chunks {
            let blob = self
                .storage
                .get(Key::Blob(chunk.address))
                .map_err(|e| match e {
                    storage::Error::NotFound => Error::Tampered(format!(
                        "{}: referenced chunk is missing from storage",
                        path
                    )),
                    other => Error::Storage(other),
                })?;

            cipher::verify_signature(&blob, |message, signature_bytes| {
                self.identity.verify(message, signature_bytes)
            })
            .map_err(|e| match e {
                cipher::Error::InvalidSignature => Error::Tampered(path.into()),
                other => Error::Cipher(other),
            })?;
        }

        Ok(())
    }

    /// Serializes, encrypts, signs, and persists every shard marked dirty since the last flush.
    /// A shard left with no entries is deleted instead, so a shard file only exists in storage
    /// while it actually contains data.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If writing or deleting a shard fails.
    /// - [`Error::Index`]: If a shard's encryption or serialization fails.
    fn flush_index(&mut self) -> Result<(), Error> {
        let dirty = self.index.get_mut().dirty_shards();
        let mut to_delete = Vec::new();

        // Writes before deletes: if something below fails partway through, we want to have failed
        // before removing anything, not after. A partially-failed flush can leave old and new
        // content briefly existing on disk until the next successful flush, but it should never
        // lose data.
        //
        // Each shard's dirty flag is only cleared once it's actually confirmed persisted (or
        // deleted); if a call below fails, every shard not yet reached, including the one that
        // just failed, stays marked dirty, so the next `flush_index()` call retries exactly what
        // didn't make it, instead of silently forgetting about it.
        for shard in dirty {
            if self.index.get_mut().is_shard_empty(shard) {
                to_delete.push(shard);

                continue;
            }

            let data = self.index.get_mut().lock_shard(
                shard,
                &self.identity.encryption_key(),
                |message| self.identity.sign(message),
            )?;

            self.storage.put(Key::Index(shard), &data)?;
            self.index.get_mut().clear_dirty(shard);
        }

        for shard in to_delete {
            self.storage.delete(Key::Index(shard))?;
            self.index.get_mut().clear_dirty(shard);
        }

        Ok(())
    }

    /// Runs `mutate` against the index, then flushes. If the flush fails, every path in
    /// `paths` is rolled back to its state immediately before `mutate` ran, so a caller that
    /// gets `Err` back can trust nothing changed.
    ///
    /// `mutate` is expected to validate everything it needs to before touching the index,
    /// the same way every [`Index`] method already does (`NotFound`/`AlreadyExists`/etc. are all
    /// checked first). If `mutate` itself returns `Err`, this assumes nothing was actually
    /// changed and skips the rollback.
    fn mutate_and_flush<T>(
        &mut self,
        paths: &[&str],
        mutate: impl FnOnce(&mut Index) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let snapshots: Vec<(&str, Option<index::Entry>)> = paths
            .iter()
            .map(|&p| (p, self.index.get_mut().entry(p).cloned()))
            .collect();
        let value = mutate(self.index.get_mut())?;

        if let Err(e) = self.flush_index() {
            for (path, snapshot) in snapshots {
                self.index.get_mut().restore_entry(path, snapshot);
            }

            return Err(e);
        }

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::storage::{Backend, Kind, chunk::CHUNK_SIZE, local};

    use gate::{
        crypto::bip39,
        sys::{
            env, fs,
            macros::{format, vec},
            path::{Path, PathBuf},
            string::ToString,
            time,
        },
    };

    mod faulty {
        use crate::storage;

        use gate::sys::{io, macros::format, vec::Vec};

        // 5 (operation: put/get/exists/delete/list) * 2 (kind: index/blob)
        const OPERATION_COUNT: usize = 10;

        #[derive(Debug, Clone, Copy)]
        pub enum Operation {
            Put,
            Get,
            Delete,
            List,
            Exists,
        }

        impl Operation {
            fn slot(self, kind: storage::Kind) -> usize {
                let op = match self {
                    Operation::Put => 0,
                    Operation::Get => 1,
                    Operation::Delete => 2,
                    Operation::List => 3,
                    Operation::Exists => 4,
                };
                let k = match kind {
                    storage::Kind::Index => 0,
                    storage::Kind::Blob => 1,
                };

                op * 2 + k
            }
        }

        pub struct Storage<I: storage::Backend> {
            inner: I,
            calls: [core::cell::Cell<usize>; OPERATION_COUNT],
            faults: [core::cell::Cell<Option<usize>>; OPERATION_COUNT],
        }

        impl<I: storage::Backend> Storage<I> {
            pub fn new(inner: I) -> Self {
                Self {
                    inner,
                    calls: [const { core::cell::Cell::new(0) }; OPERATION_COUNT],
                    faults: [const { core::cell::Cell::new(None) }; OPERATION_COUNT],
                }
            }

            pub fn fail_nth(&self, operation: Operation, kind: storage::Kind, n: usize) {
                let slot = operation.slot(kind);

                self.calls[slot].set(0);
                self.faults[slot].set(Some(n));
            }

            pub fn clear_faults(&self) {
                self.faults.iter().for_each(|f| f.set(None));
            }

            fn should_fail(
                &self,
                operation: Operation,
                kind: storage::Kind,
            ) -> Result<(), storage::Error> {
                let slot = operation.slot(kind);
                let n = self.calls[slot].get() + 1;

                self.calls[slot].set(n);

                if self.faults[slot].get() == Some(n) {
                    return Err(storage::Error::Other(
                        format!("simulated storage failure for {:?} {:?}", operation, kind).into(),
                    ));
                }

                Ok(())
            }
        }

        impl<I: storage::Backend> storage::Backend for Storage<I> {
            fn put(&self, key: storage::Key, data: &[u8]) -> Result<(), storage::Error> {
                self.should_fail(Operation::Put, key.kind())?;
                self.inner.put(key, data)
            }

            fn get(&self, key: storage::Key) -> Result<Vec<u8>, storage::Error> {
                self.should_fail(Operation::Get, key.kind())?;
                self.inner.get(key)
            }

            fn exists(&self, key: storage::Key) -> Result<bool, storage::Error> {
                self.should_fail(Operation::Exists, key.kind())?;
                self.inner.exists(key)
            }

            fn delete(&self, key: storage::Key) -> Result<(), storage::Error> {
                self.should_fail(Operation::Delete, key.kind())?;
                self.inner.delete(key)
            }

            fn list(&self, kind: storage::Kind) -> Result<Vec<storage::Key>, storage::Error> {
                self.should_fail(Operation::List, kind)?;
                self.inner.list(kind)
            }
        }

        pub struct Reader<'a> {
            data: &'a [u8],
            position: usize,
            fail_after_bytes: Option<usize>,
        }

        impl<'a> Reader<'a> {
            pub fn new(data: &'a [u8]) -> Self {
                Self {
                    data,
                    position: 0,
                    fail_after_bytes: None,
                }
            }

            pub fn fail_after_bytes(mut self, fail_after_bytes: usize) -> Self {
                self.fail_after_bytes = Some(fail_after_bytes);

                self
            }
        }

        impl<'a> io::Read for Reader<'a> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if let Some(fail_after_bytes) = self.fail_after_bytes
                    && self.position >= fail_after_bytes
                {
                    return Err(io::Error::other("simulated I/O failure"));
                }

                let available = &self.data[self.position..];
                let mut max_bytes = available.len();

                if let Some(fail_after_bytes) = self.fail_after_bytes {
                    max_bytes = max_bytes.min(fail_after_bytes - self.position);
                }

                let n = buf.len().min(max_bytes);

                if n == 0 && !buf.is_empty() && self.fail_after_bytes.is_none() {
                    return Ok(0); // EOF
                }

                buf[..n].copy_from_slice(&available[..n]);

                self.position += n;

                Ok(n)
            }
        }

        pub struct Writer {
            written: Vec<u8>,
            fail_after_bytes: Option<usize>,
        }

        impl Writer {
            pub fn new() -> Self {
                Self {
                    written: Vec::new(),
                    fail_after_bytes: None,
                }
            }

            pub fn fail_after_bytes(mut self, fail_after_bytes: usize) -> Self {
                self.fail_after_bytes = Some(fail_after_bytes);

                self
            }
        }

        impl io::Write for Writer {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if let Some(fail_after_bytes) = self.fail_after_bytes {
                    if self.written.len() >= fail_after_bytes {
                        return Err(io::Error::other("simulated I/O failure"));
                    }

                    let max_bytes = fail_after_bytes - self.written.len();
                    let n = buf.len().min(max_bytes);

                    self.written.extend_from_slice(&buf[..n]);

                    return Ok(n);
                }

                self.written.extend_from_slice(buf);

                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                if let Some(fail_after_bytes) = self.fail_after_bytes
                    && self.written.len() >= fail_after_bytes
                {
                    return Err(io::Error::other("simulated I/O failure"));
                }

                Ok(())
            }
        }
    }

    fn temp_storage_path(name: &str) -> PathBuf {
        let nanos = time::current_nanos().unwrap();

        env::temp_dir().join(format!("vault_test_{}_{}", name, nanos))
    }

    fn make_words() -> Vec<String> {
        bip39::generate(12).unwrap()
    }

    fn make_identity(words: &[impl AsRef<str>]) -> Identity {
        Identity::from_mnemonic(words).unwrap()
    }

    fn vault() -> (Vault<local::Storage>, PathBuf, Vec<String>) {
        let path = temp_storage_path("");
        let words = make_words();
        let identity = make_identity(&words);
        let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();

        (Vault::open(identity, storage), path, words)
    }

    fn faulty_vault() -> (Vault<faulty::Storage<local::Storage>>, PathBuf, Vec<String>) {
        let path = temp_storage_path("faulty");
        let words = make_words();
        let identity = make_identity(&words);
        let inner = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
        let storage = faulty::Storage::new(inner);

        (Vault::open(identity, storage), path, words)
    }

    fn put_bytes<B: storage::Backend>(vault: &mut Vault<B>, path: &str, data: &[u8]) {
        vault.put(path, data, data.len() as u64).unwrap();
    }

    fn get_bytes<B: storage::Backend>(vault: &Vault<B>, path: &str) -> Vec<u8> {
        let mut buf = Vec::new();

        vault.get(path, &mut buf).unwrap();

        buf
    }

    // Only used for tests, blob storage is immutable
    fn overwrite_bytes(storage_path: &Path, public_signing_key: &[u8; 32], key: Key, data: &[u8]) {
        let user_hex: String = Index::address(public_signing_key)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let user_dir = storage_path
            .join(&user_hex[0..2])
            .join(&user_hex[2..4])
            .join(&user_hex[4..]);
        let path = match key {
            Key::Blob(address) => {
                let blob_hex: String = address.iter().map(|b| format!("{:02x}", b)).collect();

                user_dir
                    .join("blobs")
                    .join(&blob_hex[0..2])
                    .join(&blob_hex[2..4])
                    .join(&blob_hex[4..])
            }
            Key::Index(shard) => user_dir.join("index").join(format!("{:04x}", shard)),
        };
        let temp = path.with_extension("tmp");

        fs::write(&temp, data).unwrap();
        fs::rename(&temp, &path).unwrap();
    }

    // Finds a path that lands in the same index shard as `path`
    fn same_shard_path(path: &str, base: &str, index: &Index) -> String {
        let target = index.shard_of(path);
        let mut same = String::from(base);
        let mut i = 0;

        while index.shard_of(&same) != target {
            same = format!("{}{}", base, i);
            i += 1;
        }

        same
    }

    // Finds a path that lands in a different index shard than `path`
    fn other_shard_path(from_path: &str, base: &str, encryption_key: &[u8; 32]) -> String {
        let index = Index::new(encryption_key);
        let target = index.shard_of(from_path);
        let mut other = String::from(base);
        let mut i = 0;

        while index.shard_of(&other) == target {
            other = format!("{}{}", base, i);
            i += 1;
        }

        other
    }

    #[test]
    fn put_get_small_data_roundtrip() {
        let (mut vault, _path, _words) = vault();
        let data = b"small data";

        put_bytes(&mut vault, "notes/small.txt", data);

        assert_eq!(get_bytes(&vault, "notes/small.txt"), data);
    }

    #[test]
    fn put_get_large_data_roundtrip() {
        let (mut vault, _path, _words) = vault();
        let data = [
            vec![0xAAu8; CHUNK_SIZE],
            vec![0xBBu8; CHUNK_SIZE],
            vec![0xCCu8; CHUNK_SIZE / 2],
        ]
        .concat();

        put_bytes(&mut vault, "large", &data);

        let blobs = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(blobs, 3); // 3 data blobs
        assert_eq!(get_bytes(&vault, "large"), data);
    }

    #[test]
    fn per_user_per_chunk_deduplication() {
        let (mut vault, _path, _words) = vault();
        let data1 = [
            vec![0xAAu8; CHUNK_SIZE],
            vec![0xBBu8; CHUNK_SIZE],
            vec![0xCCu8; CHUNK_SIZE / 2],
        ]
        .concat();
        let data2 = [
            vec![0xAAu8; CHUNK_SIZE],
            vec![0xBBu8; CHUNK_SIZE],
            vec![0xCCu8; CHUNK_SIZE / 2],
            vec![0xDDu8; 32], // New different chunk
        ]
        .concat();

        put_bytes(&mut vault, "file1", &data1);

        let blobs_after_first = vault.storage.list(Kind::Blob).unwrap().len();

        put_bytes(&mut vault, "file2", &data2);

        let blobs_after_second = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(blobs_after_second, blobs_after_first + 1); // Only one new chunk
        assert_eq!(get_bytes(&vault, "file1"), data1);
        assert_eq!(get_bytes(&vault, "file2"), data2);
    }

    #[test]
    fn deduplicate_chunks() {
        let (mut vault, _path, _words) = vault();
        let data = [
            vec![0xAAu8; chunk::CHUNK_SIZE],
            vec![0xAAu8; chunk::CHUNK_SIZE],
            vec![0xBBu8; chunk::CHUNK_SIZE / 2],
        ]
        .concat();

        put_bytes(&mut vault, "large", &data);

        let blobs = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(blobs, 2); // The file has 3 blobs but 2 are identical
        assert_eq!(get_bytes(&vault, "large"), data);
    }

    #[test]
    fn put_get_empty_file_roundtrip() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "notes/empty.txt", b"");

        assert_eq!(get_bytes(&vault, "notes/empty.txt"), b"");
    }

    #[test]
    fn put_get_empty_string_path_roundtrips() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "", b"empty string path");

        assert_eq!(get_bytes(&vault, ""), b"empty string path");
    }

    #[test]
    fn path_that_looks_like_traversal_is_treated_as_an_opaque_string_not_a_filesystem_path() {
        let (mut vault, _path, _words) = vault();
        let path = "../../../etc/passwd";

        put_bytes(&mut vault, path, b"lol!");

        assert_eq!(get_bytes(&vault, path), b"lol!");
        assert!(vault.get("etc/passwd", &mut Vec::new()).is_err());
        assert!(vault.get("/etc/passwd", &mut Vec::new()).is_err());
    }

    #[test]
    fn very_long_path_name_is_handled_gracefully() {
        let (mut vault, _path, _words) = vault();
        let path = "x".repeat(60_000); // safely under u16::MAX (65535), still huge

        put_bytes(&mut vault, &path, b"data");

        assert_eq!(get_bytes(&vault, &path), b"data");
    }

    #[test]
    fn path_longer_than_u16_max_fails_gracefully_instead_of_panicking() {
        let (mut vault, _path, _words) = vault();
        let huge_path = "x".repeat(70_000); // exceeds the u16 path_len field in the shard format

        assert!(vault.put(&huge_path, &b"data"[..], 4).is_err());
    }

    #[test]
    fn put_same_content_on_trashed_path_restores_it() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"same content");

        vault.trash("file").unwrap();

        put_bytes(&mut vault, "file", b"same content");

        assert_eq!(vault.list().unwrap(), vec!["file"]);
    }

    #[test]
    fn put_different_content_on_trashed_path_restores_it() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"original");

        vault.trash("file").unwrap();

        put_bytes(&mut vault, "file", b"new content");

        assert_eq!(vault.list().unwrap(), vec!["file"]);
        assert_eq!(get_bytes(&vault, "file"), b"new content");
    }

    #[test]
    fn a_put_that_fails_to_flush_should_not_be_gettable_in_the_same_session() {
        let (mut vault, _path, _words) = faulty_vault();

        vault
            .storage
            .fail_nth(faulty::Operation::Put, Kind::Index, 1);

        assert!(vault.put("new_file", &b"content"[..], 7).is_err());
        assert!(
            vault.get("new_file", &mut Vec::new()).is_err(),
            "since `put()` failed, the file should not be visible via `get()`."
        )
    }

    #[test]
    fn failed_put_is_rolled_back() {
        let (mut vault, path, words) = faulty_vault();

        put_bytes(&mut vault, "a", b"first");

        vault
            .storage
            .fail_nth(faulty::Operation::Put, Kind::Index, 1);

        assert!(vault.put("a", &b"second"[..], 6).is_err());

        // Same vault session
        assert_eq!(
            get_bytes(&vault, "a"),
            b"first",
            "a failed `put()` should already be rolled back in the same vault session"
        );

        // Storage recovered
        vault.storage.clear_faults();

        // Touch a different shard to make sure nothing else touches "a" again. The failed write
        // doesn't complete on its own
        put_bytes(
            &mut vault,
            &other_shard_path("a", "another", &make_identity(&words).encryption_key()),
            b"something",
        );

        // Still the same vault session
        assert_eq!(
            get_bytes(&vault, "a"),
            b"first",
            "a failed put() should be fully rolled back, not silently completed later by an \
             unrelated flush"
        );

        let identity = make_identity(&words);
        let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
        let reopened = Vault::open(identity, storage);

        // Vault re-opened
        assert_eq!(get_bytes(&reopened, "a"), b"first",);
    }

    #[test]
    fn retrying_an_identical_put_after_a_failed_flush_in_the_same_session() {
        let (mut vault, path, words) = faulty_vault();

        vault
            .storage
            .fail_nth(faulty::Operation::Put, Kind::Index, 1);

        assert!(vault.put("file", &b"same content"[..], 12).is_err());

        // The failed put should already be fully rolled back, "file" never existed before this
        // call, so it shouldn't exist now either
        assert!(!vault.index.get_mut().contains("file"));
        assert!(vault.get("file", &mut Vec::new()).is_err());

        // The blob persisted correctly though, so the retry would only update the index
        assert_eq!(vault.storage.list(Kind::Blob).unwrap().len(), 1);

        vault.storage.clear_faults();

        assert!(
            vault.put("file", &b"same content"[..], 12).is_ok(),
            "the retry itself should not error"
        );
        assert!(vault.index.get_mut().contains("file"));

        // No new blob is added to the vault
        assert_eq!(vault.storage.list(Kind::Blob).unwrap().len(), 1);

        let identity = make_identity(&words);
        let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
        let reopened = Vault::open(identity, storage);

        assert!(
            reopened.get("file", &mut Vec::new()).is_ok(),
            "after a successful retry, the data must actually be durable on a fresh vault session"
        );
        assert_eq!(get_bytes(&vault, "file"), b"same content");
    }

    #[test]
    fn chunks_already_uploaded_before_a_failed_index_flush_are_not_re_uploaded_on_retry() {
        let (mut vault, _path, _words) = faulty_vault();
        let data = [vec![0xAAu8; CHUNK_SIZE], vec![0xBBu8; CHUNK_SIZE]].concat();

        vault
            .storage
            .fail_nth(faulty::Operation::Put, Kind::Index, 1);

        assert!(vault.put("file", &data[..], data.len() as u64).is_err());

        let blobs_after_failed_attempt = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(
            blobs_after_failed_attempt, 2,
            "the chunks should already be durably stored even though the index flush failed"
        );

        vault.storage.clear_faults();

        put_bytes(&mut vault, "file", &data);

        let blobs_after_retry = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(
            blobs_after_retry, 2,
            "retrying the put should reuse the already-uploaded chunk instead of duplicating it"
        );
    }

    #[test]
    fn put_surfaces_an_exists_check_failure_without_corrupting_index() {
        let (mut vault, _path, _words) = faulty_vault();
        let data = [vec![0xAAu8; CHUNK_SIZE], vec![0xBBu8; CHUNK_SIZE]].concat();

        // Fail the exists-check for the second chunk
        vault
            .storage
            .fail_nth(faulty::Operation::Exists, Kind::Blob, 2);

        assert!(vault.put("file", &data[..], data.len() as u64).is_err());

        // The entry is only inserted into the index after all chunks are collected, so the path
        // must not exist at all yet
        assert!(vault.get("file", &mut Vec::new()).is_err());

        // The first chunk should have been successfully uploaded
        assert_eq!(vault.storage.list(Kind::Blob).unwrap().len(), 1);

        vault.storage.clear_faults();

        put_bytes(&mut vault, "file", &data);

        assert_eq!(get_bytes(&vault, "file"), data);
    }

    #[test]
    fn put_with_reader_that_fails_partway_does_not_corrupt_existing_data() {
        let (mut vault, _path, _words) = vault();
        let data = b"original content";

        put_bytes(&mut vault, "file", data);

        assert_eq!(vault.storage.list(Kind::Blob).unwrap().len(), 1);

        let payload = vec![0x11u8; CHUNK_SIZE + 100]; // Two chunks

        // A reader that fails partway through the second chunk
        let reader = faulty::Reader::new(&payload).fail_after_bytes(CHUNK_SIZE + 10);

        assert!(vault.put("file", reader, payload.len() as u64).is_err());

        // Only one chunk managed to be uploaded successfully plus the one we already had
        assert_eq!(vault.storage.list(Kind::Blob).unwrap().len(), 2);

        // File should still be readable after a failed overwrite
        assert_eq!(get_bytes(&vault, "file"), data);
    }

    #[test]
    fn get_with_writer_that_fails_partway_is_error_and_leaves_storage_untouched() {
        let (mut vault, _path, _words) = vault();
        let data = vec![0x22u8; CHUNK_SIZE * 2];

        put_bytes(&mut vault, "file", &data);

        let blobs_before = vault.storage.list(Kind::Blob).unwrap().len();
        let mut writer = faulty::Writer::new().fail_after_bytes(CHUNK_SIZE);

        assert!(matches!(vault.get("file", &mut writer), Err(Error::Io(_))));

        let blobs_after = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(blobs_before, blobs_after);
        assert_eq!(get_bytes(&vault, "file"), data);
    }

    #[test]
    fn get_with_multi_chunk_file_storage_read_failure() {
        let (mut vault, _path, _words) = faulty_vault();

        let data = vec![0xABu8; CHUNK_SIZE * 2];

        put_bytes(&mut vault, "file", &data);

        vault
            .storage
            .fail_nth(faulty::Operation::Get, Kind::Blob, 2);

        assert!(vault.get("file", &mut Vec::new()).is_err());

        vault.storage.clear_faults();

        assert_eq!(get_bytes(&vault, "file"), data);
    }

    #[test]
    fn file_exactly_one_chunk_produces_exactly_one_chunk() {
        let (mut vault, _path, _words) = vault();
        let data = vec![0x11u8; CHUNK_SIZE];

        put_bytes(&mut vault, "exactly one", &data);

        assert_eq!(vault.storage.list(Kind::Blob).unwrap().len(), 1);
        assert_eq!(get_bytes(&vault, "exactly one"), data);
    }

    #[test]
    fn file_exactly_two_chunks_produces_exactly_two_chunks() {
        let (mut vault, _path, _words) = vault();
        let data = [vec![0x22u8; CHUNK_SIZE], vec![0x33u8; CHUNK_SIZE]].concat();

        put_bytes(&mut vault, "exactly two", &data);

        assert_eq!(vault.storage.list(Kind::Blob).unwrap().len(), 2);
        assert_eq!(get_bytes(&vault, "exactly two"), data);
    }

    #[test]
    fn file_one_byte_over_the_chunk_size_produces_two_chunks() {
        let (mut vault, _path, _words) = vault();
        let mut data = vec![0x44u8; CHUNK_SIZE];

        data.push(0x55);

        put_bytes(&mut vault, "over", &data);

        assert_eq!(vault.storage.list(Kind::Blob).unwrap().len(), 2);
        assert_eq!(get_bytes(&vault, "over"), data);
    }

    #[test]
    fn get_version() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"first");
        put_bytes(&mut vault, "file", b"second");
        put_bytes(&mut vault, "file", b"third");

        // Versions: [0 = "first", 1 = "second"], active = "third"
        let mut buf = Vec::new();

        vault.get_version("file", 0, &mut buf).unwrap();

        assert_eq!(buf, b"first");

        let mut buf = Vec::new();

        vault.get_version("file", 1, &mut buf).unwrap();

        assert_eq!(buf, b"second");
    }

    #[test]
    fn get_version_not_found() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"only one version");

        // No previous versions exist yet
        assert!(matches!(
            vault.get_version("file", 0, &mut Vec::new()),
            Err(Error::VersionNotFound)
        ));
    }

    #[test]
    fn overwrite() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"version one");
        put_bytes(&mut vault, "file", b"version two");

        // Data in path is overwritten, but the old version is kept until dropped
        assert_eq!(get_bytes(&vault, "file"), b"version two");
    }

    #[test]
    fn overwrite_creates_version() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"version one");
        put_bytes(&mut vault, "file", b"version two");

        // Active content is the latest
        assert_eq!(get_bytes(&vault, "file"), b"version two");

        // One previous version was created
        let versions = vault.versions("file").unwrap().unwrap();

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].size, b"version one".len() as u64);
    }

    #[test]
    fn overwrite_no_unreferenced_chunks() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"version one");

        let blobs_after_first = vault.storage.list(Kind::Blob).unwrap().len();

        put_bytes(&mut vault, "file", b"version two");

        let blobs_after_second = vault.storage.list(Kind::Blob).unwrap().len();

        // A new chunk was added, nothing was removed
        assert!(blobs_after_second > blobs_after_first);
        assert_eq!(blobs_after_second, blobs_after_first + 1);
    }

    #[test]
    fn overwrite_same_content_no_new_chunks() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"same content");

        let blobs_after_first = vault.storage.list(Kind::Blob).unwrap().len();

        put_bytes(&mut vault, "file", b"same content");

        let blobs_after_second = vault.storage.list(Kind::Blob).unwrap().len();

        // Identical content, no new chunk written
        assert_eq!(blobs_after_first, blobs_after_second);

        // No-op, no new version recorded
        assert_eq!(vault.versions("file").unwrap().unwrap().len(), 0);
    }

    #[test]
    fn multiple_overwrites_accumulate_versions() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");
        put_bytes(&mut vault, "file", b"v3");

        assert_eq!(get_bytes(&vault, "file"), b"v3");
        assert_eq!(vault.versions("file").unwrap().unwrap().len(), 2);
    }

    #[test]
    fn revert() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"original");
        put_bytes(&mut vault, "file", b"overwritten");

        // Revert to version index 0 ("original")
        vault.revert("file", 0).unwrap();

        assert_eq!(get_bytes(&vault, "file"), b"original");
    }

    #[test]
    fn revert_preserves_full_history() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        // Before revert: versions = ["v1"], active = "v2"
        vault.revert("file", 0).unwrap();

        // After revert: active = "v1", versions = ["v2"]
        assert_eq!(get_bytes(&vault, "file"), b"v1");

        let versions = vault.versions("file").unwrap().unwrap();

        assert_eq!(versions.len(), 1);

        let mut buf = Vec::new();

        vault.get_version("file", 0, &mut buf).unwrap();

        assert_eq!(buf, b"v2");
    }

    #[test]
    fn revert_version_not_found() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"data");

        assert!(matches!(
            vault.revert("file", 0),
            Err(Error::VersionNotFound)
        ));
    }

    #[test]
    fn drop_version() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"old content");
        put_bytes(&mut vault, "file", b"new content");

        let blobs_before = vault.storage.list(Kind::Blob).unwrap().len();

        vault.drop_version("file", 0).unwrap();

        let blobs_after = vault.storage.list(Kind::Blob).unwrap().len();

        // One chunk purged (the "old content" chunk)
        assert!(blobs_after < blobs_before);
        assert_eq!(vault.versions("file").unwrap().unwrap().len(), 0);
        assert_eq!(get_bytes(&vault, "file"), b"new content");
    }

    #[test]
    fn drop_version_skips_shared_chunks() {
        let (mut vault, _path, _words) = vault();

        put_bytes(
            &mut vault,
            "file",
            &[vec![0xAAu8; CHUNK_SIZE], vec![0xBBu8; CHUNK_SIZE]].concat(),
        );

        // Overwrite to create version
        put_bytes(&mut vault, "file", &vec![0xBBu8; CHUNK_SIZE]);

        let blobs_before = vault.storage.list(Kind::Blob).unwrap().len();

        vault.drop_version("file", 0).unwrap();

        let blobs_after = vault.storage.list(Kind::Blob).unwrap().len();

        // A Chunk is shared with the active version, must not be deleted
        // Only one chunk is purged (the unshared one)
        assert!(blobs_after < blobs_before);
        assert_eq!(get_bytes(&vault, "file"), vec![0xBBu8; CHUNK_SIZE]);
    }

    #[test]
    fn drop_version_skips_shared_chunks_across_files() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file1", &vec![0xAAu8; CHUNK_SIZE]);
        put_bytes(
            &mut vault,
            "file2",
            &[vec![0xAAu8; CHUNK_SIZE], vec![0xBBu8; CHUNK_SIZE]].concat(),
        );

        // Overwrite file1 to create version
        put_bytes(&mut vault, "file1", &vec![0xCCu8; CHUNK_SIZE]);

        let blobs_before = vault.storage.list(Kind::Blob).unwrap().len();

        vault.drop_version("file1", 0).unwrap();

        let blobs_after = vault.storage.list(Kind::Blob).unwrap().len();

        // Chunk is shared with the active version, must not be deleted
        assert_eq!(blobs_before, blobs_after);
        assert_eq!(get_bytes(&vault, "file1"), vec![0xCCu8; CHUNK_SIZE]);
    }

    #[test]
    fn drop_version_current_skips_chunks_shared_with_its_own_new_active_version_when_trashed() {
        let (mut vault, _path, _words) = vault();

        let chunk_a = vec![0xAAu8; CHUNK_SIZE];
        let chunk_b = vec![0xBBu8; CHUNK_SIZE];
        let chunk_c = vec![0xCCu8; CHUNK_SIZE];

        // v1 = [A, B]
        put_bytes(
            &mut vault,
            "file",
            &[chunk_a.clone(), chunk_b.clone()].concat(),
        );
        // v2 = [A, C] (active), v1 = [A, B] (history), chunk A is shared between the two
        put_bytes(&mut vault, "file", &[chunk_a.clone(), chunk_c].concat());

        vault.trash("file").unwrap();

        // Drops active v2 = [A, C], falling back to v1 = [A, B]. Chunk "A" must survive since it's
        // shared with the version becoming active.
        vault.drop_version_current("file").unwrap();
        vault.restore("file").unwrap();

        assert_eq!(get_bytes(&vault, "file"), [chunk_a, chunk_b].concat());
    }

    #[test]
    fn drop_version_not_found() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"data");

        assert!(matches!(
            vault.drop_version("file", 0),
            Err(Error::VersionNotFound)
        ));
    }

    #[test]
    fn drop_version_that_fails_to_flush_index_does_not_touch_blobs() {
        let (mut vault, _path, _words) = faulty_vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        let blobs_before = vault.storage.list(Kind::Blob).unwrap().len();

        vault
            .storage
            .fail_nth(faulty::Operation::Put, Kind::Index, 1);

        assert!(vault.drop_version("file", 0).is_err());

        let blobs_after = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(
            blobs_before, blobs_after,
            "if the index flush failed, the (possibly still-referenced) blobs must not have been \
             deleted"
        );
    }

    #[test]
    fn drop_current() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        let blobs_before = vault.storage.list(Kind::Blob).unwrap().len();

        vault.drop_version_current("file").unwrap();

        let blobs_after = vault.storage.list(Kind::Blob).unwrap().len();

        // v2 chunk was purged
        assert!(blobs_after < blobs_before);

        // v1 is now active
        assert_eq!(get_bytes(&vault, "file"), b"v1");
        assert_eq!(vault.versions("file").unwrap().unwrap().len(), 0);
    }

    #[test]
    fn drop_current_no_versions_deletes_file() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"data");

        vault.drop_version_current("file").unwrap();

        assert!(matches!(
            vault.get("file", &mut Vec::new()),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn detach_version() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"original");
        put_bytes(&mut vault, "file", b"accidentally overwritten");

        vault.detach_version("file", "original", 0).unwrap();

        assert_eq!(get_bytes(&vault, "original"), b"original");
        assert_eq!(get_bytes(&vault, "file"), b"accidentally overwritten");
    }

    #[test]
    fn detach_version_rejects_existing_new_path() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");
        put_bytes(&mut vault, "other", b"already here");

        assert!(matches!(
            vault.detach_version("file", "other", 0),
            Err(Error::AlreadyExists)
        ));
        assert_eq!(vault.versions("file").unwrap().unwrap().len(), 1);
    }

    #[test]
    fn detach_version_new_path_equal_to_source_is_already_exists() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        assert!(matches!(
            vault.detach_version("file", "file", 0),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn detach_version_removes_from_source_history() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        vault.detach_version("file", "file_v1", 0).unwrap();

        // Version was removed from source
        assert_eq!(vault.versions("file").unwrap().unwrap().len(), 0);

        // Detached entry has no history of its own
        assert_eq!(vault.versions("file_v1").unwrap().unwrap().len(), 0);

        // Both paths are independently readable
        assert_eq!(get_bytes(&vault, "file"), b"v2");
        assert_eq!(get_bytes(&vault, "file_v1"), b"v1");
    }

    #[test]
    fn detach_version_no_chunk_duplication() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"shared data");
        put_bytes(&mut vault, "file", b"other data");

        let blobs_before = vault.storage.list(Kind::Blob).unwrap().len();

        // Detach just references existing chunks, no new blobs written
        vault.detach_version("file", "detached", 0).unwrap();

        let blobs_after = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(blobs_before, blobs_after);
    }

    #[test]
    fn detach_version_not_found() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"data");

        assert!(matches!(
            vault.detach_version("file", "new", 0),
            Err(Error::VersionNotFound)
        ));
    }

    #[test]
    fn detach_current() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        vault.detach_version_current("file", "file_v2").unwrap();

        assert_eq!(get_bytes(&vault, "file_v2"), b"v2");
        assert_eq!(get_bytes(&vault, "file"), b"v1");
        assert_eq!(vault.versions("file").unwrap().unwrap().len(), 0);
        assert_eq!(vault.versions("file_v2").unwrap().unwrap().len(), 0);
    }

    #[test]
    fn detach_current_no_versions_is_rename() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"data");

        vault.detach_version_current("file", "renamed").unwrap();

        assert_eq!(get_bytes(&vault, "renamed"), b"data");
        assert!(matches!(
            vault.get("file", &mut Vec::new()),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn detach_current_no_versions_restores_trashed_at_new_path() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"data");

        vault.trash("file").unwrap();
        vault.detach_version_current("file", "renamed").unwrap();

        assert_eq!(vault.list().unwrap(), &["renamed"]);
        assert_eq!(get_bytes(&vault, "renamed"), b"data");
    }

    #[test]
    fn detach_current_rejects_existing_new_path() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");
        put_bytes(&mut vault, "other", b"already here");

        assert!(matches!(
            vault.detach_version_current("file", "other"),
            Err(Error::AlreadyExists)
        ));
        assert_eq!(get_bytes(&vault, "file"), b"v2");
    }

    #[test]
    fn detach_current_new_path_equal_to_source_is_already_exists() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        assert!(matches!(
            vault.detach_version_current("file", "file"),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn rename() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "old/file", b"data");

        vault.rename("old/file", "new/file").unwrap();

        assert_eq!(get_bytes(&vault, "new/file"), b"data");
    }

    #[test]
    fn rename_trashed_is_ok_and_keeps_it_trashed() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "a", b"data");

        vault.trash("a").unwrap();

        assert!(vault.rename("a", "b").is_ok());
        assert!(vault.list_trash().unwrap().contains(&"b".to_string()));
        assert!(vault.get("b", &mut Vec::new()).is_err());
    }

    #[test]
    fn rename_rejects_existing_new_path() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "a", b"a data");
        put_bytes(&mut vault, "b", b"b data");

        assert!(matches!(vault.rename("a", "b"), Err(Error::AlreadyExists)));
        assert_eq!(get_bytes(&vault, "a"), b"a data");
        assert_eq!(get_bytes(&vault, "b"), b"b data");
    }

    #[test]
    fn rename_to_the_same_path_is_a_no_op() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"data");

        assert!(vault.rename("file", "file").is_ok());
        assert_eq!(get_bytes(&vault, "file"), b"data");
    }

    #[test]
    fn rename_to_a_trashed_path_is_already_exists() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "a", b"data a");
        put_bytes(&mut vault, "b", b"data b");

        vault.trash("b").unwrap();

        // Expected behavior
        assert!(matches!(vault.rename("a", "b"), Err(Error::AlreadyExists)));
    }

    #[test]
    fn rename_across_shards_partial_flush_failure_should_not_lose_the_file() {
        let (mut vault, path, words) = faulty_vault();

        let old_path = "old/file";
        let new_path = other_shard_path(
            old_path,
            "new/file",
            &make_identity(&words).encryption_key(),
        );

        put_bytes(&mut vault, old_path, b"data");

        // `rename` marks two shards dirty, if the "moved from shard" becomes empty (delete),
        // and the "moved to shard" is created (put), fail the put
        vault
            .storage
            .fail_nth(faulty::Operation::Put, Kind::Index, 1);

        assert!(vault.rename(old_path, &new_path).is_err());

        assert!(vault.get(old_path, &mut Vec::new()).is_ok());
        assert!(vault.get(&new_path, &mut Vec::new()).is_err());

        let identity = make_identity(&words);
        let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
        let reopened = Vault::open(identity, storage);

        let old_survived = reopened.get(old_path, &mut Vec::new()).is_ok();
        let new_survived = reopened.get(&new_path, &mut Vec::new()).is_ok();

        assert!(
            old_survived || new_survived,
            "the file must survive a failed rename under some name (most likely the `old_path`) \
             after reopening the vault; instead it vanished from both `{}` and `{}`",
            old_path,
            new_path
        );
    }

    #[test]
    fn trash() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file.txt", b"data");

        vault.trash("file.txt").unwrap();

        assert!(vault.list().unwrap().is_empty());
        assert!(!vault.storage.list(Kind::Blob).unwrap().is_empty());
        assert_eq!(vault.list_trash().unwrap(), vec!["file.txt"]);
    }

    #[test]
    fn restore() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file.txt", b"data");

        vault.trash("file.txt").unwrap();
        vault.restore("file.txt").unwrap();

        assert_eq!(get_bytes(&vault, "file.txt"), b"data");
        assert!(vault.list_trash().unwrap().is_empty());
    }

    #[test]
    fn repeated_trash_and_restore_via_put_stays_consistent() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"same data");

        for _ in 0..3 {
            vault.trash("file").unwrap();

            assert!(vault.get("file", &mut Vec::new()).is_err());

            // Same path and content restores the file
            put_bytes(&mut vault, "file", b"same data");

            assert_eq!(get_bytes(&vault, "file"), b"same data");
        }

        // No versions are added because the put calls were just no-op restores
        assert_eq!(vault.versions("file").unwrap().unwrap().len(), 0);
    }

    #[test]
    fn purge() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "1.txt", b"keep this");
        put_bytes(&mut vault, "2.txt", b"delete this");

        vault.trash("2.txt").unwrap();

        let blobs_before_purge = vault.storage.list(Kind::Blob).unwrap().len();

        vault.purge("2.txt").unwrap();

        assert!(vault.list_trash().unwrap().is_empty());
        assert!(vault.storage.list(Kind::Blob).unwrap().len() < blobs_before_purge);
        assert_eq!(get_bytes(&vault, "1.txt"), b"keep this");
    }

    #[test]
    fn purge_skips_chunks_still_used_by_a_trashed_entry() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "a", b"shared content");
        put_bytes(&mut vault, "b", b"shared content"); // Share the same chunk as "a"

        vault.trash("a").unwrap();
        vault.trash("b").unwrap();

        vault.purge("a").unwrap();
        vault.restore("b").unwrap();

        assert_eq!(get_bytes(&vault, "b"), b"shared content");
    }

    #[test]
    fn purge_that_fails_to_flush_index_does_not_touch_blobs() {
        let (mut vault, _path, _words) = faulty_vault();

        put_bytes(&mut vault, "file", b"data");

        vault.trash("file").unwrap();

        let blobs_before = vault.storage.list(Kind::Blob).unwrap().len();

        // Here we do `Delete` beucase there is only the one entry and purging it causes its shard
        // to be deleted, not put/overwrite
        vault
            .storage
            .fail_nth(faulty::Operation::Delete, Kind::Index, 1);

        assert!(vault.purge("file").is_err());

        let blobs_after = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(
            blobs_before, blobs_after,
            "if the index flush failed, the blobs must remain untouched"
        );
    }

    #[test]
    fn purge_blob_delete_failure_after_successful_flush_still_leaves_the_index_consistent() {
        let (mut vault, path, words) = faulty_vault();

        put_bytes(&mut vault, "file", b"data");

        vault.trash("file").unwrap();

        vault
            .storage
            .fail_nth(faulty::Operation::Delete, Kind::Blob, 1);

        assert!(vault.purge("file").is_err());

        // The index itself should already have been flushed successfully, so the entry should be
        // gone even though the underlying blob is now unreferenced
        let identity = make_identity(&words);
        let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
        let reopened = Vault::open(identity, storage);

        // The blob still exists in the storage though it's unreferenced
        assert_eq!(reopened.storage.list(Kind::Blob).unwrap().len(), 1);
        assert!(reopened.list_trash().unwrap().is_empty());
        assert!(reopened.get("file", &mut Vec::new()).is_err());
    }

    #[test]
    fn purge_all_version_chunks() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file1", b"keep this");
        put_bytes(&mut vault, "file2", b"delete v1");
        put_bytes(&mut vault, "file2", b"delete v2");

        vault.trash("file2").unwrap();

        let blobs_before = vault.storage.list(Kind::Blob).unwrap().len();

        vault.purge("file2").unwrap();

        let blobs_after = vault.storage.list(Kind::Blob).unwrap().len();

        // Both v1 and v2 chunks of file2 should be purged
        assert_eq!(blobs_before, blobs_after + 2);
        assert_eq!(get_bytes(&vault, "file1"), b"keep this");
    }

    #[test]
    fn cleanup() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "1.txt", b"data 1");
        put_bytes(&mut vault, "2.txt", b"data 2");

        vault.trash("1.txt").unwrap();
        vault.trash("2.txt").unwrap();

        let removed = vault.cleanup().unwrap();

        assert_eq!(removed, 2); // 1 chunk each
        assert!(vault.list_trash().unwrap().is_empty());
        assert!(vault.list().unwrap().is_empty());
    }

    #[test]
    fn cleanup_purges_all_version_chunks() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");
        put_bytes(&mut vault, "file", b"v3");

        vault.trash("file").unwrap();

        vault.cleanup().unwrap();

        assert_eq!(vault.storage.list(Kind::Blob).unwrap().len(), 0);
        assert!(vault.list().unwrap().is_empty());
    }

    #[test]
    fn cleanup_stops_deleting_blobs_on_first_failure_leaving_the_rest_unreferenced() {
        let (mut vault, _path, _words) = faulty_vault();

        put_bytes(&mut vault, "a", b"aaaa");
        put_bytes(&mut vault, "b", b"bbbb");

        vault.trash("a").unwrap();
        vault.trash("b").unwrap();

        let blobs_before = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(blobs_before, 2);

        vault
            .storage
            .fail_nth(faulty::Operation::Delete, Kind::Blob, 1);

        assert!(vault.cleanup().is_err());

        // Index side is already durable (flushed before any deletion attempt).
        assert!(vault.list_trash().unwrap().is_empty());

        let blobs_after = vault.storage.list(Kind::Blob).unwrap().len();

        // At least one blob should have failed to delete and been left behind; this is a harmless
        // storage leak (the index no longer points at it)
        assert!(
            blobs_after >= 1,
            "expected at least one unreferenced blob left behind after the injected delete failure"
        );
    }

    #[test]
    fn delete() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file.txt", b"data");

        vault.delete("file.txt").unwrap();

        assert!(vault.list_trash().unwrap().is_empty());

        // file is permanently removed and cannot be restored
        assert!(vault.restore("file.txt").is_err());
    }

    #[test]
    fn delete_a_trashed_entry_is_ok() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file.txt", b"data");

        vault.trash("file.txt").unwrap();
        // This shouldn't return `Error::AlreadyTrashed`
        vault.delete("file.txt").unwrap();

        assert!(vault.list_trash().unwrap().is_empty());

        // file is permanently removed and cannot be restored
        assert!(vault.restore("file.txt").is_err());
    }

    #[test]
    fn only_uploads_changed_chunks() {
        let (mut vault, _path, _words) = vault();

        let chunk_a = vec![0xAAu8; CHUNK_SIZE];
        let chunk_b = vec![0xBBu8; CHUNK_SIZE];
        let original: Vec<u8> = [chunk_a.clone(), chunk_b].concat();

        put_bytes(&mut vault, "file", &original);

        let blobs_after_first = vault.storage.list(Kind::Blob).unwrap().len();

        // Since `chunk_a` is identical, it should not be re-uploaded
        let chunk_b2 = vec![0xCCu8; CHUNK_SIZE];
        let updated: Vec<u8> = [chunk_a, chunk_b2].concat();

        put_bytes(&mut vault, "file", &updated);

        let blobs_after_second = vault.storage.list(Kind::Blob).unwrap().len();

        // `chunk_a` already exists, therefore it's skipped and we'd only have 1 new blob
        assert_eq!(blobs_after_second, blobs_after_first + 1);
    }

    #[test]
    fn not_found() {
        let (vault, _path, _words) = vault();
        let got = vault.get("nonexistent.txt", &mut Vec::new());

        assert!(matches!(got, Err(Error::NotFound)));
    }

    #[test]
    fn delete_not_found() {
        let (mut vault, _path, _words) = vault();
        let deleted = vault.delete("nonexistent.txt");

        assert!(matches!(deleted, Err(Error::NotFound)));
    }

    #[test]
    fn persistent_data_across_vault_opens() {
        let path = temp_storage_path("persistent");
        let words = make_words();

        {
            let identity = make_identity(&words);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage);

            put_bytes(&mut vault, "persistant.txt", b"persistent data");
        }

        {
            let identity = make_identity(&words);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage);

            assert_eq!(get_bytes(&vault, "persistant.txt"), b"persistent data");
        }
    }

    #[test]
    fn accessing_one_path_does_not_load_an_unrelated_shard() {
        let path = temp_storage_path("unrelated_shard");
        let words = make_words();
        let identity = make_identity(&words);
        let index = Index::new(&identity.encryption_key());

        let shard_a = index.shard_of("a");
        let other_path = other_shard_path("a", "b", &make_identity(&words).encryption_key());

        {
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage);

            put_bytes(&mut vault, "a", b"a data");
            put_bytes(&mut vault, &other_path, b"other data");
        }

        let identity = make_identity(&words);
        let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
        let reopened = Vault::open(identity, storage);

        // Fresh session, nothing loaded yet
        assert!(!reopened.index.borrow().is_loaded(shard_a));
        assert!(
            !reopened
                .index
                .borrow()
                .is_loaded(index.shard_of(&other_path))
        );

        assert_eq!(get_bytes(&reopened, "a"), b"a data");

        // Only "a"'s shard got loaded; the other path's shard is untouched
        assert!(reopened.index.borrow().is_loaded(shard_a));
        assert!(
            !reopened
                .index
                .borrow()
                .is_loaded(index.shard_of(&other_path))
        );
    }

    #[test]
    fn only_dirty_shard_is_rewritten() {
        let (mut vault, _path, words) = vault();
        let key = make_identity(&words).encryption_key();
        let index = Index::new(&key);

        put_bytes(&mut vault, "a", b"a data");

        let shard_a = index.shard_of("a");
        let other_path = other_shard_path("a", "b", &key);

        put_bytes(&mut vault, &other_path, b"other data");

        let blob_a_before = vault.storage.get(Key::Index(shard_a)).unwrap();

        put_bytes(&mut vault, &other_path, b"updated other data"); // Only touches its own shard

        let blob_a_after = vault.storage.get(Key::Index(shard_a)).unwrap();

        // "a"'s shard was never marked dirty on the second put
        assert_eq!(blob_a_before, blob_a_after);
        assert_eq!(get_bytes(&vault, &other_path), b"updated other data");
    }

    #[test]
    fn empty_shard_is_deleted_from_storage() {
        let (mut vault, _path, words) = vault();
        let key = make_identity(&words).encryption_key();
        let index = Index::new(&key);

        put_bytes(&mut vault, "solo", b"only entry");

        let shard = index.shard_of("solo");

        assert!(vault.storage.exists(Key::Index(shard)).unwrap());

        vault.delete("solo").unwrap();

        // No entries left in that shard, so its blob should be removed entirely rather than kept
        // around as an empty encrypted shell
        assert!(!vault.storage.exists(Key::Index(shard)).unwrap());
    }

    #[test]
    fn shard_is_not_deleted_when_it_still_contains_other_entries() {
        let (mut vault, _path, words) = vault();
        let key = make_identity(&words).encryption_key();
        let index = Index::new(&key);

        put_bytes(&mut vault, "a", b"data a");

        let file2 = same_shard_path("a", "b", &index);

        put_bytes(&mut vault, &file2, b"data b");

        let shard = index.shard_of("a");

        assert_eq!(shard, index.shard_of(&file2));
        assert!(vault.storage.exists(Key::Index(shard)).unwrap());

        vault.delete("a").unwrap();

        // The shard still contains `b`, so its underlying blob must not be deleted
        assert!(vault.storage.exists(Key::Index(shard)).unwrap());
        assert_eq!(get_bytes(&vault, &file2), b"data b");

        vault.delete(&file2).unwrap();

        assert!(!vault.storage.exists(Key::Index(shard)).unwrap());
    }

    #[test]
    fn rename_within_the_same_shard_preserves_data() {
        let (mut vault, _path, words) = vault();
        let key = make_identity(&words).encryption_key();
        let index = Index::new(&key);

        put_bytes(&mut vault, "old_name", b"data");

        let other = same_shard_path("old_name", "other", &index);

        put_bytes(&mut vault, &other, b"other data");

        let new_name = same_shard_path("old_name", "new_name", &index);

        vault.rename("old_name", &new_name).unwrap();

        assert!(vault.get("old_name", &mut Vec::new()).is_err());
        assert_eq!(get_bytes(&vault, &new_name), b"data");

        // The other in the same shard must remain intact
        assert_eq!(get_bytes(&vault, &other), b"other data");
    }

    #[test]
    fn failed_delete_in_shared_shard_leaves_other_entries_intact() {
        let (mut vault, path, words) = faulty_vault();
        let key = make_identity(&words).encryption_key();
        let index = Index::new(&key);

        put_bytes(&mut vault, "a", b"data 1");

        let b = same_shard_path("a", "b", &index);

        put_bytes(&mut vault, &b, b"data 2");

        // Deleting `a` requires a `Put` to rewrite the shard (since `b` keeps it alive).
        // We force that rewrite to fail
        vault
            .storage
            .fail_nth(faulty::Operation::Put, Kind::Index, 1);

        assert!(vault.delete("a").is_err());

        // The in-memory index should roll back. Both files should still be accessible.
        assert_eq!(get_bytes(&vault, "a"), b"data 1");
        assert_eq!(get_bytes(&vault, &b), b"data 2");

        // Verify persistence after reopening
        let identity = make_identity(&words);
        let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
        let reopened = Vault::open(identity, storage);

        assert_eq!(get_bytes(&reopened, "a"), b"data 1");
        assert_eq!(get_bytes(&reopened, &b), b"data 2");
    }

    #[test]
    fn verify_clean_file() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "clean", b"all good, mate!");

        assert!(vault.verify("clean").is_ok());
    }

    #[test]
    fn verify_nonexistent_path_is_not_found() {
        let (vault, _path, _words) = vault();

        assert!(matches!(vault.verify("nonexistent"), Err(Error::NotFound)));
    }

    #[test]
    fn verify_detects_tampering() {
        let path = temp_storage_path("verify_active_tamper");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut vault = Vault::open(identity, storage);

        put_bytes(&mut vault, "file", b"trust me");

        let address = {
            let index = vault.index.borrow();

            index.entry("file").unwrap().chunks[0].address
        };
        let mut blob = vault.storage.get(Key::Blob(address)).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, Key::Blob(address), &blob);

        assert!(matches!(vault.verify("file"), Err(Error::Tampered(_))));
    }

    #[test]
    fn verify_detects_tampering_in_a_version() {
        let path = temp_storage_path("verify_version_tamper");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut vault = Vault::open(identity, storage);

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        let address = {
            let index = vault.index.borrow();

            index.entry("file").unwrap().versions[0].chunks[0].address
        };
        let mut blob = vault.storage.get(Key::Blob(address)).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, Key::Blob(address), &blob);

        assert!(matches!(vault.verify("file"), Err(Error::Tampered(_))));
    }

    #[test]
    fn verify_includes_trashed_entries() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"data");

        vault.trash("file").unwrap();

        // Should still verify the trashed entry rather than reporting NotFound
        assert!(vault.verify("file").is_ok());
    }

    #[test]
    fn verify_a_dangling_chunk_reference_is_reported_as_tampered_not_not_found() {
        let (mut vault, _path, _words) = vault();
        let data = [
            vec![0xAAu8; CHUNK_SIZE],
            vec![0xBBu8; CHUNK_SIZE],
            vec![0xCCu8; CHUNK_SIZE],
        ]
        .concat();

        put_bytes(&mut vault, "file", &data);

        let address = {
            let index = vault.index.borrow();

            index.entry("file").unwrap().chunks[0].address
        };

        vault.storage.delete(Key::Blob(address)).unwrap();

        assert!(matches!(vault.verify("file"), Err(Error::Tampered(_))));

        // A genuinely nonexistent path is still reported distinctly
        assert!(matches!(vault.verify("nonexistent"), Err(Error::NotFound)));
    }

    #[test]
    fn verify_all() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file1", b"clean data");
        put_bytes(&mut vault, "file2", b"more clean data");

        assert!(vault.verify_all().is_empty());
    }

    #[test]
    fn verify_all_empty_vault() {
        let (vault, _path, _words) = vault();

        assert!(vault.verify_all().is_empty());
    }

    #[test]
    fn verify_all_tampered_chunk() {
        let path = temp_storage_path("verify_all_tampered_chunk");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut vault = Vault::open(identity, storage);

        put_bytes(&mut vault, "file", b"important data");

        let address = {
            let index = vault.index.borrow();

            index.entry("file").unwrap().chunks[0].address
        };
        let mut blob = vault.storage.get(Key::Blob(address)).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, Key::Blob(address), &blob);

        let tampared = vault.verify_all();

        assert!(tampared.contains(&"file".into()));
    }

    #[test]
    fn verify_all_tampered_index_shard() {
        let path = temp_storage_path("verify_all_tampered_index_shard");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let index = Index::new(&identity.encryption_key());
        let mut vault = Vault::open(identity, storage);

        put_bytes(&mut vault, "file", b"important data");

        let shard = index.shard_of("file");

        // The shard is already cached in memory from the `put` above; `verify_all` must still
        // catch tampering of the on-disk copy rather than trusting the cache.
        assert!(vault.index.borrow().is_loaded(shard));

        let mut blob = vault.storage.get(Key::Index(shard)).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, Key::Index(shard), &blob);

        let tampered = vault.verify_all();

        assert!(tampered.iter().any(|t| t.contains("index shard")));
    }

    #[test]
    fn verify_all_tampered_error() {
        let path = temp_storage_path("verify_all_tampered_error");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut vault = Vault::open(identity, storage);

        put_bytes(&mut vault, "secret.txt", b"secret");

        let address = {
            let index = vault.index.borrow();

            index.entry("secret.txt").unwrap().chunks[0].address
        };
        let mut blob = vault.storage.get(Key::Blob(address)).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, Key::Blob(address), &blob);

        assert!(matches!(
            vault.get("secret.txt", &mut Vec::new()),
            Err(Error::Tampered(_))
        ));
    }

    #[test]
    fn verify_all_includes_trashed_entries() {
        let path = temp_storage_path("verify_trashed");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut vault = Vault::open(identity, storage);

        put_bytes(&mut vault, "trashed.txt", b"will be trashed");

        vault.trash("trashed.txt").unwrap();

        // Corrupt the trashed chunk
        let address = {
            let index = vault.index.borrow();

            index.entry("trashed.txt").unwrap().chunks[0].address
        };
        let mut blob = vault.storage.get(Key::Blob(address)).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, Key::Blob(address), &blob);

        let tampared = vault.verify_all();

        assert!(tampared.contains(&"trashed.txt".into()));
    }

    #[test]
    fn verify_all_deduplicates_multi_chunk_path() {
        let path = temp_storage_path("verify_dedup");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut vault = Vault::open(identity, storage);
        let data = [vec![0xAAu8; CHUNK_SIZE], vec![0xBBu8; CHUNK_SIZE]].concat();

        put_bytes(&mut vault, "large", &data);

        // Corrupt both chunks
        let addresses: Vec<[u8; 32]> = {
            let index = vault.index.borrow();

            index
                .entry("large")
                .unwrap()
                .chunks
                .iter()
                .map(|c| c.address)
                .collect()
        };

        for address in addresses {
            let mut blob = vault.storage.get(Key::Blob(address)).unwrap();

            blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

            overwrite_bytes(&path, &public_signing_key, Key::Blob(address), &blob);
        }

        let tampared = vault.verify_all();

        // Path should appear exactly once despite two tampared chunks
        assert_eq!(tampared.iter().filter(|p| p.as_str() == "large").count(), 1);
    }

    #[test]
    fn verify_all_shared_tampered_chunk() {
        let path = temp_storage_path("verify_shared_tampered");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut vault = Vault::open(identity, storage);

        put_bytes(&mut vault, "file1", b"shared content");
        put_bytes(&mut vault, "file2", b"shared content");

        let address = {
            let index = vault.index.borrow();

            index.entry("file1").unwrap().chunks[0].address
        };
        let mut blob = vault.storage.get(Key::Blob(address)).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, Key::Blob(address), &blob);

        let tampared = vault.verify_all();

        assert!(tampared.contains(&"file1".into()));
        assert!(tampared.contains(&"file2".into()));
    }

    #[test]
    fn verify_all_catches_tampered_version() {
        let path = temp_storage_path("verify_all_catches_tampered_version");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut vault = Vault::open(identity, storage);

        put_bytes(&mut vault, "file", b"v0");
        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        // Corrupt the v1 (previous version) chunk
        let address = {
            let index = vault.index.borrow();

            index.entry("file").unwrap().versions[0].chunks[0].address // Version 1
        };
        let mut blob = vault.storage.get(Key::Blob(address)).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, Key::Blob(address), &blob);

        let tampered = vault.verify_all();

        assert_eq!(tampered, vec!["file@v1".to_string()]);
        assert!(tampered.contains(&"file@v1".into()));
    }

    #[test]
    fn swapping_a_chunk_address_to_point_at_a_different_real_blob_fails_decryption_rather_than_silently_returning_wrong_data()
     {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "a", b"data a");
        put_bytes(&mut vault, "b", b"data b");

        let address_b = {
            let index = vault.index.borrow();

            index.entry("b").unwrap().chunks[0].address
        };

        {
            let mut index = vault.index.borrow_mut();

            index.entry_mut("a").unwrap().chunks[0].address = address_b;
        }

        let result = vault.get("a", &mut Vec::new());

        assert!(
            matches!(result, Err(Error::Cipher(_))),
            "reading through a swapped chunk address must fail loudly via AEAD/signature \
             verification, not silently return the wrong file's bytes; got {:?}",
            result
        );
    }

    #[test]
    fn corrupting_the_encrypted_chunk_key_fails_decryption_cleanly() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"some secret bytes");

        {
            let mut index = vault.index.borrow_mut();

            index.entry_mut("file").unwrap().chunks[0].encrypted_key[5] ^= 0xFF;
        }

        let result = vault.get("file", &mut Vec::new());

        assert!(matches!(result, Err(Error::Cipher(_))), "got {:?}", result);
    }

    #[test]
    fn wrong_key() {
        let path = temp_storage_path("wrongkey");
        let words1 = make_words();
        let words2 = make_words();

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage);

            put_bytes(&mut vault, "user1.txt", b"this data belongs to user 1");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage);

            // User2 cannot access user1's data
            assert!(vault.get("user1.txt", &mut Vec::new()).is_err());
        }
    }

    #[test]
    fn same_file_same_path_same_user() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"same content");

        let blobs_after_first = vault.storage.list(Kind::Blob).unwrap().len();

        // Basically a no-op
        put_bytes(&mut vault, "file", b"same content");

        let blobs_after_second = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(blobs_after_first, blobs_after_second);
        assert_eq!(get_bytes(&vault, "file"), b"same content");
    }

    #[test]
    fn same_file_different_paths_same_user() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file1", b"same content");

        let blobs_after_first = vault.storage.list(Kind::Blob).unwrap().len();

        put_bytes(&mut vault, "file2", b"same content");

        let blobs_after_second = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(blobs_after_first, blobs_after_second);
        assert_eq!(get_bytes(&vault, "file1"), get_bytes(&vault, "file2"));
    }

    #[test]
    fn different_files_same_path_same_user() {
        let (mut vault, _path, _words) = vault();

        put_bytes(&mut vault, "file", b"content");

        let blobs_after_first = vault.storage.list(Kind::Blob).unwrap().len();

        put_bytes(&mut vault, "file", b"different content");

        let blobs_after_second = vault.storage.list(Kind::Blob).unwrap().len();

        // No unreferenced chunks, the old chunks are in a separate version
        assert!(blobs_after_second > blobs_after_first);
        assert_eq!(get_bytes(&vault, "file"), b"different content");

        vault.drop_version("file", 0).unwrap();

        let blobs_after_version_drop = vault.storage.list(Kind::Blob).unwrap().len();

        assert_eq!(blobs_after_version_drop, blobs_after_first);
    }

    #[test]
    fn same_file_same_path_different_users() {
        let path = temp_storage_path("same_file_same_path_different_users");
        let words1 = make_words();
        let words2 = make_words();

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage);

            put_bytes(&mut vault, "file", b"same content");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage);

            put_bytes(&mut vault, "file", b"same content");
        }

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage);

            assert_eq!(get_bytes(&vault, "file"), b"same content");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage);

            assert_eq!(get_bytes(&vault, "file"), b"same content");
        }
    }

    #[test]
    fn same_file_different_paths_different_users() {
        let path = temp_storage_path("same_file_different_paths_different_users");
        let words1 = make_words();
        let words2 = make_words();

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage);

            put_bytes(&mut vault, "file1", b"same content");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage);

            put_bytes(&mut vault, "file2", b"same content");
        }

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage);

            assert_eq!(get_bytes(&vault, "file1"), b"same content");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage);

            assert_eq!(get_bytes(&vault, "file2"), b"same content");
        }
    }

    #[test]
    fn different_files_same_path_different_users() {
        let path = temp_storage_path("different_files_same_path_different_users");
        let words1 = make_words();
        let words2 = make_words();

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage);

            put_bytes(&mut vault, "file", b"different content 1");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage);

            put_bytes(&mut vault, "file", b"different content 2");
        }

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage);

            assert_eq!(get_bytes(&vault, "file"), b"different content 1");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage);

            assert_eq!(get_bytes(&vault, "file"), b"different content 2");
        }
    }
}
