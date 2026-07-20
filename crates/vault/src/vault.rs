//! The primary API surface of the vault.
//!
//! A [`Vault`] owns an [`Identity`] and a [`storage::Backend`] and exposes high-level file
//! operation: put, get, version history, rename, trash/restore/purge, and integrity verification.
//!
//! On construction the manifest is loaded and decrypted (or an empty manifest is initialized).
//! Every mutating method updates the in-memory manifest and then flushes it back to the storage
//! before returning.

use crate::{
    crypto::cipher,
    identity::Identity,
    storage::{
        self,
        chunk::{self, Chunks},
        manifest::{self, Manifest, Properties, VersionProperties},
    },
};

use gate::sys::{borrow::Cow, io, macros::format, string::String, time, vec::Vec};

/// Errors from vault-level file operations.
#[derive(Debug)]
pub enum Error {
    /// A blob or manifest storage operation failed.
    Storage(storage::Error),

    /// An AEAD encryption or decryption error (wrong key, corrupted data, etc.).
    Cipher(cipher::Error),

    /// An error from the chunker, most likely an I/O error.
    Chunk(chunk::Error),

    /// A manifest-level error.
    Manifest(manifest::Error),

    /// An I/O error most likely while writing decrypted plaintext to the writer.
    Io(io::Error),

    /// The requested file path does not exist in the manifest (or is trashed).
    NotFound,

    /// A [`Vault::restore`] was attempted on an entry that is not currently trashed.
    NotTrashed,

    /// A [`Vault::trash`] was attempted on an entry that has already been trashed.
    AlreadyTrashed,

    /// The requested version index is out of bounds for the entry's history.
    VersionNotFound,

    /// A blob's signature did not match, could be the manifest blob or chunks (including versions).
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
            Self::Manifest(e) => write!(f, "manifest: {}", e),
            Self::Io(e) => write!(f, "I/O: {}", e),
            Self::NotFound => write!(f, "file not found"),
            Self::NotTrashed => write!(f, "file is not in the trash"),
            Self::AlreadyTrashed => write!(f, "file is already in the trash"),
            Self::VersionNotFound => write!(f, "version not found"),
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

impl From<manifest::Error> for Error {
    fn from(value: manifest::Error) -> Self {
        match value {
            manifest::Error::NotFound => Self::NotFound,
            manifest::Error::NotTrashed => Self::NotTrashed,
            manifest::Error::AlreadyTrashed => Self::AlreadyTrashed,
            manifest::Error::VersionNotFound => Self::VersionNotFound,
            other => Self::Manifest(other),
        }
    }
}

/// An active vault session with a decrypted manifest and a connected storage backend.
///
/// The manifest is kept in memory. All writes are reflected into storage by [`flush_manifest`]
/// before each method returns, keeping the on-disk state in sync.
pub struct Vault<S: storage::Backend> {
    /// The cryptographic identity used to encrypt, decrypt, sign, and verify all blobs and
    /// the manifest.
    identity: Identity,

    /// The storage backend.
    storage: S,

    /// The decrypted in-memory manifest. All mutations are applied here first, then flushed
    /// to [`Vault::storage`] via [`Vault::flush_manifest`] before each method returns.
    manifest: Manifest,
}

impl<S: storage::Backend> Vault<S> {
    /// Opens a vault by loading and decrypting the manifest from `storage`.
    ///
    /// Creates an empty manifest if none exists yet.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading the manifest from storage fails for reasons
    ///   other than [`Error::NotFound`].
    /// - [`Error::Manifest`]: If the underlying manifest decryption or deserialization fails.
    /// - [`Error::Tampered`]: If the manifest signature is invalid.
    pub fn open(identity: Identity, storage: S) -> Result<Self, Error> {
        let manifest = match storage.load_manifest() {
            Ok(manifest) => Manifest::unlock(
                &manifest,
                &identity.encryption_key(),
                |message, signature_bytes| identity.verify(message, signature_bytes),
            )
            .map_err(|e| match e {
                manifest::Error::Tampered => Error::Tampered("manifest".into()),
                other => Error::Manifest(other),
            })?,
            Err(storage::Error::NotFound) => Manifest::new(),
            Err(e) => return Err(Error::Storage(e)),
        };

        Ok(Self {
            identity,
            storage,
            manifest,
        })
    }

    /// Encrypts and stores a file, returning the number of new chunks uploaded.
    ///
    /// The file is split into [`chunk::CHUNK_SIZE`]-byte chunks. Each chunk is addressed by
    /// a keyed BLAKE3 hash of its plaintext, enabling per-user-per-chunk deduplication.
    /// If `path` already exists with different content, the previous version is saved to history
    /// via [`manifest::Entry::push_version`].
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If writing a chunk to storage or flushing the manifest fails.
    /// - [`Error::Cipher`]: If chunk or manifest encryption fails.
    /// - [`Error::Chunk`]: If reading from `reader` fails.
    /// - [`Error::Manifest`]: If manifest encryption or serialization fails.
    pub fn put(&mut self, path: &str, reader: impl io::Read, size: u64) -> Result<usize, Error> {
        let mut chunks = Chunks::new(reader);
        let mut entry_chunks = Vec::new();

        while let Some(chunk) = chunks.next_chunk()? {
            let address = chunk.address(&self.identity.encryption_key());
            let key = chunk.key(&self.identity.encryption_key());
            let encrypted_chunk_key = cipher::encrypt(&self.identity.encryption_key(), &key)?;
            let mut encrypted_key = [0u8; 60];
            encrypted_key.copy_from_slice(&encrypted_chunk_key);

            // Redundant check but we keep it in case a storage::Backend::put() didn't do the check
            // though not entirely useless since we can avoid calling cipher::encrypt()
            if !self.storage.exists_blob(&address)? {
                let encrypted =
                    cipher::lock(&key, chunk.data, |message| self.identity.sign(message))?;

                self.storage.put_blob(&address, &encrypted)?;
            }

            entry_chunks.push(manifest::EntryChunk {
                address,
                encrypted_key,
            });
        }

        if let Some(existing) = self.manifest.entries.get(path) {
            let existing_addresses: Vec<[u8; 32]> =
                existing.chunks.iter().map(|c| c.address).collect();
            let new_addresses: Vec<[u8; 32]> = entry_chunks.iter().map(|c| c.address).collect();

            if existing_addresses == new_addresses {
                // TODO: If the file exists and is trashed, we should untrash it.
                return Ok(0);
            }
        }

        let chunk_count = entry_chunks.len();
        let modified = time::current_secs().unwrap_or(0);

        if let Some(existing) = self.manifest.entries.get_mut(path) {
            existing.push_version(entry_chunks, size, modified);

            self.flush_manifest()?;

            return Ok(chunk_count);
        }

        self.manifest.insert(
            path,
            manifest::Entry {
                chunks: entry_chunks,
                versions: Vec::new(),
                size,
                modified,
                trashed: 0,
            },
        );
        self.flush_manifest()?;

        Ok(chunk_count)
    }

    /// Decrypts and streams the current version of `path` into `writer` then returns the total
    /// number of plaintext bytes written.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading a chunk blob from storage fails.
    /// - [`Error::Cipher`]: If chunk or manifest decryption fails.
    /// - [`Error::Io`]: If writing to `writer` fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::Tampered`]: If signature verification fails.
    /// - [`Error::Other`]: If wrong size chunk encryption key is found.
    pub fn get(&self, path: &str, writer: &mut impl io::Write) -> Result<u64, Error> {
        let entry = self.manifest.get(path).ok_or(Error::NotFound)?;

        self.decrypt_chunks(path, &entry.chunks, writer)
    }

    /// Returns version metadata for all historical revisions of `path`, oldest first.
    ///
    /// Includes versions of trashed entries. Returns `None` if the path is absent.
    pub fn versions(&self, path: &str) -> Option<Vec<VersionProperties>> {
        // Direct `entries` get instead of `self.manifest.get()` so the trashed entries are included
        let entry = self.manifest.entries.get(path)?;

        Some(
            entry
                .versions
                .iter()
                .enumerate()
                .map(|(i, v)| VersionProperties {
                    index: i,
                    chunk_count: v.chunks.len(),
                    size: v.size,
                    modified: v.modified,
                })
                .collect(),
        )
    }

    /// Decrypts and streams a specific historical version of `path` into `writer`.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading a chunk blob from storage fails.
    /// - [`Error::Cipher`]: If chunk or manifest decryption fails.
    /// - [`Error::Io`]: If writing to `writer` fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::VersionNotFound`]: If version at `index` is absent.
    /// - [`Error::Tampered`]: If signature verification fails.
    /// - [`Error::Other`]: If wrong size chunk encryption key is found.
    pub fn get_version(
        &self,
        path: &str,
        index: usize,
        writer: &mut impl io::Write,
    ) -> Result<u64, Error> {
        // Direct `entries` get instead of `self.manifest.get()` so the trashed entries are included
        let entry = self.manifest.entries.get(path).ok_or(Error::NotFound)?;
        let version = entry.versions.get(index).ok_or(Error::VersionNotFound)?;

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
    /// - [`Error::Manifest`]: If manifest encryption or serialization fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::VersionNotFound`]: If version at `version_index` is absent.
    pub fn revert(&mut self, path: &str, version_index: usize) -> Result<(), Error> {
        // Direct `entries` get instead of `self.manifest.get()` so the trashed entries are included
        let entry = self.manifest.entries.get_mut(path).ok_or(Error::NotFound)?;

        if version_index >= entry.versions.len() {
            return Err(Error::VersionNotFound);
        }

        let current = manifest::Version {
            chunks: core::mem::take(&mut entry.chunks),
            size: entry.size,
            modified: entry.modified,
        };
        let target = entry.versions.remove(version_index);

        entry.chunks = target.chunks;
        entry.size = target.size;
        entry.modified = target.modified;
        entry.versions.push(current);

        self.flush_manifest()?;

        Ok(())
    }

    /// Permanently drops a historical version and deletes its now-unreferenced blobs.
    ///
    /// Addresses still referenced by the active version or other files are preserved.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Manifest`]: If manifest encryption or serialization fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::VersionNotFound`]: If version at `index` is absent.
    pub fn drop_version(&mut self, path: &str, index: usize) -> Result<(), Error> {
        let dropped = self.manifest.drop_version(path, index)?;

        for address in dropped {
            self.storage.delete_blob(&address)?;
        }

        self.flush_manifest()?;

        Ok(())
    }

    /// Replaces the active version with the most recent historical version.
    ///
    /// Active chunks that are no longer referenced are deleted from storage.
    /// If no historical versions exist, the file is deleted entirely.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Manifest`]: If manifest encryption or serialization fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    pub fn drop_version_current(&mut self, path: &str) -> Result<(), Error> {
        // Direct `entries` get instead of `self.manifest.get()` so the trashed entries are included
        let entry = self.manifest.entries.get_mut(path).ok_or(Error::NotFound)?;

        if entry.versions.is_empty() {
            return self.delete(path);
        }

        let latest_version = entry.versions.remove(entry.versions.len() - 1);
        let dropped_chunks = core::mem::replace(&mut entry.chunks, latest_version.chunks);

        entry.size = latest_version.size;
        entry.modified = latest_version.modified;

        let still_referenced: Vec<[u8; 32]> = self.manifest.addresses();
        let addresses: Vec<[u8; 32]> = dropped_chunks
            .into_iter()
            .map(|c| c.address)
            .filter(|a| !still_referenced.contains(a))
            .collect();

        for address in &addresses {
            self.storage.delete_blob(address)?;
        }

        self.flush_manifest()?;

        Ok(())
    }

    /// Moves a historical version out of `path`'s history into a new independent file at `new_path`.
    ///
    /// No blobs are copied, only manifest references are updated. Both paths become independently
    /// readable and writable after the call.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Manifest`]: If manifest encryption or serialization fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::VersionNotFound`]: If version at `index` is absent.
    pub fn detach_version(
        &mut self,
        path: &str,
        index: usize,
        new_path: &str,
    ) -> Result<(), Error> {
        // Direct `entries` get instead of `self.manifest.get()` so the trashed entries are included
        let entry = self.manifest.entries.get_mut(path).ok_or(Error::NotFound)?;

        if index >= entry.versions.len() {
            return Err(Error::VersionNotFound);
        }

        let detached = entry.versions.remove(index);

        self.manifest.insert(
            new_path,
            manifest::Entry {
                chunks: detached.chunks,
                versions: Vec::new(),
                size: detached.size,
                modified: detached.modified,
                trashed: 0,
            },
        );
        self.flush_manifest()?;

        Ok(())
    }

    /// Moves the active version of `path` to `new_path` and makees the most recent historical
    /// version the new active revision.
    ///
    /// Equivalent to [`Vault::rename`] when no historical versions exist.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Manifest`]: If manifest encryption or serialization fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    pub fn detach_version_current(&mut self, path: &str, new_path: &str) -> Result<(), Error> {
        // Direct `entries` get instead of `self.manifest.get()` so the trashed entries are included
        let entry = self.manifest.entries.get_mut(path).ok_or(Error::NotFound)?;

        if entry.versions.is_empty() {
            return self.rename(path, new_path);
        }

        let latest_version = entry.versions.remove(entry.versions.len() - 1);
        let chunks = core::mem::replace(&mut entry.chunks, latest_version.chunks);
        let size = core::mem::replace(&mut entry.size, latest_version.size);
        let modified = core::mem::replace(&mut entry.modified, latest_version.modified);

        self.manifest.insert(
            new_path,
            manifest::Entry {
                chunks,
                versions: Vec::new(),
                size,
                modified,
                trashed: 0,
            },
        );
        self.flush_manifest()?;

        Ok(())
    }

    /// Renames `old_path` to `new_path` in the manifest. Manifest manipulation only, no blobs are
    /// touched.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Manifest`]: If manifest encryption or serialization fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    pub fn rename(&mut self, old_path: &str, new_path: &str) -> Result<(), Error> {
        self.manifest.rename(old_path, new_path)?;
        self.flush_manifest()?;

        Ok(())
    }

    /// Soft-deletes `path`, moving it to the trash. Blobs are retained and the entry can be
    /// recovered with [`Vault::restore`].
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Manifest`]: If manifest encryption or serialization fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::AlreadyTrashed`]: If the `path` is already trashed.
    pub fn trash(&mut self, path: &str) -> Result<(), Error> {
        self.manifest.trash(path)?;
        self.flush_manifest()?;

        Ok(())
    }

    /// Recovers a trashed entry, making it live again.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Manifest`]: If manifest encryption or serialization fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::NotTrashed`]: If the `path` is not currently trashed.
    pub fn restore(&mut self, path: &str) -> Result<(), Error> {
        self.manifest.restore(path)?;
        self.flush_manifest()?;

        Ok(())
    }

    /// Permanently removes a trashed entry and deletes its blobs if no longer referenced by any
    /// live file.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Manifest`]: If manifest encryption or serialization fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::NotTrashed`]: If the `path` is not currently trashed.
    pub fn purge(&mut self, path: &str) -> Result<(), Error> {
        let addresses = self.manifest.purge(path)?;

        for address in &addresses {
            self.storage.delete_blob(address)?;
        }

        self.flush_manifest()?;

        Ok(())
    }

    /// Purges all trashed entries at once. Returns the total number of blobs deleted.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Manifest`]: If manifest encryption or serialization fails.
    pub fn cleanup(&mut self) -> Result<usize, Error> {
        let addresses = self.manifest.purge_all();
        let removed = addresses.len();

        for address in &addresses {
            self.storage.delete_blob(address)?;
        }

        self.flush_manifest()?;

        Ok(removed)
    }

    /// Hard-deletes `path`, trashes it and immediately purges it. Non-recoverable.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Manifest`]: If manifest encryption or serialization fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    pub fn delete(&mut self, path: &str) -> Result<(), Error> {
        // TODO: If trash returns [`Error::AlreadyTrashed`], it should gracefully purge it instead
        // of propagating the error in this method.
        self.manifest.trash(path)?;
        self.purge(path)?;

        Ok(())
    }

    /// Returns a sorted list of paths for all live (non-trashed) entries.
    pub fn list(&self) -> Vec<&str> {
        let mut paths: Vec<&str> = self
            .manifest
            .entries
            .iter()
            .filter(|(_, v)| v.trashed == 0)
            .map(|(k, _)| k.as_str())
            .collect();

        paths.sort();

        paths
    }

    /// Returns a sorted list of paths for all trashed entries.
    pub fn list_trash(&self) -> Vec<&str> {
        let mut paths: Vec<&str> = self
            .manifest
            .entries
            .iter()
            .filter(|(_, v)| v.trashed != 0)
            .map(|(k, _)| k.as_str())
            .collect();

        paths.sort();

        paths
    }

    /// Returns [`Properties`] metadata for `path`.
    ///
    /// Also returns metadata for trashed entries.
    pub fn properties(&self, path: &str) -> Option<Properties> {
        // Direct `entries` get instead of `self.manifest.get()` so the trashed entries are included
        self.manifest.entries.get(path).map(|e| Properties {
            chunk_count: e.chunks.len(),
            size: e.size,
            modified: e.modified,
            trashed: e.trashed,
            version_count: e.versions.len(),
        })
    }

    /// Verifies the signatures on all chunks of `path`, including every version.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading a chunk blob from storage fails.
    /// - [`Error::Cipher`]: If chunk or manifest decryption fails.
    /// - [`Error::NotFound`]: If `path` is absent.
    /// - [`Error::Tampered`]: If signature verification fails.
    /// - [`Error::Other`]: If wrong size chunk encryption key is found.
    pub fn verify(&self, path: &str) -> Result<(), Error> {
        // Direct `entries` get instead of `self.manifest.get()` so the trashed entries are included
        let entry = self.manifest.entries.get(path).ok_or(Error::NotFound)?;

        self.verify_entry_chunks(path, &entry.chunks)?;

        for (i, version) in entry.versions.iter().enumerate() {
            self.verify_entry_chunks(
                &format!("{}@v{}", path, i + 1), // Display versions start from 1
                &version.chunks,
            )?;
        }

        Ok(())
    }

    /// Verifies every chunk in the manifest, live, trashed, and all versions as well as
    /// the manifest blob itself.
    ///
    /// Returns a sorted, deduplicated list of paths with at least one tampered chunk.
    pub fn verify_all(&self) -> Vec<String> {
        let mut tampered = Vec::new();

        // Check the manifest blob itself
        if let Ok(blob) = self.storage.load_manifest()
            && Manifest::unlock(
                &blob,
                &self.identity.encryption_key(),
                |message, signature_bytes| self.identity.verify(message, signature_bytes),
            )
            .is_err()
        {
            tampered.push("manifest".into());
        }

        for (path, entry) in &self.manifest.entries {
            if self.verify_entry_chunks(path, &entry.chunks).is_err() {
                tampered.push(path.clone());
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

    /// Decrypts the chunk list for `path` and writes plaintext to `writer`.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If reading a chunk blob from storage fails.
    /// - [`Error::Cipher`]: If chunk or manifest decryption fails.
    /// - [`Error::Io`]: If writing to `writer` fails.
    /// - [`Error::Tampered`]: If signature verification fails.
    /// - [`Error::Other`]: If wrong size chunk encryption key is found.
    fn decrypt_chunks(
        &self,
        path: &str,
        chunks: &[manifest::EntryChunk],
        writer: &mut impl io::Write,
    ) -> Result<u64, Error> {
        let mut size = 0u64;

        for chunk in chunks {
            let chunk_key = cipher::decrypt(&self.identity.encryption_key(), &chunk.encrypted_key)?;
            let key = chunk_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::Other("wrong size chunk encryption key was found".into()))?;
            let blob = self.storage.get_blob(&chunk.address)?;
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
    /// - [`Error::Cipher`]: If chunk or manifest decryption fails.
    /// - [`Error::Tampered`]: If signature verification fails.
    /// - [`Error::Other`]: If wrong size chunk encryption key is found.
    fn verify_entry_chunks(
        &self,
        path: &str,
        chunks: &[manifest::EntryChunk],
    ) -> Result<(), Error> {
        // TODO: Should this only verify the signature and ignore the decryption?
        for chunk in chunks {
            let chunk_key = cipher::decrypt(&self.identity.encryption_key(), &chunk.encrypted_key)?;
            let key = chunk_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::Other("wrong size chunk encryption key was found".into()))?;
            let blob = self.storage.get_blob(&chunk.address)?;

            cipher::unlock(&key, &blob, |message, signature_bytes| {
                self.identity.verify(message, signature_bytes)
            })
            .map_err(|e| match e {
                cipher::Error::InvalidSignature => Error::Tampered(path.into()),
                other => Error::Cipher(other),
            })?;
        }

        Ok(())
    }

    /// Serialises, encrypts, signs, and persists the current manifest to the storage backend.
    ///
    /// # Errors
    ///
    /// - [`Error::Storage`]: If writing the manifest blob to storage fails.
    /// - [`Error::Manifest`]: If the underlying manifest decryption or deserialization fails.
    fn flush_manifest(&self) -> Result<(), Error> {
        let data = self
            .manifest
            .lock(&self.identity.encryption_key(), |message| {
                self.identity.sign(message)
            })?;

        self.storage.save_manifest(&data)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::storage::{Backend, chunk::CHUNK_SIZE, local};

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

    fn vault() -> Vault<local::Storage> {
        let path = temp_storage_path("");
        let words = make_words();
        let identity = make_identity(&words);
        let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();

        Vault::open(identity, storage).unwrap()
    }

    fn put_bytes(vault: &mut Vault<local::Storage>, path: &str, data: &[u8]) {
        vault.put(path, data, data.len() as u64).unwrap();
    }

    fn get_bytes(vault: &Vault<local::Storage>, path: &str) -> Vec<u8> {
        let mut buf = Vec::new();

        vault.get(path, &mut buf).unwrap();

        buf
    }

    // Only used for tests, blob storage is immutable
    fn overwrite_bytes(
        storage_path: &Path,
        public_signing_key: &[u8; 32],
        address: &[u8; 32],
        data: &[u8],
    ) {
        let user_hex: String = Manifest::address(public_signing_key)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let blob_hex: String = address.iter().map(|b| format!("{:02x}", b)).collect();
        let path = storage_path
            .join(&user_hex[0..2])
            .join(&user_hex[2..4])
            .join(&user_hex[4..])
            .join("blobs")
            .join(&blob_hex[0..2])
            .join(&blob_hex[2..4])
            .join(&blob_hex[4..]);
        let temp = path.with_extension("tmp");

        fs::write(&temp, data).unwrap();
        fs::rename(&temp, &path).unwrap();
    }

    #[test]
    fn put_get_small_data_roundtrip() {
        let mut vault = vault();
        let data = b"small data";

        put_bytes(&mut vault, "notes/small.txt", data);

        assert_eq!(get_bytes(&vault, "notes/small.txt"), data);
    }

    #[test]
    fn put_get_large_data_roundtrip() {
        let mut vault = vault();
        let data = [
            vec![0xAAu8; CHUNK_SIZE],
            vec![0xBBu8; CHUNK_SIZE],
            vec![0xCCu8; CHUNK_SIZE / 2],
        ]
        .concat();

        put_bytes(&mut vault, "large", &data);

        let blobs = vault.storage.list_blobs().unwrap().len();

        assert_eq!(blobs, 3); // 3 data blobs
        assert_eq!(get_bytes(&vault, "large"), data);
    }

    #[test]
    fn per_user_per_chunk_deduplication() {
        let mut vault = vault();
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

        let blobs_after_first = vault.storage.list_blobs().unwrap().len();

        put_bytes(&mut vault, "file2", &data2);

        let blobs_after_second = vault.storage.list_blobs().unwrap().len();

        assert_eq!(blobs_after_second, blobs_after_first + 1); // Only one new chunk
        assert_eq!(get_bytes(&vault, "file1"), data1);
        assert_eq!(get_bytes(&vault, "file2"), data2);
    }

    #[test]
    fn deduplicate_chunks() {
        let mut vault = vault();
        let data = [
            vec![0xAAu8; chunk::CHUNK_SIZE],
            vec![0xAAu8; chunk::CHUNK_SIZE],
            vec![0xBBu8; chunk::CHUNK_SIZE / 2],
        ]
        .concat();

        put_bytes(&mut vault, "large", &data);

        let blobs = vault.storage.list_blobs().unwrap().len();

        assert_eq!(blobs, 2); // The file has 3 blobs but 2 are identical
        assert_eq!(get_bytes(&vault, "large"), data);
    }

    #[test]
    fn put_get_empty_file_roundtrip() {
        let mut vault = vault();

        put_bytes(&mut vault, "notes/empty.txt", b"");

        assert_eq!(get_bytes(&vault, "notes/empty.txt"), b"");
    }

    #[test]
    fn get_version() {
        let mut vault = vault();

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
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"only one version");

        // No previous versions exist yet
        let mut buf = Vec::new();
        let result = vault.get_version("file", 0, &mut buf);

        assert!(matches!(result, Err(Error::VersionNotFound)));
    }

    #[test]
    fn overwrite() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"version one");
        put_bytes(&mut vault, "file", b"version two");

        // Data in path is overwritten, but the old version is kept until dropped
        assert_eq!(get_bytes(&vault, "file"), b"version two");
    }

    #[test]
    fn overwrite_creates_version() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"version one");
        put_bytes(&mut vault, "file", b"version two");

        // Active content is the latest
        assert_eq!(get_bytes(&vault, "file"), b"version two");

        // One previous version was created
        let versions = vault.versions("file").unwrap();

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].size, b"version one".len() as u64);
    }

    #[test]
    fn overwrite_no_unreferenced_chunks() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"version one");

        let blobs_after_first = vault.storage.list_blobs().unwrap().len();

        put_bytes(&mut vault, "file", b"version two");

        let blobs_after_second = vault.storage.list_blobs().unwrap().len();

        // A new chunk was added, nothing was removed
        assert!(blobs_after_second > blobs_after_first);
        assert_eq!(blobs_after_second, blobs_after_first + 1);
    }

    #[test]
    fn overwrite_same_content_no_new_chunks() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"same content");

        let blobs_after_first = vault.storage.list_blobs().unwrap().len();

        put_bytes(&mut vault, "file", b"same content");

        let blobs_after_second = vault.storage.list_blobs().unwrap().len();

        // Identical content, no new chunk written
        assert_eq!(blobs_after_first, blobs_after_second);

        // No-op, no new version recorded
        assert_eq!(vault.versions("file").unwrap().len(), 0);
    }

    #[test]
    fn multiple_overwrites_accumulate_versions() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");
        put_bytes(&mut vault, "file", b"v3");

        assert_eq!(get_bytes(&vault, "file"), b"v3");
        assert_eq!(vault.versions("file").unwrap().len(), 2);
    }

    #[test]
    fn revert() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"original");
        put_bytes(&mut vault, "file", b"overwritten");

        // Revert to index 0 ("original")
        vault.revert("file", 0).unwrap();

        assert_eq!(get_bytes(&vault, "file"), b"original");
    }

    #[test]
    fn revert_preserves_full_history() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        // Before revert: versions = ["v1"], active = "v2"
        vault.revert("file", 0).unwrap();

        // After revert: active = "v1", versions = ["v2"]
        assert_eq!(get_bytes(&vault, "file"), b"v1");

        let versions = vault.versions("file").unwrap();

        assert_eq!(versions.len(), 1);

        let mut buf = Vec::new();

        vault.get_version("file", 0, &mut buf).unwrap();

        assert_eq!(buf, b"v2");
    }

    #[test]
    fn revert_version_not_found() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"data");

        assert!(matches!(
            vault.revert("file", 0),
            Err(Error::VersionNotFound)
        ));
    }

    #[test]
    fn drop_version() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"old content");
        put_bytes(&mut vault, "file", b"new content");

        let blobs_before = vault.storage.list_blobs().unwrap().len();

        vault.drop_version("file", 0).unwrap();

        let blobs_after = vault.storage.list_blobs().unwrap().len();

        // One chunk purged (the "old content" chunk)
        assert!(blobs_after < blobs_before);
        assert_eq!(vault.versions("file").unwrap().len(), 0);
        assert_eq!(get_bytes(&vault, "file"), b"new content");
    }

    #[test]
    fn drop_version_skips_shared_chunks() {
        let mut vault = vault();

        put_bytes(
            &mut vault,
            "file",
            &[vec![0xAAu8; CHUNK_SIZE], vec![0xBBu8; CHUNK_SIZE]].concat(),
        );

        // Overwrite to create version
        put_bytes(&mut vault, "file", &vec![0xBBu8; CHUNK_SIZE]);

        let blobs_before = vault.storage.list_blobs().unwrap().len();

        vault.drop_version("file", 0).unwrap();

        let blobs_after = vault.storage.list_blobs().unwrap().len();

        // A Chunk is shared with the active version, must not be deleted
        // Only one chunk is purged (the unshared one)
        assert!(blobs_after < blobs_before);
        assert_eq!(get_bytes(&vault, "file"), vec![0xBBu8; CHUNK_SIZE]);
    }

    #[test]
    fn drop_version_skips_shared_chunks_across_files() {
        let mut vault = vault();

        put_bytes(&mut vault, "file1", &vec![0xAAu8; CHUNK_SIZE]);
        put_bytes(
            &mut vault,
            "file2",
            &[vec![0xAAu8; CHUNK_SIZE], vec![0xBBu8; CHUNK_SIZE]].concat(),
        );

        // Overwrite file1 to create version
        put_bytes(&mut vault, "file1", &vec![0xCCu8; CHUNK_SIZE]);

        let blobs_before = vault.storage.list_blobs().unwrap().len();

        vault.drop_version("file1", 0).unwrap();

        let blobs_after = vault.storage.list_blobs().unwrap().len();

        // Chunk is shared with the active version, must not be deleted
        assert_eq!(blobs_before, blobs_after);
        assert_eq!(get_bytes(&vault, "file1"), vec![0xCCu8; CHUNK_SIZE]);
    }

    #[test]
    fn drop_version_not_found() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"data");

        assert!(matches!(
            vault.drop_version("file", 0),
            Err(Error::VersionNotFound)
        ));
    }

    #[test]
    fn drop_current() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        let blobs_before = vault.storage.list_blobs().unwrap().len();

        vault.drop_version_current("file").unwrap();

        let blobs_after = vault.storage.list_blobs().unwrap().len();

        // v2 chunk was purged
        assert!(blobs_after < blobs_before);

        // v1 is now active
        assert_eq!(get_bytes(&vault, "file"), b"v1");
        assert_eq!(vault.versions("file").unwrap().len(), 0);
    }

    #[test]
    fn drop_current_no_versions_deletes_file() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"data");

        vault.drop_version_current("file").unwrap();

        assert!(matches!(
            vault.get("file", &mut Vec::new()),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn detach_version() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"original");
        put_bytes(&mut vault, "file", b"accidentally overwritten");

        vault.detach_version("file", 0, "original").unwrap();

        assert_eq!(get_bytes(&vault, "original"), b"original");
        assert_eq!(get_bytes(&vault, "file"), b"accidentally overwritten");
    }

    #[test]
    fn detach_version_removes_from_source_history() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        vault.detach_version("file", 0, "file_v1").unwrap();

        // Version was removed from source
        assert_eq!(vault.versions("file").unwrap().len(), 0);

        // Detached entry has no history of its own
        assert_eq!(vault.versions("file_v1").unwrap().len(), 0);

        // Both paths are independently readable
        assert_eq!(get_bytes(&vault, "file"), b"v2");
        assert_eq!(get_bytes(&vault, "file_v1"), b"v1");
    }

    #[test]
    fn detach_version_no_chunk_duplication() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"shared data");
        put_bytes(&mut vault, "file", b"other data");

        let blobs_before = vault.storage.list_blobs().unwrap().len();

        // Detach just references existing chunks, no new blobs written
        vault.detach_version("file", 0, "detached").unwrap();

        let blobs_after = vault.storage.list_blobs().unwrap().len();

        assert_eq!(blobs_before, blobs_after);
    }

    #[test]
    fn detach_version_not_found() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"data");

        assert!(matches!(
            vault.detach_version("file", 0, "new"),
            Err(Error::VersionNotFound)
        ));
    }

    #[test]
    fn detach_current() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        vault.detach_version_current("file", "file_v2").unwrap();

        assert_eq!(get_bytes(&vault, "file_v2"), b"v2");
        assert_eq!(get_bytes(&vault, "file"), b"v1");
        assert_eq!(vault.versions("file").unwrap().len(), 0);
        assert_eq!(vault.versions("file_v2").unwrap().len(), 0);
    }

    #[test]
    fn detach_current_no_versions_is_rename() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"data");

        vault.detach_version_current("file", "renamed").unwrap();

        assert_eq!(get_bytes(&vault, "renamed"), b"data");
        assert!(matches!(
            vault.get("file", &mut Vec::new()),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn rename() {
        let mut vault = vault();

        put_bytes(&mut vault, "old/file", b"data");

        vault.rename("old/file", "new/file").unwrap();

        assert_eq!(get_bytes(&vault, "new/file"), b"data");
    }

    #[test]
    fn trash() {
        let mut vault = vault();

        put_bytes(&mut vault, "file.txt", b"data");

        vault.trash("file.txt").unwrap();

        assert!(vault.list().is_empty());
        assert!(!vault.storage.list_blobs().unwrap().is_empty());
        assert_eq!(vault.list_trash(), vec!["file.txt"]);
    }

    #[test]
    fn restore() {
        let mut vault = vault();

        put_bytes(&mut vault, "file.txt", b"data");

        vault.trash("file.txt").unwrap();
        vault.restore("file.txt").unwrap();

        assert_eq!(get_bytes(&vault, "file.txt"), b"data");
        assert!(vault.list_trash().is_empty());
    }

    #[test]
    fn purge() {
        let mut vault = vault();

        put_bytes(&mut vault, "1.txt", b"keep this");
        put_bytes(&mut vault, "2.txt", b"delete this");

        vault.trash("2.txt").unwrap();

        let blobs_before_purge = vault.storage.list_blobs().unwrap().len();

        vault.purge("2.txt").unwrap();

        assert!(vault.list_trash().is_empty());
        assert!(vault.storage.list_blobs().unwrap().len() < blobs_before_purge);
        assert_eq!(get_bytes(&vault, "1.txt"), b"keep this");
    }

    #[test]
    fn purge_all_version_chunks() {
        let mut vault = vault();

        put_bytes(&mut vault, "file1", b"keep this");
        put_bytes(&mut vault, "file2", b"delete v1");
        put_bytes(&mut vault, "file2", b"delete v2");

        vault.trash("file2").unwrap();

        let blobs_before = vault.storage.list_blobs().unwrap().len();

        vault.purge("file2").unwrap();

        let blobs_after = vault.storage.list_blobs().unwrap().len();

        // Both v1 and v2 chunks of file2 should be purged
        assert_eq!(blobs_before, blobs_after + 2);
        assert_eq!(get_bytes(&vault, "file1"), b"keep this");
    }

    #[test]
    fn cleanup() {
        let mut vault = vault();

        put_bytes(&mut vault, "1.txt", b"data 1");
        put_bytes(&mut vault, "2.txt", b"data 2");

        vault.trash("1.txt").unwrap();
        vault.trash("2.txt").unwrap();

        let removed = vault.cleanup().unwrap();

        assert_eq!(removed, 2); // 1 chunk each
        assert!(vault.list_trash().is_empty());
        assert!(vault.list().is_empty());
    }

    #[test]
    fn cleanup_purges_all_version_chunks() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");
        put_bytes(&mut vault, "file", b"v3");

        vault.trash("file").unwrap();

        vault.cleanup().unwrap();

        assert_eq!(vault.storage.list_blobs().unwrap().len(), 0);
        assert!(vault.list().is_empty());
    }

    #[test]
    fn delete() {
        let mut vault = vault();

        put_bytes(&mut vault, "file.txt", b"data");

        vault.delete("file.txt").unwrap();

        assert!(vault.list_trash().is_empty());

        // file is permanently removed and cannot be restored
        assert!(vault.restore("file.txt").is_err());
    }

    #[test]
    fn only_uploads_changed_chunks() {
        let mut vault = vault();

        let chunk_a = vec![0xAAu8; CHUNK_SIZE];
        let chunk_b = vec![0xBBu8; CHUNK_SIZE];
        let original: Vec<u8> = [chunk_a.clone(), chunk_b].concat();

        put_bytes(&mut vault, "file", &original);

        let blobs_after_first = vault.storage.list_blobs().unwrap().len();

        // Since `chunk_a` is identical, it should not be re-uploaded
        let chunk_b2 = vec![0xCCu8; CHUNK_SIZE];
        let updated: Vec<u8> = [chunk_a, chunk_b2].concat();

        put_bytes(&mut vault, "file", &updated);

        let blobs_after_second = vault.storage.list_blobs().unwrap().len();

        // `chunk_a` already exists, therefore it's skipped and we'd only have 1 new blob
        assert_eq!(blobs_after_second, blobs_after_first + 1);
    }

    #[test]
    fn not_found() {
        let vault = vault();
        let mut buf = Vec::new();

        let got = vault.get("nonexistent.txt", &mut buf);

        assert!(matches!(got, Err(Error::NotFound)));
    }

    #[test]
    fn delete_not_found() {
        let mut vault = vault();
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
            let mut vault = Vault::open(identity, storage).unwrap();

            put_bytes(&mut vault, "persistant.txt", b"persistent data");
        }

        {
            let identity = make_identity(&words);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage).unwrap();

            assert_eq!(get_bytes(&vault, "persistant.txt"), b"persistent data");
        }
    }

    #[test]
    fn verify_all() {
        let mut vault = vault();

        put_bytes(&mut vault, "file1", b"clean data");
        put_bytes(&mut vault, "file2", b"more clean data");

        assert!(vault.verify_all().is_empty());
    }

    #[test]
    fn verify_all_empty_vault() {
        let vault = vault();

        assert!(vault.verify_all().is_empty());
    }

    #[test]
    fn verify_all_tampered_chunk() {
        let path = temp_storage_path("verify_all_tampered_chunk");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut vault = Vault::open(identity, storage).unwrap();

        put_bytes(&mut vault, "file", b"important data");

        let entry = vault.manifest.entries.get("file").unwrap();
        let address = entry.chunks[0].address;
        let mut blob = vault.storage.get_blob(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, &address, &blob);

        let tampared = vault.verify_all();

        assert!(tampared.contains(&"file".into()));
    }

    #[test]
    fn verify_all_tampered_error() {
        let path = temp_storage_path("verify_all_tampered_error");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut vault = Vault::open(identity, storage).unwrap();

        put_bytes(&mut vault, "secret.txt", b"secret");

        let entry = vault.manifest.entries.get("secret.txt").unwrap();
        let address = entry.chunks[0].address;
        let mut blob = vault.storage.get_blob(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, &address, &blob);

        let mut buf = Vec::new();
        let result = vault.get("secret.txt", &mut buf);

        assert!(matches!(result, Err(Error::Tampered(_))));
    }

    #[test]
    fn verify_all_includes_trashed_entries() {
        let path = temp_storage_path("verify_trashed");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut vault = Vault::open(identity, storage).unwrap();

        put_bytes(&mut vault, "trashed.txt", b"will be trashed");

        vault.trash("trashed.txt").unwrap();

        // Corrupt the trashed chunk
        let entry = vault.manifest.entries.get("trashed.txt").unwrap();
        let address = entry.chunks[0].address;
        let mut blob = vault.storage.get_blob(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, &address, &blob);

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
        let mut vault = Vault::open(identity, storage).unwrap();
        let data = [vec![0xAAu8; CHUNK_SIZE], vec![0xBBu8; CHUNK_SIZE]].concat();

        put_bytes(&mut vault, "large", &data);

        // Corrupt both chunks
        let entry = vault.manifest.entries.get("large").unwrap();
        let chunks = &entry.chunks;

        for chunk in chunks {
            let mut blob = vault.storage.get_blob(&chunk.address).unwrap();

            blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

            overwrite_bytes(&path, &public_signing_key, &chunk.address, &blob);
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
        let mut vault = Vault::open(identity, storage).unwrap();

        put_bytes(&mut vault, "file1", b"shared content");
        put_bytes(&mut vault, "file2", b"shared content");

        let entry = vault.manifest.entries.get("file1").unwrap();
        let address = entry.chunks[0].address;
        let mut blob = vault.storage.get_blob(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, &address, &blob);

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
        let mut vault = Vault::open(identity, storage).unwrap();

        put_bytes(&mut vault, "file", b"v0");
        put_bytes(&mut vault, "file", b"v1");
        put_bytes(&mut vault, "file", b"v2");

        // Corrupt the v1 (previous version) chunk
        let entry = vault.manifest.entries.get("file").unwrap();
        let address = entry.versions[0].chunks[0].address; // Version 1
        let mut blob = vault.storage.get_blob(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, &address, &blob);

        let tampered = vault.verify_all();

        assert_eq!(tampered, vec!["file@v1".to_string()]);
        assert!(tampered.contains(&"file@v1".into()));
    }

    #[test]
    fn wrong_key() {
        let path = temp_storage_path("wrongkey");
        let words1 = make_words();
        let words2 = make_words();

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage).unwrap();

            put_bytes(&mut vault, "user1.txt", b"this data belongs to user 1");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage).unwrap();
            let mut buf = Vec::new();

            // User2 cannot access user1's data
            assert!(vault.get("user1.txt", &mut buf).is_err());
        }
    }

    #[test]
    fn same_file_same_path_same_user() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"same content");

        let blobs_after_first = vault.storage.list_blobs().unwrap().len();

        // Basically a no-op
        put_bytes(&mut vault, "file", b"same content");

        let blobs_after_second = vault.storage.list_blobs().unwrap().len();

        assert_eq!(blobs_after_first, blobs_after_second);
        assert_eq!(get_bytes(&vault, "file"), b"same content");
    }

    #[test]
    fn same_file_different_paths_same_user() {
        let mut vault = vault();

        put_bytes(&mut vault, "file1", b"same content");

        let blobs_after_first = vault.storage.list_blobs().unwrap().len();

        put_bytes(&mut vault, "file2", b"same content");

        let blobs_after_second = vault.storage.list_blobs().unwrap().len();

        assert_eq!(blobs_after_first, blobs_after_second);
        assert_eq!(get_bytes(&vault, "file1"), get_bytes(&vault, "file2"));
    }

    #[test]
    fn different_files_same_path_same_user() {
        let mut vault = vault();

        put_bytes(&mut vault, "file", b"content");

        let blobs_after_first = vault.storage.list_blobs().unwrap().len();

        put_bytes(&mut vault, "file", b"different content");

        let blobs_after_second = vault.storage.list_blobs().unwrap().len();

        // No unreferenced chunks, the old chunks are in a separate version
        assert!(blobs_after_second > blobs_after_first);
        assert_eq!(get_bytes(&vault, "file"), b"different content");

        vault.drop_version("file", 0).unwrap();

        let blobs_after_version_drop = vault.storage.list_blobs().unwrap().len();

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
            let mut vault = Vault::open(identity, storage).unwrap();

            put_bytes(&mut vault, "file", b"same content");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage).unwrap();

            put_bytes(&mut vault, "file", b"same content");
        }

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage).unwrap();

            assert_eq!(get_bytes(&vault, "file"), b"same content");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage).unwrap();

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
            let mut vault = Vault::open(identity, storage).unwrap();

            put_bytes(&mut vault, "file1", b"same content");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage).unwrap();

            put_bytes(&mut vault, "file2", b"same content");
        }

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage).unwrap();

            assert_eq!(get_bytes(&vault, "file1"), b"same content");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage).unwrap();

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
            let mut vault = Vault::open(identity, storage).unwrap();

            put_bytes(&mut vault, "file", b"different content 1");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut vault = Vault::open(identity, storage).unwrap();

            put_bytes(&mut vault, "file", b"different content 2");
        }

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage).unwrap();

            assert_eq!(get_bytes(&vault, "file"), b"different content 1");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let vault = Vault::open(identity, storage).unwrap();

            assert_eq!(get_bytes(&vault, "file"), b"different content 2");
        }
    }
}
