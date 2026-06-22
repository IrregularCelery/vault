use gate::sys::{
    io,
    macros::format,
    string::String,
    time::{SystemTime, UNIX_EPOCH},
    vec::Vec,
};

use crate::{
    crypto::cipher,
    identity::Identity,
    storage::{
        self,
        chunk::{self, Chunks},
        manifest::{self, Manifest, Properties, VersionProperties},
    },
};

#[derive(Debug)]
pub enum Error {
    Storage(storage::Error),
    Cipher(cipher::Error),
    Chunk(chunk::Error),
    Manifest(manifest::Error),
    Io(io::Error),
    NotFound,
    NotTrashed,
    AlreadyTrashed,
    VersionNotFound,
    Tampered(String),
    Other(String),
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

pub struct Session<S: storage::Backend> {
    identity: Identity,
    storage: S,
    manifest: Manifest,
}

impl<S: storage::Backend> Session<S> {
    pub fn new(identity: Identity, storage: S) -> Result<Self, Error> {
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

    pub fn put(&mut self, path: &str, reader: impl io::Read, size: u64) -> Result<usize, Error> {
        let mut chunks = Chunks::new(reader);
        let mut entry_chunks = Vec::new();

        while let Some(chunk) = chunks.next_chunk()? {
            let address = chunk.address(&self.identity.encryption_key());
            let key = chunk.key(&self.identity.encryption_key());
            let encrypted_chunk_key =
                cipher::encrypt(&self.identity.encryption_key(), &key).map_err(Error::Cipher)?;
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
                return Ok(0);
            }
        }

        let chunk_count = entry_chunks.len();
        let modified = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

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

    pub fn get(&self, path: &str, writer: &mut impl io::Write) -> Result<u64, Error> {
        let entry = self.manifest.get(path).ok_or(Error::NotFound)?;

        self.decrypt_chunks(path, &entry.chunks, writer)
    }

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

    pub fn drop_version(&mut self, path: &str, index: usize) -> Result<(), Error> {
        let dropped = self.manifest.drop_version(path, index)?;

        for address in dropped {
            self.storage.delete_blob(&address)?;
        }

        self.flush_manifest()?;

        Ok(())
    }

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

    pub fn rename(&mut self, old_path: &str, new_path: &str) -> Result<(), Error> {
        self.manifest.rename(old_path, new_path)?;
        self.flush_manifest()?;

        Ok(())
    }

    pub fn trash(&mut self, path: &str) -> Result<(), Error> {
        self.manifest.trash(path)?;
        self.flush_manifest()?;

        Ok(())
    }

    pub fn restore(&mut self, path: &str) -> Result<(), Error> {
        self.manifest.restore(path)?;
        self.flush_manifest()?;

        Ok(())
    }

    pub fn purge(&mut self, path: &str) -> Result<(), Error> {
        let addresses = self.manifest.purge(path)?;

        for address in &addresses {
            self.storage.delete_blob(address)?;
        }

        self.flush_manifest()?;

        Ok(())
    }

    pub fn cleanup(&mut self) -> Result<usize, Error> {
        let addresses = self.manifest.purge_all();
        let removed = addresses.len();

        for address in &addresses {
            self.storage.delete_blob(address)?;
        }

        self.flush_manifest()?;

        Ok(removed)
    }

    pub fn delete(&mut self, path: &str) -> Result<(), Error> {
        self.manifest.trash(path)?;
        self.purge(path)?;

        Ok(())
    }

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

    fn decrypt_chunks(
        &self,
        path: &str,
        chunks: &[manifest::EntryChunk],
        writer: &mut impl io::Write,
    ) -> Result<u64, Error> {
        let mut size = 0u64;

        for chunk in chunks {
            let chunk_key = cipher::decrypt(&self.identity.encryption_key(), &chunk.encrypted_key)
                .map_err(Error::Cipher)?;
            let key = chunk_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::Chunk(chunk::Error::UnexpectedEof))?;
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

    fn verify_entry_chunks(
        &self,
        path: &str,
        chunks: &[manifest::EntryChunk],
    ) -> Result<(), Error> {
        for chunk in chunks {
            let chunk_key = cipher::decrypt(&self.identity.encryption_key(), &chunk.encrypted_key)
                .map_err(Error::Cipher)?;
            let key = chunk_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::Chunk(chunk::Error::UnexpectedEof))?;
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
    use gate::{
        crypto::bip39,
        sys::{
            env, fs,
            macros::{format, vec},
            path::{Path, PathBuf},
            string::ToString,
        },
    };

    use crate::storage::{Backend, chunk::CHUNK_SIZE, local};

    use super::*;

    fn temp_storage_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();

        env::temp_dir().join(format!("vault_test_{}_{}", name, nanos))
    }

    fn make_words() -> Vec<String> {
        bip39::generate(12).unwrap()
    }

    fn make_identity(words: &[impl AsRef<str>]) -> Identity {
        Identity::from_mnemonic(words).unwrap()
    }

    fn session() -> Session<local::Storage> {
        let path = temp_storage_path("");
        let words = make_words();
        let identity = make_identity(&words);
        let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();

        Session::new(identity, storage).unwrap()
    }

    fn put_bytes(session: &mut Session<local::Storage>, path: &str, data: &[u8]) {
        session.put(path, data, data.len() as u64).unwrap();
    }

    fn get_bytes(session: &Session<local::Storage>, path: &str) -> Vec<u8> {
        let mut buf = Vec::new();

        session.get(path, &mut buf).unwrap();

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
        let mut session = session();
        let data = b"small data";

        put_bytes(&mut session, "notes/small.txt", data);

        assert_eq!(get_bytes(&session, "notes/small.txt"), data);
    }

    #[test]
    fn put_get_large_data_roundtrip() {
        let mut session = session();
        let data = [
            vec![0xAAu8; CHUNK_SIZE],
            vec![0xBBu8; CHUNK_SIZE],
            vec![0xCCu8; CHUNK_SIZE / 2],
        ]
        .concat();

        put_bytes(&mut session, "large", &data);

        let blobs = session.storage.list_blobs().unwrap().len();

        assert_eq!(blobs, 3); // 3 data blobs
        assert_eq!(get_bytes(&session, "large"), data);
    }

    #[test]
    fn per_user_per_chunk_deduplication() {
        let mut session = session();
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

        put_bytes(&mut session, "file1", &data1);

        let blobs_after_first = session.storage.list_blobs().unwrap().len();

        put_bytes(&mut session, "file2", &data2);

        let blobs_after_second = session.storage.list_blobs().unwrap().len();

        assert_eq!(blobs_after_second, blobs_after_first + 1); // Only one new chunk
        assert_eq!(get_bytes(&session, "file1"), data1);
        assert_eq!(get_bytes(&session, "file2"), data2);
    }

    #[test]
    fn deduplicate_chunks() {
        let mut session = session();
        let data = [
            vec![0xAAu8; chunk::CHUNK_SIZE],
            vec![0xAAu8; chunk::CHUNK_SIZE],
            vec![0xBBu8; chunk::CHUNK_SIZE / 2],
        ]
        .concat();

        put_bytes(&mut session, "large", &data);

        let blobs = session.storage.list_blobs().unwrap().len();

        assert_eq!(blobs, 2); // The file has 3 blobs but 2 are identical
        assert_eq!(get_bytes(&session, "large"), data);
    }

    #[test]
    fn put_get_empty_file_roundtrip() {
        let mut session = session();

        put_bytes(&mut session, "notes/empty.txt", b"");

        assert_eq!(get_bytes(&session, "notes/empty.txt"), b"");
    }

    #[test]
    fn get_version() {
        let mut session = session();

        put_bytes(&mut session, "file", b"first");
        put_bytes(&mut session, "file", b"second");
        put_bytes(&mut session, "file", b"third");

        // Versions: [0 = "first", 1 = "second"], active = "third"
        let mut buf = Vec::new();

        session.get_version("file", 0, &mut buf).unwrap();

        assert_eq!(buf, b"first");

        let mut buf = Vec::new();

        session.get_version("file", 1, &mut buf).unwrap();

        assert_eq!(buf, b"second");
    }

    #[test]
    fn get_version_not_found() {
        let mut session = session();

        put_bytes(&mut session, "file", b"only one version");

        // No previous versions exist yet
        let mut buf = Vec::new();
        let result = session.get_version("file", 0, &mut buf);

        assert!(matches!(result, Err(Error::VersionNotFound)));
    }

    #[test]
    fn overwrite() {
        let mut session = session();

        put_bytes(&mut session, "file", b"version one");
        put_bytes(&mut session, "file", b"version two");

        // Data in path is overwritten, but the old version is kept until dropped
        assert_eq!(get_bytes(&session, "file"), b"version two");
    }

    #[test]
    fn overwrite_creates_version() {
        let mut session = session();

        put_bytes(&mut session, "file", b"version one");
        put_bytes(&mut session, "file", b"version two");

        // Active content is the latest
        assert_eq!(get_bytes(&session, "file"), b"version two");

        // One previous version was created
        let versions = session.versions("file").unwrap();

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].size, b"version one".len() as u64);
    }

    #[test]
    fn overwrite_no_unreferenced_chunks() {
        let mut session = session();

        put_bytes(&mut session, "file", b"version one");

        let blobs_after_first = session.storage.list_blobs().unwrap().len();

        put_bytes(&mut session, "file", b"version two");

        let blobs_after_second = session.storage.list_blobs().unwrap().len();

        // A new chunk was added, nothing was removed
        assert!(blobs_after_second > blobs_after_first);
        assert_eq!(blobs_after_second, blobs_after_first + 1);
    }

    #[test]
    fn overwrite_same_content_no_new_chunks() {
        let mut session = session();

        put_bytes(&mut session, "file", b"same content");

        let blobs_after_first = session.storage.list_blobs().unwrap().len();

        put_bytes(&mut session, "file", b"same content");

        let blobs_after_second = session.storage.list_blobs().unwrap().len();

        // Identical content, no new chunk written
        assert_eq!(blobs_after_first, blobs_after_second);

        // No-op, no new version recorded
        assert_eq!(session.versions("file").unwrap().len(), 0);
    }

    #[test]
    fn multiple_overwrites_accumulate_versions() {
        let mut session = session();

        put_bytes(&mut session, "file", b"v1");
        put_bytes(&mut session, "file", b"v2");
        put_bytes(&mut session, "file", b"v3");

        assert_eq!(get_bytes(&session, "file"), b"v3");
        assert_eq!(session.versions("file").unwrap().len(), 2);
    }

    #[test]
    fn revert() {
        let mut session = session();

        put_bytes(&mut session, "file", b"original");
        put_bytes(&mut session, "file", b"overwritten");

        // Revert to index 0 ("original")
        session.revert("file", 0).unwrap();

        assert_eq!(get_bytes(&session, "file"), b"original");
    }

    #[test]
    fn revert_preserves_full_history() {
        let mut session = session();

        put_bytes(&mut session, "file", b"v1");
        put_bytes(&mut session, "file", b"v2");

        // Before revert: versions = ["v1"], active = "v2"
        session.revert("file", 0).unwrap();

        // After revert: active = "v1", versions = ["v2"]
        assert_eq!(get_bytes(&session, "file"), b"v1");

        let versions = session.versions("file").unwrap();

        assert_eq!(versions.len(), 1);

        let mut buf = Vec::new();

        session.get_version("file", 0, &mut buf).unwrap();

        assert_eq!(buf, b"v2");
    }

    #[test]
    fn revert_version_not_found() {
        let mut session = session();

        put_bytes(&mut session, "file", b"data");

        assert!(matches!(
            session.revert("file", 0),
            Err(Error::VersionNotFound)
        ));
    }

    #[test]
    fn drop_version() {
        let mut session = session();

        put_bytes(&mut session, "file", b"old content");
        put_bytes(&mut session, "file", b"new content");

        let blobs_before = session.storage.list_blobs().unwrap().len();

        session.drop_version("file", 0).unwrap();

        let blobs_after = session.storage.list_blobs().unwrap().len();

        // One chunk purged (the "old content" chunk)
        assert!(blobs_after < blobs_before);
        assert_eq!(session.versions("file").unwrap().len(), 0);
        assert_eq!(get_bytes(&session, "file"), b"new content");
    }

    #[test]
    fn drop_version_skips_shared_chunks() {
        let mut session = session();

        put_bytes(
            &mut session,
            "file",
            &[vec![0xAAu8; CHUNK_SIZE], vec![0xBBu8; CHUNK_SIZE]].concat(),
        );

        // Overwrite to create version
        put_bytes(&mut session, "file", &vec![0xBBu8; CHUNK_SIZE]);

        let blobs_before = session.storage.list_blobs().unwrap().len();

        session.drop_version("file", 0).unwrap();

        let blobs_after = session.storage.list_blobs().unwrap().len();

        // A Chunk is shared with the active version, must not be deleted
        // Only one chunk is purged (the unshared one)
        assert!(blobs_after < blobs_before);
        assert_eq!(get_bytes(&session, "file"), vec![0xBBu8; CHUNK_SIZE]);
    }

    #[test]
    fn drop_version_skips_shared_chunks_across_files() {
        let mut session = session();

        put_bytes(&mut session, "file1", &vec![0xAAu8; CHUNK_SIZE]);
        put_bytes(
            &mut session,
            "file2",
            &[vec![0xAAu8; CHUNK_SIZE], vec![0xBBu8; CHUNK_SIZE]].concat(),
        );

        // Overwrite file1 to create version
        put_bytes(&mut session, "file1", &vec![0xCCu8; CHUNK_SIZE]);

        let blobs_before = session.storage.list_blobs().unwrap().len();

        session.drop_version("file1", 0).unwrap();

        let blobs_after = session.storage.list_blobs().unwrap().len();

        // Chunk is shared with the active version, must not be deleted
        assert_eq!(blobs_before, blobs_after);
        assert_eq!(get_bytes(&session, "file1"), vec![0xCCu8; CHUNK_SIZE]);
    }

    #[test]
    fn drop_version_not_found() {
        let mut session = session();

        put_bytes(&mut session, "file", b"data");

        assert!(matches!(
            session.drop_version("file", 0),
            Err(Error::VersionNotFound)
        ));
    }

    #[test]
    fn drop_current() {
        let mut session = session();

        put_bytes(&mut session, "file", b"v1");
        put_bytes(&mut session, "file", b"v2");

        let blobs_before = session.storage.list_blobs().unwrap().len();

        session.drop_version_current("file").unwrap();

        let blobs_after = session.storage.list_blobs().unwrap().len();

        // v2 chunk was purged
        assert!(blobs_after < blobs_before);

        // v1 is now active
        assert_eq!(get_bytes(&session, "file"), b"v1");
        assert_eq!(session.versions("file").unwrap().len(), 0);
    }

    #[test]
    fn drop_current_no_versions_deletes_file() {
        let mut session = session();

        put_bytes(&mut session, "file", b"data");

        session.drop_version_current("file").unwrap();

        assert!(matches!(
            session.get("file", &mut Vec::new()),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn detach_version() {
        let mut session = session();

        put_bytes(&mut session, "file", b"original");
        put_bytes(&mut session, "file", b"accidentally overwritten");

        session.detach_version("file", 0, "original").unwrap();

        assert_eq!(get_bytes(&session, "original"), b"original");
        assert_eq!(get_bytes(&session, "file"), b"accidentally overwritten");
    }

    #[test]
    fn detach_version_removes_from_source_history() {
        let mut session = session();

        put_bytes(&mut session, "file", b"v1");
        put_bytes(&mut session, "file", b"v2");

        session.detach_version("file", 0, "file_v1").unwrap();

        // Version was removed from source
        assert_eq!(session.versions("file").unwrap().len(), 0);

        // Detached entry has no history of its own
        assert_eq!(session.versions("file_v1").unwrap().len(), 0);

        // Both paths are independently readable
        assert_eq!(get_bytes(&session, "file"), b"v2");
        assert_eq!(get_bytes(&session, "file_v1"), b"v1");
    }

    #[test]
    fn detach_version_no_chunk_duplication() {
        let mut session = session();

        put_bytes(&mut session, "file", b"shared data");
        put_bytes(&mut session, "file", b"other data");

        let blobs_before = session.storage.list_blobs().unwrap().len();

        // Detach just references existing chunks, no new blobs written
        session.detach_version("file", 0, "detached").unwrap();

        let blobs_after = session.storage.list_blobs().unwrap().len();

        assert_eq!(blobs_before, blobs_after);
    }

    #[test]
    fn detach_version_not_found() {
        let mut session = session();

        put_bytes(&mut session, "file", b"data");

        assert!(matches!(
            session.detach_version("file", 0, "new"),
            Err(Error::VersionNotFound)
        ));
    }

    #[test]
    fn detach_current() {
        let mut session = session();

        put_bytes(&mut session, "file", b"v1");
        put_bytes(&mut session, "file", b"v2");

        session.detach_version_current("file", "file_v2").unwrap();

        assert_eq!(get_bytes(&session, "file_v2"), b"v2");
        assert_eq!(get_bytes(&session, "file"), b"v1");
        assert_eq!(session.versions("file").unwrap().len(), 0);
        assert_eq!(session.versions("file_v2").unwrap().len(), 0);
    }

    #[test]
    fn detach_current_no_versions_is_rename() {
        let mut session = session();

        put_bytes(&mut session, "file", b"data");

        session.detach_version_current("file", "renamed").unwrap();

        assert_eq!(get_bytes(&session, "renamed"), b"data");
        assert!(matches!(
            session.get("file", &mut Vec::new()),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn rename() {
        let mut session = session();

        put_bytes(&mut session, "old/file", b"data");

        session.rename("old/file", "new/file").unwrap();

        assert_eq!(get_bytes(&session, "new/file"), b"data");
    }

    #[test]
    fn trash() {
        let mut session = session();

        put_bytes(&mut session, "file.txt", b"data");

        session.trash("file.txt").unwrap();

        assert!(session.list().is_empty());
        assert!(!session.storage.list_blobs().unwrap().is_empty());
        assert_eq!(session.list_trash(), vec!["file.txt"]);
    }

    #[test]
    fn restore() {
        let mut session = session();

        put_bytes(&mut session, "file.txt", b"data");

        session.trash("file.txt").unwrap();
        session.restore("file.txt").unwrap();

        assert_eq!(get_bytes(&session, "file.txt"), b"data");
        assert!(session.list_trash().is_empty());
    }

    #[test]
    fn purge() {
        let mut session = session();

        put_bytes(&mut session, "1.txt", b"keep this");
        put_bytes(&mut session, "2.txt", b"delete this");

        session.trash("2.txt").unwrap();

        let blobs_before_purge = session.storage.list_blobs().unwrap().len();

        session.purge("2.txt").unwrap();

        assert!(session.list_trash().is_empty());
        assert!(session.storage.list_blobs().unwrap().len() < blobs_before_purge);
        assert_eq!(get_bytes(&session, "1.txt"), b"keep this");
    }

    #[test]
    fn purge_all_version_chunks() {
        let mut session = session();

        put_bytes(&mut session, "file1", b"keep this");
        put_bytes(&mut session, "file2", b"delete v1");
        put_bytes(&mut session, "file2", b"delete v2");

        session.trash("file2").unwrap();

        let blobs_before = session.storage.list_blobs().unwrap().len();

        session.purge("file2").unwrap();

        let blobs_after = session.storage.list_blobs().unwrap().len();

        // Both v1 and v2 chunks of file2 should be purged
        assert_eq!(blobs_before, blobs_after + 2);
        assert_eq!(get_bytes(&session, "file1"), b"keep this");
    }

    #[test]
    fn cleanup() {
        let mut session = session();

        put_bytes(&mut session, "1.txt", b"data 1");
        put_bytes(&mut session, "2.txt", b"data 2");

        session.trash("1.txt").unwrap();
        session.trash("2.txt").unwrap();

        let removed = session.cleanup().unwrap();

        assert_eq!(removed, 2); // 1 chunk each
        assert!(session.list_trash().is_empty());
        assert!(session.list().is_empty());
    }

    #[test]
    fn cleanup_purges_all_version_chunks() {
        let mut session = session();

        put_bytes(&mut session, "file", b"v1");
        put_bytes(&mut session, "file", b"v2");
        put_bytes(&mut session, "file", b"v3");

        session.trash("file").unwrap();

        session.cleanup().unwrap();

        assert_eq!(session.storage.list_blobs().unwrap().len(), 0);
        assert!(session.list().is_empty());
    }

    #[test]
    fn delete() {
        let mut session = session();

        put_bytes(&mut session, "file.txt", b"data");

        session.delete("file.txt").unwrap();

        assert!(session.list_trash().is_empty());

        // file is permanently removed and cannot be restored
        assert!(session.restore("file.txt").is_err());
    }

    #[test]
    fn only_uploads_changed_chunks() {
        let mut session = session();

        let chunk_a = vec![0xAAu8; CHUNK_SIZE];
        let chunk_b = vec![0xBBu8; CHUNK_SIZE];
        let original: Vec<u8> = [chunk_a.clone(), chunk_b].concat();

        put_bytes(&mut session, "file", &original);

        let blobs_after_first = session.storage.list_blobs().unwrap().len();

        // Since `chunk_a` is identical, it should not be re-uploaded
        let chunk_b2 = vec![0xCCu8; CHUNK_SIZE];
        let updated: Vec<u8> = [chunk_a, chunk_b2].concat();

        put_bytes(&mut session, "file", &updated);

        let blobs_after_second = session.storage.list_blobs().unwrap().len();

        // `chunk_a` already exists, therefore it's skipped and we'd only have 1 new blob
        assert_eq!(blobs_after_second, blobs_after_first + 1);
    }

    #[test]
    fn not_found() {
        let session = session();
        let mut buf = Vec::new();

        let got = session.get("nonexistent.txt", &mut buf);

        assert!(matches!(got, Err(Error::NotFound)));
    }

    #[test]
    fn delete_not_found() {
        let mut session = session();
        let deleted = session.delete("nonexistent.txt");

        assert!(matches!(deleted, Err(Error::NotFound)));
    }

    #[test]
    fn persistent_data_across_sessions() {
        let path = temp_storage_path("persistent");
        let words = make_words();

        {
            let identity = make_identity(&words);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut session = Session::new(identity, storage).unwrap();

            put_bytes(&mut session, "persistant.txt", b"persistent data");
        }

        {
            let identity = make_identity(&words);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let session = Session::new(identity, storage).unwrap();

            assert_eq!(get_bytes(&session, "persistant.txt"), b"persistent data");
        }
    }

    #[test]
    fn verify_all() {
        let mut session = session();

        put_bytes(&mut session, "file1", b"clean data");
        put_bytes(&mut session, "file2", b"more clean data");

        assert!(session.verify_all().is_empty());
    }

    #[test]
    fn verify_all_empty_vault() {
        let session = session();

        assert!(session.verify_all().is_empty());
    }

    #[test]
    fn verify_all_tampered_chunk() {
        let path = temp_storage_path("verify_all_tampered_chunk");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut session = Session::new(identity, storage).unwrap();

        put_bytes(&mut session, "file", b"important data");

        let entry = session.manifest.entries.get("file").unwrap();
        let address = entry.chunks[0].address;
        let mut blob = session.storage.get_blob(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, &address, &blob);

        let tampared = session.verify_all();

        assert!(tampared.contains(&"file".into()));
    }

    #[test]
    fn verify_all_tampered_error() {
        let path = temp_storage_path("verify_all_tampered_error");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut session = Session::new(identity, storage).unwrap();

        put_bytes(&mut session, "secret.txt", b"secret");

        let entry = session.manifest.entries.get("secret.txt").unwrap();
        let address = entry.chunks[0].address;
        let mut blob = session.storage.get_blob(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, &address, &blob);

        let mut buf = Vec::new();
        let result = session.get("secret.txt", &mut buf);

        assert!(matches!(result, Err(Error::Tampered(_))));
    }

    #[test]
    fn verify_all_includes_trashed_entries() {
        let path = temp_storage_path("verify_trashed");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut session = Session::new(identity, storage).unwrap();

        put_bytes(&mut session, "trashed.txt", b"will be trashed");

        session.trash("trashed.txt").unwrap();

        // Corrupt the trashed chunk
        let entry = session.manifest.entries.get("trashed.txt").unwrap();
        let address = entry.chunks[0].address;
        let mut blob = session.storage.get_blob(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, &address, &blob);

        let tampared = session.verify_all();

        assert!(tampared.contains(&"trashed.txt".into()));
    }

    #[test]
    fn verify_all_deduplicates_multi_chunk_path() {
        let path = temp_storage_path("verify_dedup");
        let words = make_words();
        let identity = make_identity(&words);
        let public_signing_key = identity.public_signing_key();
        let storage = local::Storage::new(&path, &public_signing_key).unwrap();
        let mut session = Session::new(identity, storage).unwrap();
        let data = [vec![0xAAu8; CHUNK_SIZE], vec![0xBBu8; CHUNK_SIZE]].concat();

        put_bytes(&mut session, "large", &data);

        // Corrupt both chunks
        let entry = session.manifest.entries.get("large").unwrap();
        let chunks = &entry.chunks;

        for chunk in chunks {
            let mut blob = session.storage.get_blob(&chunk.address).unwrap();

            blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

            overwrite_bytes(&path, &public_signing_key, &chunk.address, &blob);
        }

        let tampared = session.verify_all();

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
        let mut session = Session::new(identity, storage).unwrap();

        put_bytes(&mut session, "file1", b"shared content");
        put_bytes(&mut session, "file2", b"shared content");

        let entry = session.manifest.entries.get("file1").unwrap();
        let address = entry.chunks[0].address;
        let mut blob = session.storage.get_blob(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, &address, &blob);

        let tampared = session.verify_all();

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
        let mut session = Session::new(identity, storage).unwrap();

        put_bytes(&mut session, "file", b"v0");
        put_bytes(&mut session, "file", b"v1");
        put_bytes(&mut session, "file", b"v2");

        // Corrupt the v1 (previous version) chunk
        let entry = session.manifest.entries.get("file").unwrap();
        let address = entry.versions[0].chunks[0].address; // Version 1
        let mut blob = session.storage.get_blob(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        overwrite_bytes(&path, &public_signing_key, &address, &blob);

        let tampered = session.verify_all();

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
            let mut session = Session::new(identity, storage).unwrap();

            put_bytes(&mut session, "user1.txt", b"this data belongs to user 1");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let session = Session::new(identity, storage).unwrap();
            let mut buf = Vec::new();

            // User2 cannot access user1's data
            assert!(session.get("user1.txt", &mut buf).is_err());
        }
    }

    #[test]
    fn same_file_same_path_same_user() {
        let mut session = session();

        put_bytes(&mut session, "file", b"same content");

        let blobs_after_first = session.storage.list_blobs().unwrap().len();

        // Basically a no-op
        put_bytes(&mut session, "file", b"same content");

        let blobs_after_second = session.storage.list_blobs().unwrap().len();

        assert_eq!(blobs_after_first, blobs_after_second);
        assert_eq!(get_bytes(&session, "file"), b"same content");
    }

    #[test]
    fn same_file_different_paths_same_user() {
        let mut session = session();

        put_bytes(&mut session, "file1", b"same content");

        let blobs_after_first = session.storage.list_blobs().unwrap().len();

        put_bytes(&mut session, "file2", b"same content");

        let blobs_after_second = session.storage.list_blobs().unwrap().len();

        assert_eq!(blobs_after_first, blobs_after_second);
        assert_eq!(get_bytes(&session, "file1"), get_bytes(&session, "file2"));
    }

    #[test]
    fn different_files_same_path_same_user() {
        let mut session = session();

        put_bytes(&mut session, "file", b"content");

        let blobs_after_first = session.storage.list_blobs().unwrap().len();

        put_bytes(&mut session, "file", b"different content");

        let blobs_after_second = session.storage.list_blobs().unwrap().len();

        // No unreferenced chunks, the old chunks are in a separate version
        assert!(blobs_after_second > blobs_after_first);
        assert_eq!(get_bytes(&session, "file"), b"different content");

        session.drop_version("file", 0).unwrap();

        let blobs_after_version_drop = session.storage.list_blobs().unwrap().len();

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
            let mut session = Session::new(identity, storage).unwrap();

            put_bytes(&mut session, "file", b"same content");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut session = Session::new(identity, storage).unwrap();

            put_bytes(&mut session, "file", b"same content");
        }

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let session = Session::new(identity, storage).unwrap();

            assert_eq!(get_bytes(&session, "file"), b"same content");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let session = Session::new(identity, storage).unwrap();

            assert_eq!(get_bytes(&session, "file"), b"same content");
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
            let mut session = Session::new(identity, storage).unwrap();

            put_bytes(&mut session, "file1", b"same content");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut session = Session::new(identity, storage).unwrap();

            put_bytes(&mut session, "file2", b"same content");
        }

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let session = Session::new(identity, storage).unwrap();

            assert_eq!(get_bytes(&session, "file1"), b"same content");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let session = Session::new(identity, storage).unwrap();

            assert_eq!(get_bytes(&session, "file2"), b"same content");
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
            let mut session = Session::new(identity, storage).unwrap();

            put_bytes(&mut session, "file", b"different content 1");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let mut session = Session::new(identity, storage).unwrap();

            put_bytes(&mut session, "file", b"different content 2");
        }

        {
            let identity = make_identity(&words1);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let session = Session::new(identity, storage).unwrap();

            assert_eq!(get_bytes(&session, "file"), b"different content 1");
        }

        {
            let identity = make_identity(&words2);
            let storage = local::Storage::new(&path, &identity.public_signing_key()).unwrap();
            let session = Session::new(identity, storage).unwrap();

            assert_eq!(get_bytes(&session, "file"), b"different content 2");
        }
    }
}
