use gate::{
    crypto::blake3,
    sys::{
        io,
        string::String,
        time::{SystemTime, UNIX_EPOCH},
        vec::Vec,
    },
};

use crate::{
    crypto::{cipher, identity::Identity},
    storage::{
        self,
        chunk::{self, Chunks},
        manifest::{self, Manifest, Properties},
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
            Error::Io(e) => write!(f, "I/O: {}", e),
            Self::NotFound => write!(f, "file not found"),
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

impl From<manifest::Error> for Error {
    fn from(value: manifest::Error) -> Self {
        match value {
            manifest::Error::NotFound => Self::NotFound,
            manifest::Error::NotTrashed => Self::NotTrashed,
            manifest::Error::AlreadyTrashed => Self::AlreadyTrashed,
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
        let manifest_key = Manifest::address(&identity.public_key_bytes());
        let manifest = match storage.get(&manifest_key) {
            Ok(blob) => Manifest::unlock(
                &blob,
                &identity.encryption_key,
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

    pub fn put(
        &mut self,
        path: &str,
        mut reader: impl io::Read + io::Seek,
        size: u64,
    ) -> Result<usize, Error> {
        // NOTE: I don't really like this two-pass design:
        // The goal was to have a single-pass streaming, full per-user dedup,
        // and a no-re-encryption sharing `put()` method.
        // But with per-file encryption key, I couldn't find a better way to have them all.
        // The single-pass approach I originally had (https://github.com/IrregularCelery/vault/commit/0db9b73)
        // had a big issue with test `same_file_different_paths_same_user`.
        // When uploading a file that had identical chunks to what the user already had,
        // re-uploading those chunks would be skipped, but a different PFK was stored for the entry.
        // Therefore, the latter file couldn't be decrypted.

        let hashes = {
            let mut chunks = Chunks::new(&mut reader);
            let mut hashes = Vec::new();

            while let Some(chunk) = chunks.next_chunk()? {
                // Addressed by identity key (not PFK) to preserve per-user chunk deduplication
                let hash = chunk.address(&self.identity.encryption_key);

                hashes.push(hash);
            }

            hashes
        };

        let mut hasher = blake3::Hasher::new();

        for hash in &hashes {
            hasher.update(hash);
        }

        let pfk = Manifest::derive_pfk(&self.identity.encryption_key, &hasher.finalize().into());
        let encrypted_pfk = Manifest::encrypt_pfk(&pfk, &self.identity.encryption_key)?;

        reader.seek(io::SeekFrom::Start(0)).map_err(Error::Io)?;

        {
            let mut chunks = Chunks::new(&mut reader);

            for hash in &hashes {
                let chunk = chunks.next_chunk()?.ok_or(chunk::Error::UnexpectedEof)?;

                // Redundant check but we keep it in case a storage::Backend::put() didn't do the check
                // though not entirely useless since we can avoid calling cipher::encrypt()
                if !self.storage.exists(hash)? {
                    let encrypted =
                        cipher::lock(&pfk, chunk.data, |message| self.identity.sign(message))?;

                    self.storage.put(hash, &encrypted)?;
                }
            }
        }

        let chunk_count = hashes.len();

        // TODO: Handle unreferenced chunks on overwrite.
        // For now, if an entry already exists, `put()` overwrites the manifest silently
        // and leaves the old chunks unreferenced.
        self.manifest.insert(
            path,
            manifest::Entry {
                encrypted_pfk,
                addresses: hashes,
                size,
                modified: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                trashed: 0,
            },
        );
        self.flush_manifest()?;

        Ok(chunk_count)
    }

    pub fn get(&self, path: &str, writer: &mut impl io::Write) -> Result<u64, Error> {
        let entry = self.manifest.get(path).ok_or(Error::NotFound)?;
        let pfk = Manifest::decrypt_pfk(&entry.encrypted_pfk, &self.identity.encryption_key)?;
        let mut size = 0u64;

        for address in &entry.addresses {
            let blob = self.storage.get(address)?;
            let plaintext = cipher::unlock(&pfk, &blob, |message, signature_bytes| {
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
            self.storage.delete(address)?;
        }

        self.flush_manifest()?;

        Ok(())
    }

    pub fn cleanup(&mut self) -> Result<usize, Error> {
        let addresses = self.manifest.purge_all();
        let removed = addresses.len();

        for address in &addresses {
            self.storage.delete(address)?;
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
            size: e.size,
            chunk_count: e.addresses.len(),
            modified: e.modified,
            trashed: e.trashed,
        })
    }

    pub fn verify(&self, path: &str) -> Result<(), Error> {
        // Direct `entries` get instead of `self.manifest.get()` so the trashed entries are included
        let entry = self.manifest.entries.get(path).ok_or(Error::NotFound)?;

        self.verify_entry(path, entry)
    }

    pub fn verify_all(&self) -> Vec<String> {
        let mut tampered = Vec::new();
        let manifest_hash = Manifest::address(&self.identity.public_key_bytes());

        // Check the manifest blob itself
        if let Ok(blob) = self.storage.get(&manifest_hash)
            && Manifest::unlock(
                &blob,
                &self.identity.encryption_key,
                |message, signature_bytes| self.identity.verify(message, signature_bytes),
            )
            .is_err()
        {
            tampered.push("manifest".into());
        }

        for (path, entry) in &self.manifest.entries {
            if self.verify_entry(path, entry).is_err() {
                tampered.push(path.clone());
            }
        }

        tampered.sort();
        tampered.dedup();

        tampered
    }

    fn verify_entry(&self, path: &str, entry: &manifest::Entry) -> Result<(), Error> {
        let pfk = Manifest::decrypt_pfk(&entry.encrypted_pfk, &self.identity.encryption_key)?;

        for address in &entry.addresses {
            let blob = self.storage.get(address)?;

            cipher::unlock(&pfk, &blob, |message, signature_bytes| {
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
            .lock(&self.identity.encryption_key, |message| {
                self.identity.sign(message)
            })?;
        let hash = Manifest::address(&self.identity.public_key_bytes());

        self.storage.overwrite(&hash, &data)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use gate::sys::{
        env,
        macros::{format, vec},
        path::PathBuf,
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

    fn make_identity(phrase: &str) -> Identity {
        Identity::from_phrase(phrase).unwrap()
    }

    fn session() -> Session<local::Storage> {
        let path = temp_storage_path("");
        let storage = local::Storage::new(&path).unwrap();

        Session::new(
            make_identity(
                "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about",
            ),
            storage,
        )
        .unwrap()
    }

    fn put_bytes(session: &mut Session<local::Storage>, path: &str, data: &[u8]) {
        session
            .put(path, io::Cursor::new(data), data.len() as u64)
            .unwrap();
    }

    fn get_bytes(session: &Session<local::Storage>, path: &str) -> Vec<u8> {
        let mut buf = Vec::new();

        session.get(path, &mut buf).unwrap();

        buf
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

        let blobs = session.storage.list().unwrap().len();

        assert_eq!(blobs, 4); // 3 data blobs + 1 manifest blob
        assert_eq!(get_bytes(&session, "large"), data);
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

        let blobs = session.storage.list().unwrap().len();

        assert_eq!(blobs, 3); // The file has 3 blobs but two are identical, so 2 + 1 for manifest
        assert_eq!(get_bytes(&session, "large"), data);
    }

    #[test]
    fn put_get_empty_file_roundtrip() {
        let mut session = session();

        put_bytes(&mut session, "notes/empty.txt", b"");

        assert_eq!(get_bytes(&session, "notes/empty.txt"), b"");
    }

    #[ignore = "causes unreferenced chunks. see test `different_files_same_path_same_users`."]
    #[test]
    fn overwrite() {
        let mut session = session();

        put_bytes(&mut session, "file", b"version one");
        put_bytes(&mut session, "file", b"version two");

        assert_eq!(get_bytes(&session, "file"), b"version two");
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
        assert!(!session.storage.list().unwrap().is_empty());
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

        let blobs_before_purge = session.storage.list().unwrap().len();

        session.purge("2.txt").unwrap();

        assert!(session.list_trash().is_empty());
        assert!(session.storage.list().unwrap().len() < blobs_before_purge);
        assert_eq!(get_bytes(&session, "1.txt"), b"keep this");
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

        let blobs_after_first = session.storage.list().unwrap().len();

        // Since `chunk_a` is identical, it should not be re-uploaded
        let chunk_b2 = vec![0xCCu8; CHUNK_SIZE];
        let updated: Vec<u8> = [chunk_a, chunk_b2].concat();

        put_bytes(&mut session, "file", &updated);

        let blobs_after_second = session.storage.list().unwrap().len();

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
        let phrase = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon about";

        {
            let storage = local::Storage::new(&path).unwrap();
            let mut session = Session::new(make_identity(phrase), storage).unwrap();

            put_bytes(&mut session, "persistant.txt", b"persistent data");
        }

        {
            let storage = local::Storage::new(&path).unwrap();
            let session = Session::new(make_identity(phrase), storage).unwrap();

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
        let phrase = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon about";
        let storage = local::Storage::new(&path).unwrap();
        let mut session = Session::new(make_identity(phrase), storage).unwrap();

        put_bytes(&mut session, "file", b"important data");

        let entry = session.manifest.entries.get("file").unwrap();
        let address = entry.addresses[0];
        let mut blob = session.storage.get(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        session.storage.overwrite(&address, &blob).unwrap();

        let tampared = session.verify_all();

        assert!(tampared.contains(&"file".into()));
    }

    #[test]
    fn verify_all_tampered_error() {
        let path = temp_storage_path("verify_all_tampered_error");
        let phrase = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon about";
        let storage = local::Storage::new(&path).unwrap();
        let mut session = Session::new(make_identity(phrase), storage).unwrap();

        put_bytes(&mut session, "secret.txt", b"secret");

        let entry = session.manifest.entries.get("secret.txt").unwrap();
        let address = entry.addresses[0];
        let mut blob = session.storage.get(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        session.storage.overwrite(&address, &blob).unwrap();

        let mut buf = Vec::new();
        let result = session.get("secret.txt", &mut buf);

        assert!(matches!(result, Err(Error::Tampered(_))));
    }

    #[test]
    fn verify_all_includes_trashed_entries() {
        let path = temp_storage_path("verify_trashed");
        let phrase = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon about";
        let storage = local::Storage::new(&path).unwrap();
        let mut session = Session::new(make_identity(phrase), storage).unwrap();

        put_bytes(&mut session, "trashed.txt", b"will be trashed");

        session.trash("trashed.txt").unwrap();

        // Corrupt the trashed chunk
        let entry = session.manifest.entries.get("trashed.txt").unwrap();
        let address = entry.addresses[0];
        let mut blob = session.storage.get(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        session.storage.overwrite(&address, &blob).unwrap();

        let tampared = session.verify_all();

        assert!(tampared.contains(&"trashed.txt".into()));
    }

    #[test]
    fn verify_all_deduplicates_multi_chunk_path() {
        let path = temp_storage_path("verify_dedup");
        let phrase = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon about";
        let storage = local::Storage::new(&path).unwrap();
        let mut session = Session::new(make_identity(phrase), storage).unwrap();
        let data = [vec![0xAAu8; CHUNK_SIZE], vec![0xBBu8; CHUNK_SIZE]].concat();

        put_bytes(&mut session, "large", &data);

        // Corrupt both chunks
        let entry = session.manifest.entries.get("large").unwrap();
        let addresses = entry.addresses.clone();

        for address in &addresses {
            let mut blob = session.storage.get(address).unwrap();

            blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

            session.storage.overwrite(address, &blob).unwrap();
        }

        let tampared = session.verify_all();

        // Path should appear exactly once despite two tampared chunks
        assert_eq!(tampared.iter().filter(|p| p.as_str() == "large").count(), 1);
    }

    #[test]
    fn verify_all_shared_tampered_chunk() {
        let path = temp_storage_path("verify_shared_tampered");
        let phrase = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon about";
        let storage = local::Storage::new(&path).unwrap();
        let mut session = Session::new(make_identity(phrase), storage).unwrap();

        put_bytes(&mut session, "file1", b"shared content");
        put_bytes(&mut session, "file2", b"shared content");

        let entry = session.manifest.entries.get("file1").unwrap();
        let address = entry.addresses[0];
        let mut blob = session.storage.get(&address).unwrap();

        blob[65] ^= 0xFF; // Flip a bit inside the ciphertext region

        session.storage.overwrite(&address, &blob).unwrap();

        let tampared = session.verify_all();

        assert!(tampared.contains(&"file1".into()));
        assert!(tampared.contains(&"file2".into()));
    }

    #[test]
    fn wrong_key() {
        let path = temp_storage_path("wrongkey");
        let phrase1 = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon about";
        let phrase2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

        {
            let storage = local::Storage::new(&path).unwrap();
            let mut session = Session::new(make_identity(phrase1), storage).unwrap();

            put_bytes(&mut session, "user1.txt", b"this data belongs to user 1");
        }

        {
            let storage = local::Storage::new(&path).unwrap();
            let session = Session::new(make_identity(phrase2), storage).unwrap();
            let mut buf = Vec::new();

            // User2 cannot access user1's data
            assert!(session.get("user1.txt", &mut buf).is_err());
        }
    }

    #[test]
    fn same_file_same_path_same_user() {
        let mut session = session();

        put_bytes(&mut session, "file", b"same content");

        let blobs_after_first = session.storage.list().unwrap().len();

        // Basically a no-op
        put_bytes(&mut session, "file", b"same content");

        let blobs_after_second = session.storage.list().unwrap().len();

        assert_eq!(blobs_after_first, blobs_after_second);
        assert_eq!(get_bytes(&session, "file"), b"same content");
    }

    #[test]
    fn same_file_different_paths_same_user() {
        let mut session = session();

        put_bytes(&mut session, "file1", b"same content");

        let blobs_after_first = session.storage.list().unwrap().len();

        put_bytes(&mut session, "file2", b"same content");

        let blobs_after_second = session.storage.list().unwrap().len();

        assert_eq!(blobs_after_first, blobs_after_second);
        assert_eq!(get_bytes(&session, "file1"), get_bytes(&session, "file2"));
    }

    #[ignore = "causes unreferenced chunks."]
    #[test]
    fn different_files_same_path_same_user() {
        let mut session = session();

        put_bytes(&mut session, "file", b"content");

        let blobs_after_first = session.storage.list().unwrap().len();

        put_bytes(&mut session, "file", b"different content");

        let blobs_after_second = session.storage.list().unwrap().len();

        // TODO: This is currently true, but shouldn't be the case because it means there are
        // unreferenced chunks. see `Session::put()` `TODO` message.
        assert!(blobs_after_second > blobs_after_first);
        assert_eq!(get_bytes(&session, "file"), b"different content");
    }

    #[test]
    fn same_file_same_path_different_users() {
        let path = temp_storage_path("same_file_same_path_different_users");
        let phrase1 = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon about";
        let phrase2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

        {
            let storage = local::Storage::new(&path).unwrap();
            let mut session = Session::new(make_identity(phrase1), storage).unwrap();

            put_bytes(&mut session, "file", b"same content");
        }

        {
            let storage = local::Storage::new(&path).unwrap();
            let mut session = Session::new(make_identity(phrase2), storage).unwrap();

            put_bytes(&mut session, "file", b"same content");
        }

        {
            let storage = local::Storage::new(&path).unwrap();
            let session = Session::new(make_identity(phrase1), storage).unwrap();

            assert_eq!(get_bytes(&session, "file"), b"same content");
        }

        {
            let storage = local::Storage::new(&path).unwrap();
            let session = Session::new(make_identity(phrase2), storage).unwrap();

            assert_eq!(get_bytes(&session, "file"), b"same content");
        }
    }

    #[test]
    fn same_file_different_paths_different_users() {
        let path = temp_storage_path("same_file_different_paths_different_users");
        let phrase1 = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon about";
        let phrase2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

        {
            let storage = local::Storage::new(&path).unwrap();
            let mut session = Session::new(make_identity(phrase1), storage).unwrap();

            put_bytes(&mut session, "file1", b"same content");
        }

        {
            let storage = local::Storage::new(&path).unwrap();
            let mut session = Session::new(make_identity(phrase2), storage).unwrap();

            put_bytes(&mut session, "file2", b"same content");
        }

        {
            let storage = local::Storage::new(&path).unwrap();
            let session = Session::new(make_identity(phrase1), storage).unwrap();

            assert_eq!(get_bytes(&session, "file1"), b"same content");
        }

        {
            let storage = local::Storage::new(&path).unwrap();
            let session = Session::new(make_identity(phrase2), storage).unwrap();

            assert_eq!(get_bytes(&session, "file2"), b"same content");
        }
    }

    #[test]
    fn different_files_same_path_different_users() {
        let path = temp_storage_path("different_files_same_path_different_users");
        let phrase1 = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon about";
        let phrase2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

        {
            let storage = local::Storage::new(&path).unwrap();
            let mut session = Session::new(make_identity(phrase1), storage).unwrap();

            put_bytes(&mut session, "file", b"different content 1");
        }

        {
            let storage = local::Storage::new(&path).unwrap();
            let mut session = Session::new(make_identity(phrase2), storage).unwrap();

            put_bytes(&mut session, "file", b"different content 2");
        }

        {
            let storage = local::Storage::new(&path).unwrap();
            let session = Session::new(make_identity(phrase1), storage).unwrap();

            assert_eq!(get_bytes(&session, "file"), b"different content 1");
        }

        {
            let storage = local::Storage::new(&path).unwrap();
            let session = Session::new(make_identity(phrase2), storage).unwrap();

            assert_eq!(get_bytes(&session, "file"), b"different content 2");
        }
    }
}
