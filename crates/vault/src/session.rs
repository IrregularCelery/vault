use gate::sys::{
    io,
    string::{String, ToString},
    time::{SystemTime, UNIX_EPOCH},
    vec::Vec,
};

use crate::{
    crypto::{cipher, identity::Identity},
    storage::{
        self,
        chunk::{self, Chunks},
        index::{self, Index},
    },
};

#[derive(Debug)]
pub enum Error {
    Storage(storage::Error),
    Cipher(cipher::Error),
    Chunk(chunk::Error),
    Index(index::Error),
    NotFound,
    NotTrashed,
    AlreadyTrashed,
    Other(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage: {}", e),
            Self::Cipher(e) => write!(f, "cipher: {}", e),
            Self::Chunk(e) => write!(f, "chunk: {}", e),
            Self::Index(e) => write!(f, "index: {}", e),
            Self::NotFound => write!(f, "file not found"),
            Self::NotTrashed => write!(f, "file is not in the trash"),
            Self::AlreadyTrashed => write!(f, "file is already in the trash"),
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
        Self::Cipher(value)
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
            index::Error::NotTrashed => Self::NotTrashed,
            index::Error::AlreadyTrashed => Self::AlreadyTrashed,
            other => Self::Index(other),
        }
    }
}

pub struct Session<S: storage::Backend> {
    identity: Identity,
    storage: S,
    index: Index,
}

impl<S: storage::Backend> Session<S> {
    pub fn new(identity: Identity, storage: S) -> Result<Self, Error> {
        let index_key = Index::address(&identity.public_key_bytes());
        let index = match storage.get(&index_key) {
            Ok(blob) => Index::unlock(&blob, &identity.encryption_key)?,
            Err(storage::Error::NotFound) => Index::new(),
            Err(e) => return Err(Error::Storage(e)),
        };

        Ok(Self {
            identity,
            storage,
            index,
        })
    }

    pub fn put(&mut self, path: &str, reader: impl io::Read, size: u64) -> Result<usize, Error> {
        let mut chunks = Chunks::new(reader);
        let mut hashes = Vec::new();

        while let Some(chunk) = chunks.next_chunk()? {
            let hash = chunk.address(&self.identity.encryption_key);

            hashes.push(hash);

            // Redundant check but we keep it in case a storage::Backend::put() didn't do the check
            // though not entirely useless since we can avoid calling cipher::encrypt()
            if !self.storage.exists(&hash)? {
                let encrypted = cipher::encrypt(&self.identity.encryption_key, chunk.data)?;

                self.storage.put(&hash, &encrypted)?;
            }
        }

        let chunk_count = hashes.len();

        self.index.insert(
            path,
            index::Entry {
                addresses: hashes,
                size,
                modified: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                trashed: 0,
            },
        );

        self.flush_index()?;

        Ok(chunk_count)
    }

    pub fn get(&self, path: &str, writer: &mut impl io::Write) -> Result<u64, Error> {
        let entry = self.index.get(path).ok_or(Error::NotFound)?;
        let mut size = 0u64;

        for address in &entry.addresses {
            let blob = self.storage.get(address)?;
            let plaintext = cipher::decrypt(&self.identity.encryption_key, &blob)?;

            writer
                .write_all(&plaintext)
                .map_err(|e| Error::Other(e.to_string()))?;

            size += plaintext.len() as u64;
        }

        Ok(size)
    }

    pub fn trash(&mut self, path: &str) -> Result<(), Error> {
        self.index.trash(path)?;
        self.flush_index()?;

        Ok(())
    }

    pub fn restore(&mut self, path: &str) -> Result<(), Error> {
        self.index.restore(path)?;
        self.flush_index()?;

        Ok(())
    }

    pub fn purge(&mut self, path: &str) -> Result<(), Error> {
        let addresses = self.index.purge(path)?;
        // Could be a "Not a trashed entry, skipped" Fix this.

        for address in &addresses {
            self.storage.delete(address)?;
        }

        self.flush_index()?;

        Ok(())
    }

    pub fn purge_all(&mut self) -> Result<usize, Error> {
        let addresses = self.index.purge_all();
        let removed = addresses.len();

        for address in &addresses {
            self.storage.delete(address)?;
        }

        self.flush_index()?;

        Ok(removed)
    }

    pub fn delete(&mut self, path: &str) -> Result<(), Error> {
        self.trash(path)?;
        self.purge(path)?;

        Ok(())
    }

    pub fn list(&self) -> Vec<&str> {
        let mut paths: Vec<&str> = self
            .index
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
            .index
            .entries
            .iter()
            .filter(|(_, v)| v.trashed != 0)
            .map(|(k, _)| k.as_str())
            .collect();

        paths.sort();

        paths
    }

    fn flush_index(&self) -> Result<(), Error> {
        let data = self.index.lock(&self.identity.encryption_key)?;
        let hash = Index::address(&self.identity.public_key_bytes());

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
        session.put(path, data, data.len() as u64).unwrap();
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
        let data: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 2 + 500_000).collect();

        put_bytes(&mut session, "large", &data);

        let blobs = session.storage.list().unwrap().len();

        assert_eq!(blobs, 3);
        assert_eq!(get_bytes(&session, "large"), data);
    }

    #[test]
    fn put_get_empty_file_roundtrip() {
        let mut session = session();

        put_bytes(&mut session, "notes/empty.txt", b"");

        assert_eq!(get_bytes(&session, "notes/empty.txt"), b"");
    }

    #[test]
    fn overwrite() {
        let mut session = session();

        put_bytes(&mut session, "file", b"version one");
        put_bytes(&mut session, "file", b"version two");

        assert_eq!(get_bytes(&session, "file"), b"version two");
    }

    #[test]
    fn same_data_shares_chunks() {
        let mut session = session();

        put_bytes(&mut session, "file1", b"same content");

        let blobs_after_first = session.storage.list().unwrap().len();

        put_bytes(&mut session, "file2", b"same content");

        let blobs_after_second = session.storage.list().unwrap().len();

        assert_eq!(blobs_after_first, blobs_after_second);
        assert_eq!(get_bytes(&session, "file1"), get_bytes(&session, "file2"));
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
    fn purge_all() {
        let mut session = session();

        put_bytes(&mut session, "1.txt", b"data 1");
        put_bytes(&mut session, "2.txt", b"data 2");

        session.trash("1.txt").unwrap();
        session.trash("2.txt").unwrap();

        let removed = session.purge_all().unwrap();

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
    fn not_found() {
        let session = session();
        let mut buf = Vec::new();

        match session.get("nonexistent.txt", &mut buf) {
            Err(Error::NotFound) => {}
            other => panic!("expected `NotFound`, got {:?}", other),
        }
    }

    #[test]
    fn delete_not_found() {
        let mut session = session();

        match session.delete("nonexistent.txt") {
            Err(Error::NotFound) => {}
            other => panic!("expected `NotFound`, got {:?}", other),
        }
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
    fn same_file_same_path() {
        let path = temp_storage_path("same_file_same_path");
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
    fn same_file_different_paths() {
        let path = temp_storage_path("same_file_different_path");
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
    fn different_files_same_path() {
        let path = temp_storage_path("different_file_same_paths");
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
