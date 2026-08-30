//! Local storage backend.
//!
//! Storage layout is as follows:
//!
//!   [root]/<u0:2>/<u2:4>/<u4:64>/index/<shard>
//!          |-------------------|       |-----|
//!                   ^- user address       ^- encrypted shards of the index (4 hex chars)
//!
//!   [root]/<u0:2>/<u2:4>/<u4:64>/blobs/<b0:2>/<b2:4>/<b4:64>
//!          |-------------------|       |-------------------|
//!                   ^- user address           ^- encrypted blobs (Content-Addressed Storage)
//!
//! Each [`Storage`] instance is scoped to a single user. The shared prefix is
//! `Index::address(public_key)`.
//! The same 2+2+60 hex split used for blob addresses [`HashPath`] is reused.
//!
//! Write operations are atomic.

use crate::storage::{Backend, Error, Key, Kind, SHARD_COUNT, hashpath::HashPath, index::Index};

use gate::sys::{fs, io, macros::format, path::PathBuf, vec::Vec};

/// Name of the subdirectory inside each user's directory that contains index shards.
const INDEX_DIRNAME: &str = "index";
/// Name of the subdirectory inside each user's directory that contains content-addressed blobs.
const BLOBS_DIRNAME: &str = "blobs";

/// A filesystem-backed, user-scoped blob and index store.
///
/// All data lives under a nested hex directory tree derived from the user's public signing key,
/// ensuring storage isolation between users sharing the same root directory. All index shard and
/// blob writes are atomic; data is staged to a `.tmp` file and renamed into place.
pub struct Storage {
    /// Absolute path to this user's scoped storage root (i.e. `[base_root]/xx/xx/xxxxxx...`).
    /// All index shard and blob paths are derived relative to this directory.
    root: PathBuf,
}

impl Storage {
    /// Creates a new [`Storage`] instance rooted at `root`, scoped to `public_key`.
    pub fn new(root: impl Into<PathBuf>, public_key: &[u8; 32]) -> Result<Self, Error> {
        let user_address = Index::address(public_key);
        let root = root
            .into()
            .join(PathBuf::from(HashPath::new(&user_address)));

        Ok(Self { root })
    }

    /// Resolves a key and returns the path at which the key will be stored.
    fn resolve(&self, key: Key) -> PathBuf {
        match key {
            Key::Index(number) => self
                .root
                .join(INDEX_DIRNAME)
                .join(format!("{:04x}", number)),
            Key::Blob(address) => self
                .root
                .join(BLOBS_DIRNAME)
                .join(PathBuf::from(HashPath::new(&address))),
        }
    }

    /// Lists every index's key present in the [`INDEX_DIRNAME`] directory.
    fn list_index_dir(&self) -> Result<Vec<Key>, Error> {
        let mut keys = Vec::new();

        let entries = match fs::read_dir(self.root.join(INDEX_DIRNAME)) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(keys),
            Err(e) => return Err(Error::Io(e)),
        };

        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }

            if let Some(name) = entry.file_name().to_str()
                && name.len() == 4
                && let Ok(number) = u16::from_str_radix(name, 16)
                && number < SHARD_COUNT
            {
                keys.push(Key::Index(number));
            }
        }

        Ok(keys)
    }

    /// Lists every blob's key present in the [`BLOBS_DIRNAME`] directory.
    fn list_blobs_dir(&self) -> Result<Vec<Key>, Error> {
        let mut keys = Vec::new();

        // Must be 3 levels: ./xx/xx/xxxxxx...
        let entries = match fs::read_dir(self.root.join(BLOBS_DIRNAME)) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(keys),
            Err(e) => return Err(Error::Io(e)),
        };

        /// Reconstructs a 32-byte blob address from its three hex path segments
        /// (`dir` = 2 chars, `subdir` = 2 chars, `file` = 60 chars).
        ///
        /// Returns `None` if any segment has an unexpected length or contains non-hex characters.
        fn path_to_address(dir: &str, subdir: &str, file: &str) -> Option<[u8; 32]> {
            if dir.len() != 2 || subdir.len() != 2 || file.len() != 60 {
                return None;
            }

            let mut address = [0u8; 32];

            // dir
            address[0] = u8::from_str_radix(dir, 16).ok()?;
            // subdir
            address[1] = u8::from_str_radix(subdir, 16).ok()?;

            for (i, chunk) in file.as_bytes().chunks(2).enumerate() {
                let chunk_str = core::str::from_utf8(chunk).ok()?;

                // file
                address[2 + i] = u8::from_str_radix(chunk_str, 16).ok()?;
            }

            Some(address)
        }

        for dir in entries.flatten() {
            if !dir.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }

            let subdir_entries = match fs::read_dir(dir.path()) {
                Ok(e) => e,
                Err(_) => continue, // Skip unreadable subdirs
            };

            for subdir in subdir_entries.flatten() {
                if !subdir.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }

                let file_entries = match fs::read_dir(subdir.path()) {
                    Ok(e) => e,
                    Err(_) => continue, // Skip unreadable files
                };

                for file in file_entries.flatten() {
                    if !file.file_type().map(|t| t.is_file()).unwrap_or(false) {
                        continue;
                    }

                    if let (Some(dir), Some(subdir), Some(file)) = (
                        dir.file_name().to_str(),
                        subdir.file_name().to_str(),
                        file.file_name().to_str(),
                    ) && let Some(address) = path_to_address(dir, subdir, file)
                    {
                        keys.push(Key::Blob(address));
                    }
                }
            }
        }

        Ok(keys)
    }
}

impl Backend for Storage {
    fn put(&self, key: Key, data: &[u8]) -> Result<(), Error> {
        let path = self.resolve(key);

        if matches!(key, Key::Blob(_)) && path.exists() {
            return Ok(()); // No-op in content-addressed, file already exists
        }

        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
        }

        let temp = path.with_extension("tmp");

        // Atomic write
        fs::write(&temp, data)?;
        fs::rename(&temp, path)?;

        Ok(())
    }

    fn get(&self, key: Key) -> Result<Vec<u8>, Error> {
        let path = self.resolve(key);

        Ok(fs::read(&path)?)
    }

    fn exists(&self, key: Key) -> Result<bool, Error> {
        let path = self.resolve(key);

        Ok(path.exists())
    }

    fn delete(&self, key: Key) -> Result<(), Error> {
        let path = self.resolve(key);

        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn list(&self, kind: Kind) -> Result<Vec<Key>, Error> {
        match kind {
            Kind::Index => self.list_index_dir(),
            Kind::Blob => self.list_blobs_dir(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gate::sys::{
        env,
        macros::{format, vec},
        time,
    };

    fn temp_storage(name: &str) -> Storage {
        let nanos = time::current_nanos().unwrap();
        let path = env::temp_dir().join(format!("vault_test_{}_{}", name, nanos));
        let public_key = [0u8; 32];

        Storage::new(path, &public_key).unwrap()
    }

    #[test]
    fn index_shard_put_get_roundtrip() {
        let storage = temp_storage("index_shard_roundtrip");
        let key = Key::Index(0);
        let data = b"data";

        storage.put(key, data).unwrap();

        assert_eq!(storage.get(key).unwrap(), data);
    }

    #[test]
    fn blob_put_get_roundtrip() {
        let storage = temp_storage("roundtrip");
        let key = Key::Blob([0; 32]);
        let data = b"data";

        storage.put(key, data).unwrap();

        assert_eq!(storage.get(key).unwrap(), data);
    }

    #[test]
    fn exists() {
        let storage = temp_storage("exists");
        let key = Key::Blob([1; 32]);
        let data = b"data";

        assert!(!storage.exists(key).unwrap());

        storage.put(key, data).unwrap();

        assert!(storage.exists(key).unwrap());
    }

    #[test]
    fn not_found() {
        let storage = temp_storage("not_found");
        let key = Key::Blob([2; 32]);
        let got = storage.get(key);

        assert!(matches!(got, Err(Error::NotFound)));
    }

    #[test]
    fn no_op_put() {
        let storage = temp_storage("no_op_put");
        let key = Key::Blob([3; 32]);

        storage.put(key, b"first write").unwrap();
        storage
            .put(key, b"second write - should be ignored")
            .unwrap();

        // Same address so the second put is a no-op, original data preserved
        assert_eq!(storage.get(key).unwrap(), b"first write");
    }

    #[test]
    fn index_shard_put_always_overwrites() {
        let storage = temp_storage("index_overwrite");
        let key = Key::Index(3);

        storage.put(key, b"first write").unwrap();
        storage.put(key, b"second write").unwrap();

        // Unlike blobs, an index shard is mutable and always overwritten
        assert_eq!(storage.get(key).unwrap(), b"second write");
    }

    #[test]
    fn delete() {
        let storage = temp_storage("delete");
        let key = Key::Blob([4; 32]);

        storage.put(key, b"gonna get deleted").unwrap();
        storage.delete(key).unwrap();

        assert!(!storage.exists(key).unwrap());
    }

    #[test]
    fn delete_non_existent() {
        let storage = temp_storage("delete_non_existent");
        let key = Key::Blob([5; 32]);

        assert!(storage.delete(key).is_ok());
    }

    #[test]
    fn list() {
        let storage = temp_storage("list");
        let key1 = Key::Blob([6; 32]);
        let key2 = Key::Blob([7; 32]);

        storage.put(key1, b"a").unwrap();
        storage.put(key2, b"b").unwrap();

        let mut list = storage.list(Kind::Blob).unwrap();
        let expected = vec![key1, key2];

        list.sort();

        assert_eq!(list, expected);
    }

    #[test]
    fn list_index_shards() {
        let storage = temp_storage("list_index");
        let key1 = Key::Index(1);
        let key2 = Key::Index(200);

        storage.put(key1, b"shard one").unwrap();
        storage.put(key2, b"shard two").unwrap();

        let mut list = storage.list(Kind::Index).unwrap();
        let expected = vec![key1, key2];

        list.sort();

        assert_eq!(list, expected);
    }

    #[test]
    fn list_index_empty_when_nothing_written() {
        let storage = temp_storage("list_index_empty");

        assert!(storage.list(Kind::Index).unwrap().is_empty());
    }

    #[test]
    fn blobs_and_index_are_isolated() {
        let storage = temp_storage("isolation");

        storage.put(Key::Blob([9; 32]), b"blob data").unwrap();
        storage.put(Key::Index(69), b"shard data").unwrap();

        assert_eq!(storage.list(Kind::Blob).unwrap(), vec![Key::Blob([9; 32])]);
        assert_eq!(storage.list(Kind::Index).unwrap(), vec![Key::Index(69)]);
    }

    #[test]
    #[cfg(unix)]
    fn list_skips_inaccessible_directories() {
        use gate::sys::{fs::Permissions, os::unix::fs::PermissionsExt};

        let storage = temp_storage("list_inaccessible");
        let key = Key::Blob([8; 32]);

        storage.put(key, b"accessible payload").unwrap();

        let broken_dir = storage.root.join(BLOBS_DIRNAME).join("ff");

        fs::create_dir_all(&broken_dir).unwrap();

        // Revoke all permissions so read_dir fails
        fs::set_permissions(&broken_dir, Permissions::from_mode(0o000)).unwrap();

        let result = storage.list(Kind::Blob);

        // Restore permissions so we can delete the temporary directory after the test
        let _ = fs::set_permissions(&broken_dir, Permissions::from_mode(0o755));
        let list = result.unwrap();

        assert_eq!(
            list.len(),
            1,
            "Should have skipped the broken directory instead of failing"
        );
        assert_eq!(
            list[0], key,
            "The valid chunk must still be collected safely"
        );
    }
}
