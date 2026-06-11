//! Storage layout is as follows: (Content-Addressed Storage)
//!
//!   [root]/a1/b2/c3d4e5...
//!                   ^- encrpyted blob file
//!
//! Blob writes are atomic

use crate::storage::{Backend, Error, hashpath::HashPath};

use gate::sys::{fs, io, path::PathBuf, vec::Vec};

pub struct Storage {
    root: PathBuf,
}

impl Storage {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, Error> {
        let root = root.into();

        fs::create_dir_all(&root)?;

        Ok(Self { root })
    }

    fn blob_path(&self, hash: &[u8; 32]) -> PathBuf {
        self.root.join(PathBuf::from(HashPath::new(hash)))
    }
}

impl Backend for Storage {
    fn put(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let path = self.blob_path(hash);

        if path.exists() {
            return Ok(()); // No-op in content-addressed, file already exists
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp = path.with_extension("tmp");

        // Atomic write
        fs::write(&temp, data)?;
        fs::rename(&temp, path)?;

        Ok(())
    }

    fn get(&self, hash: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let path = self.blob_path(hash);

        Ok(fs::read(&path)?)
    }

    fn overwrite(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let path = self.blob_path(hash);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp = path.with_extension("tmp");

        // Atomic write
        fs::write(&temp, data)?;
        fs::rename(&temp, path)?;

        Ok(())
    }

    fn exists(&self, hash: &[u8; 32]) -> Result<bool, Error> {
        Ok(self.blob_path(hash).exists())
    }

    fn delete(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let path = self.blob_path(hash);

        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn list(&self) -> Result<Vec<[u8; 32]>, Error> {
        let mut hashes = Vec::new();

        // Must be 3 levels: root/XX/XX/XXXXXX...
        let entries = match fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(hashes),
            Err(e) => return Err(Error::Io(e)),
        };

        fn path_to_hash(dir: &str, subdir: &str, file: &str) -> Option<[u8; 32]> {
            if dir.len() != 2 || subdir.len() != 2 || file.len() != 60 {
                return None;
            }

            let mut hash = [0u8; 32];

            hash[0] = u8::from_str_radix(dir, 16).ok()?;
            hash[1] = u8::from_str_radix(subdir, 16).ok()?;

            for (i, chunk) in file.as_bytes().chunks(2).enumerate() {
                let chunk_str = core::str::from_utf8(chunk).ok()?;

                hash[2 + i] = u8::from_str_radix(chunk_str, 16).ok()?;
            }

            Some(hash)
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
                    ) && let Some(hash) = path_to_hash(dir, subdir, file)
                    {
                        hashes.push(hash);
                    }
                }
            }
        }

        Ok(hashes)
    }
}

#[cfg(test)]
mod tests {
    use gate::sys::{
        env,
        macros::{format, vec},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    fn temp_storage(name: &str) -> Storage {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = env::temp_dir().join(format!("vault_test_{}_{}", name, nanos));

        Storage::new(path).unwrap()
    }

    #[test]
    fn put_get_roundtrip() {
        let storage = temp_storage("roundtrip");
        let hash = [0; 32];
        let data = b"data";

        storage.put(&hash, data).unwrap();

        assert_eq!(storage.get(&hash).unwrap(), data);
    }

    #[test]
    fn exists() {
        let storage = temp_storage("exists");
        let hash = [1; 32];
        let data = b"data";

        assert!(!storage.exists(&hash).unwrap());

        storage.put(&hash, data).unwrap();

        assert!(storage.exists(&hash).unwrap());
    }

    #[test]
    fn not_found() {
        let storage = temp_storage("not_found");
        let hash = [2; 32];
        match storage.get(&hash) {
            Err(Error::NotFound) => {}
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn no_op_put() {
        let storage = temp_storage("no_op_put");
        let hash = [3; 32];

        storage.put(&hash, b"first write").unwrap();
        storage
            .put(&hash, b"second write - should be ignored")
            .unwrap();

        // Same hash so the second put is a no-op, original data preserved
        assert_eq!(storage.get(&hash).unwrap(), b"first write");
    }

    #[test]
    fn delete() {
        let storage = temp_storage("delete");
        let hash = [4; 32];

        storage.put(&hash, b"gonna get deleted").unwrap();
        storage.delete(&hash).unwrap();

        assert!(!storage.exists(&hash).unwrap());
    }

    #[test]
    fn delete_non_existent() {
        let storage = temp_storage("delete_non_existent");
        let hash = [5; 32];

        assert!(storage.delete(&hash).is_ok());
    }

    #[test]
    fn list() {
        let storage = temp_storage("list");
        let hash1 = [6; 32];
        let hash2 = [7; 32];

        storage.put(&hash1, b"a").unwrap();
        storage.put(&hash2, b"b").unwrap();

        let mut list = storage.list().unwrap();
        let expected = vec![hash1, hash2];

        list.sort();

        assert_eq!(list, expected);
    }

    #[test]
    #[cfg(unix)]
    fn list_skips_inaccessible_directories() {
        use gate::sys::{fs::Permissions, os::unix::fs::PermissionsExt};

        let storage = temp_storage("list_inaccessible");
        let hash = [8; 32];

        storage.put(&hash, b"accessible payload").unwrap();

        let broken_dir = storage.root.join("ff");

        fs::create_dir_all(&broken_dir).unwrap();

        // Revoke all permissions so read_dir fails
        fs::set_permissions(&broken_dir, Permissions::from_mode(0o000)).unwrap();

        let result = storage.list();

        // Restore permissions so we can delete the temporary directory after the test
        let _ = fs::set_permissions(&broken_dir, Permissions::from_mode(0o755));
        let list = result.unwrap();

        assert_eq!(
            list.len(),
            1,
            "Should have skipped the broken directory instead of failing"
        );
        assert_eq!(
            list[0], hash,
            "The valid chunk must still be collected safely"
        );
    }
}
