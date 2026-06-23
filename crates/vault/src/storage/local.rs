//! Storage layout is as follows:
//!
//!   [root]/<u0:2>/<u2:4>/<u4:64>/manifest
//!          |-------------------|    ^- encrypted manifest file
//!                   ^- user address
//!
//!   [root]/<u0:2>/<u2:4>/<u4:64>/blobs/<b0:2>/<b2:4>/<b4:64>
//!          |-------------------|       |-------------------|
//!                   ^- user address           ^- encrypted blob file (Content-Addressed Storage)
//!
//! Each `Storage` instance is scoped to a single user. The shared prefix is
//! `Manifest::address(public_key)`.
//! The same 2+2+60 hex split used for blob addresses (`HashPath`) is reused.
//!
//! Blob writes are atomic

use crate::storage::{Backend, Error, hashpath::HashPath, manifest::Manifest};

use gate::sys::{fs, io, path::PathBuf, vec::Vec};

const MANIFEST_FILENAME: &str = "manifest";
const BLOBS_DIRNAME: &str = "blobs";

pub struct Storage {
    root: PathBuf,
}

impl Storage {
    pub fn new(root: impl Into<PathBuf>, public_key: &[u8; 32]) -> Result<Self, Error> {
        let user_address = Manifest::address(public_key);
        let root = root
            .into()
            .join(PathBuf::from(HashPath::new(&user_address)));

        fs::create_dir_all(&root)?;
        fs::create_dir_all(root.join(BLOBS_DIRNAME))?;

        Ok(Self { root })
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join(MANIFEST_FILENAME)
    }

    fn blob_path(&self, address: &[u8; 32]) -> PathBuf {
        self.root
            .join(BLOBS_DIRNAME)
            .join(PathBuf::from(HashPath::new(address)))
    }
}

impl Backend for Storage {
    fn save_manifest(&self, data: &[u8]) -> Result<(), Error> {
        let path = self.manifest_path();
        let temp = path.with_extension("tmp");

        // Atomic write
        fs::write(&temp, data)?;
        fs::rename(&temp, &path)?;

        Ok(())
    }

    fn load_manifest(&self) -> Result<Vec<u8>, Error> {
        let path = self.manifest_path();

        Ok(fs::read(&path)?)
    }

    fn put_blob(&self, address: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let path = self.blob_path(address);

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

    fn get_blob(&self, address: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let path = self.blob_path(address);

        Ok(fs::read(&path)?)
    }

    fn exists_blob(&self, address: &[u8; 32]) -> Result<bool, Error> {
        Ok(self.blob_path(address).exists())
    }

    fn delete_blob(&self, address: &[u8; 32]) -> Result<(), Error> {
        let path = self.blob_path(address);

        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn list_blobs(&self) -> Result<Vec<[u8; 32]>, Error> {
        let mut addresses = Vec::new();

        // Must be 3 levels: ./xx/xx/xxxxxx...
        let entries = match fs::read_dir(self.root.join(BLOBS_DIRNAME)) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(addresses),
            Err(e) => return Err(Error::Io(e)),
        };

        fn path_to_address(dir: &str, subdir: &str, file: &str) -> Option<[u8; 32]> {
            if dir.len() != 2 || subdir.len() != 2 || file.len() != 60 {
                return None;
            }

            let mut address = [0u8; 32];

            address[0] = u8::from_str_radix(dir, 16).ok()?;
            address[1] = u8::from_str_radix(subdir, 16).ok()?;

            for (i, chunk) in file.as_bytes().chunks(2).enumerate() {
                let chunk_str = core::str::from_utf8(chunk).ok()?;

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
                        addresses.push(address);
                    }
                }
            }
        }

        Ok(addresses)
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
        let public_key = [0u8; 32];

        Storage::new(path, &public_key).unwrap()
    }

    #[test]
    fn manifest_save_load_roundtrip() {
        let storage = temp_storage("manifest_roundtrip");
        let data = b"data";

        storage.save_manifest(data).unwrap();

        assert_eq!(storage.load_manifest().unwrap(), data);
    }

    #[test]
    fn put_get_roundtrip() {
        let storage = temp_storage("roundtrip");
        let address = [0; 32];
        let data = b"data";

        storage.put_blob(&address, data).unwrap();

        assert_eq!(storage.get_blob(&address).unwrap(), data);
    }

    #[test]
    fn exists() {
        let storage = temp_storage("exists");
        let address = [1; 32];
        let data = b"data";

        assert!(!storage.exists_blob(&address).unwrap());

        storage.put_blob(&address, data).unwrap();

        assert!(storage.exists_blob(&address).unwrap());
    }

    #[test]
    fn not_found() {
        let storage = temp_storage("not_found");
        let address = [2; 32];
        let got = storage.get_blob(&address);

        assert!(matches!(got, Err(Error::NotFound)));
    }

    #[test]
    fn no_op_put() {
        let storage = temp_storage("no_op_put");
        let address = [3; 32];

        storage.put_blob(&address, b"first write").unwrap();
        storage
            .put_blob(&address, b"second write - should be ignored")
            .unwrap();

        // Same address so the second put is a no-op, original data preserved
        assert_eq!(storage.get_blob(&address).unwrap(), b"first write");
    }

    #[test]
    fn delete() {
        let storage = temp_storage("delete");
        let address = [4; 32];

        storage.put_blob(&address, b"gonna get deleted").unwrap();
        storage.delete_blob(&address).unwrap();

        assert!(!storage.exists_blob(&address).unwrap());
    }

    #[test]
    fn delete_non_existent() {
        let storage = temp_storage("delete_non_existent");
        let address = [5; 32];

        assert!(storage.delete_blob(&address).is_ok());
    }

    #[test]
    fn list() {
        let storage = temp_storage("list");
        let address1 = [6; 32];
        let address2 = [7; 32];

        storage.put_blob(&address1, b"a").unwrap();
        storage.put_blob(&address2, b"b").unwrap();

        let mut list = storage.list_blobs().unwrap();
        let expected = vec![address1, address2];

        list.sort();

        assert_eq!(list, expected);
    }

    #[test]
    #[cfg(unix)]
    fn list_skips_inaccessible_directories() {
        use gate::sys::{fs::Permissions, os::unix::fs::PermissionsExt};

        let storage = temp_storage("list_inaccessible");
        let address = [8; 32];

        storage.put_blob(&address, b"accessible payload").unwrap();

        let broken_dir = storage.root.join(BLOBS_DIRNAME).join("ff");

        fs::create_dir_all(&broken_dir).unwrap();

        // Revoke all permissions so read_dir fails
        fs::set_permissions(&broken_dir, Permissions::from_mode(0o000)).unwrap();

        let result = storage.list_blobs();

        // Restore permissions so we can delete the temporary directory after the test
        let _ = fs::set_permissions(&broken_dir, Permissions::from_mode(0o755));
        let list = result.unwrap();

        assert_eq!(
            list.len(),
            1,
            "Should have skipped the broken directory instead of failing"
        );
        assert_eq!(
            list[0], address,
            "The valid chunk must still be collected safely"
        );
    }
}
