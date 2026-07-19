//! Converts a 32-byte hash into a three-level `xx/xx/xxxxxx...` hex directory path.
//!
//! The first byte encodes the top-level directory (2 hex chars), the second bytes
//! the subdirectory (2 hex chars), and the remaining 30 bytes the filename (60 hex chars).

use gate::sys::path::PathBuf;

/// A content-addressed filesystem path derived from a 32-byte hash.
///
/// All three components are stored as fixed-size byte arrays of ASCII hex digits.
pub struct HashPath {
    /// First byte of the hash encoded as 2 lowercase hex ASCII digits, the top-level directory name.
    dir: [u8; 2],

    /// Second byte of the hash encoded as 2 lowercase hex ASCII digits, the subdirectory name.
    subdir: [u8; 2],

    /// Remaining 30 bytes (bytes 2–31) encoded as 60 lowercase hex ASCII digits, the filename.
    file: [u8; 60],
}

impl HashPath {
    /// Encodes `hash` into three hex path components and creates a [`HashPath`].
    pub fn new(hash: &[u8; 32]) -> Self {
        const LUT: &[u8; 16] = b"0123456789abcdef";

        let mut hex = [0u8; 64];

        for (i, &byte) in hash.iter().enumerate() {
            hex[i * 2] = LUT[(byte >> 4) as usize];
            hex[i * 2 + 1] = LUT[(byte & 0x0f) as usize];
        }

        let mut dir = [0u8; 2];
        let mut subdir = [0u8; 2];
        let mut file = [0u8; 60];

        dir.copy_from_slice(&hex[0..2]);
        subdir.copy_from_slice(&hex[2..4]);
        file.copy_from_slice(&hex[4..64]);

        Self { dir, subdir, file }
    }

    /// Returns the three path components as UTF-8 string slices.
    fn as_str_parts(&self) -> (&str, &str, &str) {
        // All bytes are ASCII hex digits (0-9, a-f) produced only by the `LUT` in the `new` method

        let dir = core::str::from_utf8(&self.dir)
            .expect("slice to utf-8 failed: this should never happen");
        let subdir = core::str::from_utf8(&self.subdir)
            .expect("slice to utf-8 failed: this should never happen");
        let file = core::str::from_utf8(&self.file)
            .expect("slice to utf-8 failed: this should never happen");

        (dir, subdir, file)
    }
}

impl core::fmt::Display for HashPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let dir = core::str::from_utf8(&self.dir).map_err(|_| core::fmt::Error)?;
        let subdir = core::str::from_utf8(&self.subdir).map_err(|_| core::fmt::Error)?;
        let file = core::str::from_utf8(&self.file).map_err(|_| core::fmt::Error)?;

        write!(f, "{}/{}/{}", dir, subdir, file)
    }
}

impl From<HashPath> for PathBuf {
    fn from(value: HashPath) -> Self {
        let (dir, subdir, file) = value.as_str_parts();
        // 2 (dir) + 1 (sep) + 2 (subdir) + 1 (sep) + 60 (file) = 66
        let mut path = PathBuf::with_capacity(66);

        path.push(dir);
        path.push(subdir);
        path.push(file);

        path
    }
}
