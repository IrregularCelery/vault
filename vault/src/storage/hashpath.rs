use gate::sys::path::PathBuf;

pub struct HashPath {
    dir: [u8; 2],
    subdir: [u8; 2],
    file: [u8; 60],
}

impl HashPath {
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
        let dir = core::str::from_utf8(&self.dir).unwrap();
        let subdir = core::str::from_utf8(&self.subdir).unwrap();
        let file = core::str::from_utf8(&self.file).unwrap();

        write!(f, "{}/{}/{}", dir, subdir, file)
    }
}

impl From<HashPath> for PathBuf {
    fn from(value: HashPath) -> Self {
        let (dir, subdir, file) = value.as_str_parts();
        let mut path = PathBuf::with_capacity(66);

        path.push(dir);
        path.push(subdir);
        path.push(file);

        path
    }
}
