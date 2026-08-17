//! BLAKE3-based hashing and key-derivation primitives.

use gate::crypto::blake3;

/// Derives a domain-separated 32-byte key from `context` and `key_material`.
pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, key_material)
}

/// Computes a keyed hash over `data` under `key`.
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// An incremental hasher, for hashing data from pieces without concatenation.
pub struct Hasher(blake3::Hasher);

impl Hasher {
    /// Creates a new keyed hasher.
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self(blake3::Hasher::new_keyed(key))
    }

    /// Feeds more data into the hash state.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);

        self
    }

    /// Finalizes and returns the resulting hash.
    pub fn finalize(&self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }
}
