//! Encrypted blobs are as follows:
//!   `[ 12-bytes nonce ] + [ ciphertext ] + [ 16-bytes tag ]`

use gate::{
    crypto::chacha20poly1305::{Aead, AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce, OsRng},
    sys::macros::vec::Vec,
};

#[derive(Debug)]
pub enum Error {
    EncryptFailed,
    DecryptFailed,
    InvalidLength,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EncryptFailed => write!(f, "encryption failed"),
            Self::DecryptFailed => write!(f, "decryption failed (wrong key or corrupted data)"),
            Self::InvalidLength => write!(f, "cipher payload is too short"),
        }
    }
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| Error::EncryptFailed)?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());

    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

pub fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, Error> {
    // 12-bytes nonce + 16-bytes tag
    if blob.len() < 28 {
        return Err(Error::InvalidLength);
    }

    let (nonce_raw, ciphertext) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce_raw);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use gate::sys::macros::vec;

    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let plaintext = b"Something";
        let encrypted_blob = encrypt(&key, plaintext).unwrap();

        assert!(encrypted_blob.len() > 28); // Minimum size of 12 (nonce) + 16 (tag)

        let decrypted_data = decrypt(&key, &encrypted_blob).unwrap();

        assert_eq!(decrypted_data, plaintext);
    }

    #[test]
    fn empty_plaintext() {
        let key = [69u8; 32];
        let plaintext = b"";
        let encrypted_blob = encrypt(&key, plaintext).unwrap();

        // Should be exactly 28 bytes (12-bytes nonce + 0-bytes ciphertext + 16-bytes tag)
        assert_eq!(encrypted_blob.len(), 28);

        let decrypted_data = decrypt(&key, &encrypted_blob).unwrap();

        assert!(decrypted_data.is_empty());
    }

    #[test]
    fn blob_too_short() {
        let key = [0u8; 32];

        // Incorrectly short blob (under 12 bytes)
        let tiny_blob = vec![0u8; 10];

        assert!(matches!(
            decrypt(&key, &tiny_blob),
            Err(Error::InvalidLength)
        ));

        // Missing tag, exactly 12 bytes (nonce only)
        let nonce_only_blob = vec![0u8; 12];

        assert!(matches!(
            decrypt(&key, &nonce_only_blob),
            Err(Error::InvalidLength)
        ));
    }

    #[test]
    fn corrupted_ciphertext() {
        let key = [0u8; 32];
        let plaintext = b"PooPoo";
        let mut encrypted_blob = encrypt(&key, plaintext).unwrap();

        // Flip a bit in the ciphertext to simulate corruption
        let index = encrypted_blob.len() - 1;

        encrypted_blob[index] ^= 1;

        assert!(matches!(
            decrypt(&key, &encrypted_blob),
            Err(Error::DecryptFailed)
        ));
    }

    #[test]
    fn wrong_key() {
        let correct_key = [7u8; 32];
        let wrong_key = [9u8; 32];
        let plaintext = b"The quick brown fox jumps over the dude";
        let encrypted_blob = encrypt(&correct_key, plaintext).unwrap();

        assert!(matches!(
            decrypt(&wrong_key, &encrypted_blob),
            Err(Error::DecryptFailed)
        ));
    }
}
