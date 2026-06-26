//! Encrypted blobs are as follows:
//!   `[ 12-bytes nonce ] + [ ciphertext ] + [ 16-bytes tag ]`

use gate::{
    crypto::chacha20poly1305::{Aead, AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce},
    sys::{macros::vec::Vec, random::OsRng},
};

#[derive(Debug)]
pub enum Error {
    EncryptFailed,
    DecryptFailed,
    InvalidLength,
    InvalidSignature,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EncryptFailed => write!(f, "encryption failed"),
            Self::DecryptFailed => write!(f, "decryption failed (wrong key or corrupted data)"),
            Self::InvalidLength => write!(f, "cipher payload is too short"),
            Self::InvalidSignature => write!(f, "invalid blob signature"),
        }
    }
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| Error::EncryptFailed)?;
    let mut out = Vec::with_capacity(12 + ciphertext.len()); // 12-bytes nonce

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

pub fn lock(
    key: &[u8; 32],
    plaintext: &[u8],
    sign: impl Fn(&[u8]) -> [u8; 64],
) -> Result<Vec<u8>, Error> {
    let encrypted = encrypt(key, plaintext)?;
    let signature = sign(&encrypted);
    let mut out = Vec::with_capacity(64 + encrypted.len()); // 64-bytes signature

    out.extend_from_slice(&signature);
    out.extend_from_slice(&encrypted);

    Ok(out)
}

pub fn unlock(
    key: &[u8; 32],
    blob: &[u8],
    verify: impl Fn(&[u8], &[u8; 64]) -> bool,
) -> Result<Vec<u8>, Error> {
    // 64-bytes signature + 12-bytes nonce + 16-bytes tag
    if blob.len() < 92 {
        return Err(Error::InvalidLength);
    }

    let (signature_bytes, encrypted) = blob.split_at(64);
    let signature = signature_bytes
        .try_into()
        .map_err(|_| Error::InvalidLength)?;

    if !verify(encrypted, signature) {
        return Err(Error::InvalidSignature);
    }

    decrypt(key, encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    use gate::sys::macros::vec;

    fn sign(data: &[u8]) -> [u8; 64] {
        let mut sig = [0u8; 64];

        // XOR the first 64 bytes of data into the signature so tampering is detectable
        for (i, &b) in data.iter().take(64).enumerate() {
            sig[i] = b ^ 0xAB;
        }

        sig
    }

    fn verify(data: &[u8], sig: &[u8; 64]) -> bool {
        sign(data) == *sig
    }

    #[test]
    fn lock_unlock_roundtrip() {
        let key = [0u8; 32];
        let plaintext = b"Something";
        let blob = lock(&key, plaintext, sign).unwrap();
        let decrypted = unlock(&key, &blob, verify).unwrap();

        assert_eq!(decrypted, plaintext);
    }

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
        let blob = lock(&key, b"", sign).unwrap();

        // 64 (signature) + 12 (nonce) + 0 (ciphertext) + 16 (tag)
        assert_eq!(blob.len(), 92);

        let decrypted = unlock(&key, &blob, verify).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_decrypt_blob_too_short() {
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
    fn lock_unlock_blob_too_short() {
        let key = [0u8; 32];
        let tiny = vec![0u8; 91]; // 1 byte below minimum

        assert!(matches!(
            unlock(&key, &tiny, verify),
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
    fn encrypt_decrypt_wrong_key() {
        let correct_key = [7u8; 32];
        let wrong_key = [9u8; 32];
        let plaintext = b"The quick brown fox jumps over the dude";
        let encrypted_blob = encrypt(&correct_key, plaintext).unwrap();

        assert!(matches!(
            decrypt(&wrong_key, &encrypted_blob),
            Err(Error::DecryptFailed)
        ));
    }

    #[test]
    fn lock_unlock_wrong_key() {
        let correct_key = [7u8; 32];
        let wrong_key = [9u8; 32];
        let blob = lock(&correct_key, b"secret", sign).unwrap();

        // Signature is valid but decryption should fail
        assert!(matches!(
            unlock(&wrong_key, &blob, verify),
            Err(Error::DecryptFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext() {
        let key = [0u8; 32];
        let mut blob = lock(&key, b"original", sign).unwrap();

        // Flip a bit in the ciphertext (after the 64-byte signature)
        blob[65] ^= 1;

        assert!(matches!(
            unlock(&key, &blob, verify),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn tampered_signature() {
        let key = [0u8; 32];
        let mut blob = lock(&key, b"original", sign).unwrap();

        // Corrupt the signature itself
        blob[0] ^= 0xFF;

        assert!(matches!(
            unlock(&key, &blob, verify),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn corrupted_ciphertext_after_valid_signature() {
        let key = [0u8; 32];
        let mut blob = lock(&key, b"data", sign).unwrap();

        // Re-sign the corrupted ciphertext so signature passes, but won't be tagged by poly1305
        let corrupt_byte_idx = 64 + 12; // First byte of actual ciphertext

        blob[corrupt_byte_idx] ^= 0xFF;

        let new_signature = sign(&blob[64..]);

        blob[..64].copy_from_slice(&new_signature);

        assert!(matches!(
            unlock(&key, &blob, verify),
            Err(Error::DecryptFailed)
        ));
    }
}
