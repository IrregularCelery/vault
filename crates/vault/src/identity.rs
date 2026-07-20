//! Deterministic identity derivation from a BIP-39 mnemonic.
//!
//! A mnemonic phrase is passed to Argon2id (64 MiB, 3 iterations, 1 thread, 64-byte output,
//! fixed salt) into a 64-byte seed. Three independent keys are then derived via BLAKE3
//! domain-separated KDF used for an encryption key, signing keys, and exchange keys.
//!
//! The mnemonic itself IS the credential.

use gate::{
    crypto::{
        argon2::{Algorithm, Argon2, Params, Version},
        bip39, blake3,
        ed25519::{Signature, Signer, SigningKey, Verifier, VerifyingKey},
        x25519::{PublicKey, StaticSecret},
    },
    sys::{
        borrow::Cow,
        macros::{format, vec::Vec},
    },
};

/// Fixed salt for Argon2id KDF.
const KDF_SALT: &[u8] = b"vault::kdf::v1::salt";
/// BLAKE3 domain tag for deriving the encryption key from the seed.
const DOMAIN_ENCRYPTION: &str = "vault::encryption";
/// BLAKE3 domain tag for deriving the Ed25519 signing keys from the seed.
const DOMAIN_SIGNING: &str = "vault::signing";
/// BLAKE3 domain tag for deriving the X25519 exchange keys from the seed.
const DOMAIN_EXCHANGE: &str = "vault::exchange";

/// Errors from mnemonic validation or identity derivation.
#[derive(Debug)]
pub enum Error {
    /// The payload word list failed BIP-39 validation (wrong word count, unknown words,
    /// or invalid checksum).
    InvalidMnemonic,

    /// The phrase is a known BIP-39 test vector and must not be used as a real credential.
    UnsafeMnemonic,

    /// Specific message error
    Other(Cow<'static, str>),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidMnemonic => write!(f, "please enter a valid mnemonic"),
            Self::UnsafeMnemonic => write!(
                f,
                "unsafe mnemonic detected! please generate a random mnemonic"
            ),
            Self::Other(e) => write!(f, "{}", e),
        }
    }
}

/// The cryptographic identity of a user.
///
/// All keys are derived deterministically, reconstructing an [`Identity`] from the same mnemonic
/// always produces identical keys.
pub struct Identity {
    /// 32-byte symmetric key used for ChaCha20-Poly1305 encryption of data.
    encryption_key: [u8; 32],

    /// Ed25519 public signing key.
    public_signing_key: VerifyingKey,

    /// Ed25519 private signing key.
    private_signing_key: SigningKey,

    /// X25519 public exchange key.
    public_exchange_key: PublicKey,

    /// X25519 private exchange key.
    private_exchange_key: StaticSecret,
}

impl Identity {
    /// Derives an `Identity` from a validated BIP-39 word list.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidMnemonic`]: If an invalid word is found.
    /// - [`Error::UnsafeMnemonic`]: If the phrase is a known BIP-39 test vector, guarding against
    ///   accidental use of example mnemonics.
    pub fn from_mnemonic(words: &[impl AsRef<str>]) -> Result<Self, Error> {
        if words.is_empty() {
            return Err(Error::InvalidMnemonic);
        }

        let words: Vec<&str> = words.iter().map(|w| w.as_ref()).collect();

        bip39::validate(&words).map_err(|_| Error::InvalidMnemonic)?;

        let phrase = words.join(" ");

        if bip39::VECTORS.contains(&phrase.as_str()) {
            return Err(Error::UnsafeMnemonic);
        }

        Self::from_phrase(&phrase)
    }

    /// Derives an `Identity` directly from a 64-byte seed, bypassing Argon2id.
    ///
    /// Used for when the caller has already performed its own KDF. The three child keys are still
    /// derived via BLAKE3 with distinct domain tags, ensuring they remain fully independent.
    pub fn from_seed(seed: &[u8; 64]) -> Self {
        // Three independent keys from one seed, separated by distinct domain tags.
        let encryption_key = blake3::derive_key(DOMAIN_ENCRYPTION, seed);
        let signing_seed = blake3::derive_key(DOMAIN_SIGNING, seed);
        let exchange_seed = blake3::derive_key(DOMAIN_EXCHANGE, seed);

        let private_signing_key = SigningKey::from_bytes(&signing_seed);
        let public_signing_key = private_signing_key.verifying_key();

        let private_exchange_key = StaticSecret::from(exchange_seed);
        let public_exchange_key = PublicKey::from(&private_exchange_key);

        Self {
            encryption_key,
            public_signing_key,
            private_signing_key,
            public_exchange_key,
            private_exchange_key,
        }
    }

    /// Derives an `Identity` from a validated BIP-39 word list.
    fn from_phrase(phrase: &str) -> Result<Self, Error> {
        // --- Argon2id ---
        // Parameters: 64 MiB memory, 3 iterations, 1 thread, 64-byte output.
        // Password -> UTF-8 bytes of the mnemonic phrase
        // Salt     -> Fixed salt (The mnemonic IS the key, no need for per-user salt)
        // Output   -> 64 bytes (Used to derive independent keys via BLAKE3 KDF)
        let params = Params::new(64 * 1024, 3, 1, Some(64))
            .map_err(|e| Error::Other(format!("argon2 params: {}", e).into()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = KDF_SALT;
        let mut seed = [0u8; 64];

        argon2
            .hash_password_into(phrase.as_bytes(), salt, &mut seed)
            .map_err(|e| Error::Other(format!("argon2 hash: {}", e).into()))?;

        Ok(Self::from_seed(&seed))
    }

    /// Returns the 32-byte encryption key (used for ChaCha20-Poly1305).
    pub fn encryption_key(&self) -> [u8; 32] {
        self.encryption_key
    }

    /// Returns the Ed25519 public signing key.
    pub fn public_signing_key(&self) -> [u8; 32] {
        self.public_signing_key.to_bytes()
    }

    /// Returns the Ed25519 private signing key.
    pub fn private_signing_key(&self) -> [u8; 32] {
        self.private_signing_key.to_bytes()
    }

    /// Returns the X25519 public exchange key.
    pub fn public_exchange_key(&self) -> [u8; 32] {
        self.public_exchange_key.to_bytes()
    }

    /// Returns the X25519 private exchange key.
    pub fn private_exchange_key(&self) -> [u8; 32] {
        self.private_exchange_key.to_bytes()
    }

    /// Signs `message` with this identity's Ed25519 private signing key.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.private_signing_key.sign(message).to_bytes()
    }

    /// Verifies `signature` against `message` using this identity's Ed25519 public key.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8; 64]) -> bool {
        let signature = Signature::from_bytes(signature_bytes);

        self.public_signing_key.verify(message, &signature).is_ok()
    }

    /// Verifies `signature` against `message` using an Ed25519 public key.
    pub fn verify_with_key(
        public_key: &[u8; 32],
        message: &[u8],
        signature_bytes: &[u8; 64],
    ) -> bool {
        let Ok(public_signing_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let signature = Signature::from_bytes(signature_bytes);

        public_signing_key.verify(message, &signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let words = bip39::generate(12).unwrap();
        let id1 = Identity::from_mnemonic(&words).unwrap();
        let id2 = Identity::from_mnemonic(&words).unwrap();

        assert_eq!(id1.encryption_key, id2.encryption_key);
        assert_eq!(id1.public_signing_key(), id2.public_signing_key());
        assert_eq!(id1.public_exchange_key(), id2.public_exchange_key());
    }

    #[test]
    fn encryption_and_signing_keys_are_different() {
        let words = bip39::generate(12).unwrap();
        let id = Identity::from_mnemonic(&words).unwrap();

        assert_ne!(id.encryption_key, id.private_signing_key.to_bytes());
    }

    #[test]
    fn signing_exchange_keys_are_different() {
        let words = bip39::generate(12).unwrap();
        let id = Identity::from_mnemonic(&words).unwrap();

        assert_ne!(id.public_signing_key(), id.public_exchange_key());
        assert_ne!(
            id.private_signing_key.to_bytes(),
            id.private_exchange_key.to_bytes()
        );
        assert_ne!(id.public_signing_key(), id.private_exchange_key.to_bytes());
        assert_ne!(id.private_signing_key.to_bytes(), id.public_exchange_key());
    }

    #[test]
    fn different_mnemonics_produce_different_keys() {
        let words1 = bip39::generate(12).unwrap();
        let words2 = bip39::generate(12).unwrap();
        let id1 = Identity::from_mnemonic(&words1).unwrap();
        let id2 = Identity::from_mnemonic(&words2).unwrap();

        assert_ne!(id1.public_signing_key(), id2.public_signing_key());
        assert_ne!(id1.encryption_key, id2.encryption_key);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let words = bip39::generate(12).unwrap();
        let id = Identity::from_mnemonic(&words).unwrap();
        let challenge = b"challenge";
        let signature = id.sign(challenge);

        assert!(id.verify(challenge, &signature));
    }

    #[test]
    fn wrong_challenge_fails_verification() {
        let words = bip39::generate(12).unwrap();
        let id = Identity::from_mnemonic(&words).unwrap();
        let signature = id.sign(b"correct_nonce");

        assert!(!id.verify(b"wrong_nonce", &signature));
    }

    #[test]
    fn cross_identity_verification_fails() {
        let words1 = bip39::generate(12).unwrap();
        let words2 = bip39::generate(12).unwrap();
        let id1 = Identity::from_mnemonic(&words1).unwrap();
        let id2 = Identity::from_mnemonic(&words2).unwrap();
        let signature = id1.sign(b"message");

        // id2 must not be able to verify id1's signature
        assert!(!id2.verify(b"message", &signature));
    }

    #[test]
    fn tampered_signature_fails() {
        let words = bip39::generate(12).unwrap();
        let id = Identity::from_mnemonic(&words).unwrap();
        let mut signature = id.sign(b"message");

        signature[0] ^= 0xFF; // flip bits in the first byte

        assert!(!id.verify(b"message", &signature));
    }

    #[test]
    fn empty_message_roundtrip() {
        let words = bip39::generate(12).unwrap();
        let id = Identity::from_mnemonic(&words).unwrap();
        let signature = id.sign(b"");

        assert!(id.verify(b"", &signature));
    }
}
