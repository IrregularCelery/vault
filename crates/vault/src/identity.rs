use gate::{
    crypto::{
        argon2::{Algorithm, Argon2, Params, Version},
        bip39, blake3,
        ed25519::{Signature, Signer, SigningKey, Verifier, VerifyingKey},
        x25519::{PublicKey, StaticSecret},
    },
    sys::{
        macros::{format, vec::Vec},
        string::String,
    },
};

const KDF_SALT: &[u8] = b"vault::kdf::v1::salt";
const DOMAIN_ENCRYPTION: &str = "vault::encryption";
const DOMAIN_SIGNING: &str = "vault::signing";
const DOMAIN_EXCHANGE: &str = "vault::exchange";

#[derive(Debug)]
pub enum Error {
    InvalidMnemonic,
    UnsafeMnemonic,
    Other(String),
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

pub struct Identity {
    encryption_key: [u8; 32],

    public_signing_key: VerifyingKey,
    private_signing_key: SigningKey,

    public_exchange_key: PublicKey,
    private_exchange_key: StaticSecret,
}

impl Identity {
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

    pub fn from_seed(seed: &[u8; 64]) -> Self {
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

    fn from_phrase(phrase: &str) -> Result<Self, Error> {
        // --- Argon2id ---
        // Password -> UTF-8 bytes of the mnemonic phrase
        // Salt     -> Fixed salt (The mnemonic IS the key, no need for per-user salt)
        // Output   -> 64 bytes (32 for encryption key domain, 32 for signing key domain)
        let params = Params::new(64 * 1024, 3, 1, Some(64))
            .map_err(|e| Error::Other(format!("argon2 params: {}", e)))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = KDF_SALT;
        let mut seed = [0u8; 64];

        argon2
            .hash_password_into(phrase.as_bytes(), salt, &mut seed)
            .map_err(|e| Error::Other(format!("argon2 hash: {}", e)))?;

        Ok(Self::from_seed(&seed))
    }

    pub fn encryption_key(&self) -> [u8; 32] {
        self.encryption_key
    }

    pub fn public_signing_key(&self) -> [u8; 32] {
        self.public_signing_key.to_bytes()
    }

    pub fn public_exchange_key(&self) -> [u8; 32] {
        self.public_exchange_key.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.private_signing_key.sign(message).to_bytes()
    }

    pub fn verify(&self, message: &[u8], signature_bytes: &[u8; 64]) -> bool {
        let signature = Signature::from_bytes(signature_bytes);

        self.public_signing_key.verify(message, &signature).is_ok()
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
