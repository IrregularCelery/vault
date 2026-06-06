use gate::{
    crypto::{
        argon2::{Algorithm, Argon2, Params, Version},
        blake3,
        ed25519::{Signature, Signer, SigningKey, Verifier, VerifyingKey},
    },
    sys::{macros::format, string::String},
};

const KDF_SALT: &[u8] = b"vault::kdf::v1::salt";
const DOMAIN_ENCRYPTION: &[u8] = b"vault::encryption";
const DOMAIN_SIGNING: &[u8] = b"vault::signing";

pub struct Identity {
    encryption_key: [u8; 32],
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Identity {
    pub fn from_phrase(phrase: &str) -> Result<Self, String> {
        // --- Argon2id ---
        // Password -> UTF-8 bytes of the mnemonic phrase
        // Salt     -> Fixed salt (The mnemonic IS the key, no need for per-user salt)
        // Output   -> 64 bytes (32 for encryption key domain, 32 for signing key domain)
        let params =
            Params::new(64 * 1024, 3, 1, Some(64)).map_err(|e| format!("argon2 params: {}", e))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = KDF_SALT;
        let mut seed = [0u8; 64];

        argon2
            .hash_password_into(phrase.as_bytes(), salt, &mut seed)
            .map_err(|e| format!("argon2 hash: {}", e))?;

        // Separate domains by hashing each half with a domain tag
        let encryption_key = derive_subkey(&seed[..32], DOMAIN_ENCRYPTION);
        let signing_seed = derive_subkey(&seed[32..], DOMAIN_SIGNING);
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            encryption_key,
            signing_key,
            verifying_key,
        })
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub fn verify(&self, message: &[u8], signature_bytes: &[u8; 64]) -> bool {
        let signature = Signature::from_bytes(signature_bytes);

        self.verifying_key.verify(message, &signature).is_ok()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

fn derive_subkey(material: &[u8], domain: &[u8]) -> [u8; 32] {
    // BLACK3 hashing key needs exactly 32-bytes for the key
    let mut key = [0u8; 32];
    let len = material.len().min(32);
    key[..len].copy_from_slice(&material[..len]);

    // Use domain as the input so the output is bound to both the key material and the domain
    *blake3::keyed_hash(&key, domain).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon about";

    #[test]
    fn derivation_is_deterministic() {
        let id1 = Identity::from_phrase(TEST_PHRASE).unwrap();
        let id2 = Identity::from_phrase(TEST_PHRASE).unwrap();

        assert_eq!(id1.public_key_bytes(), id2.public_key_bytes());
        assert_eq!(id1.encryption_key, id2.encryption_key);
    }

    #[test]
    fn enc_and_sign_keys_are_different() {
        let id = Identity::from_phrase(TEST_PHRASE).unwrap();

        assert_ne!(id.encryption_key, id.signing_key.to_bytes());
    }

    #[test]
    fn different_mnemonics_produce_different_keys() {
        let id1 = Identity::from_phrase(TEST_PHRASE).unwrap();
        let id2 =
            Identity::from_phrase("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong").unwrap();

        assert_ne!(id1.public_key_bytes(), id2.public_key_bytes());
        assert_ne!(id1.encryption_key, id2.encryption_key);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let id = Identity::from_phrase(TEST_PHRASE).unwrap();
        let challenge = b"challenge";
        let signature = id.sign(challenge);

        assert!(id.verify(challenge, &signature));
    }

    #[test]
    fn wrong_challenge_fails_verification() {
        let id = Identity::from_phrase(TEST_PHRASE).unwrap();
        let signature = id.sign(b"correct_nonce");

        assert!(!id.verify(b"wrong_nonce", &signature));
    }
}
