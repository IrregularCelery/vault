use gate::{
    crypto::sha256,
    sys::{
        macros::{format, vec},
        random::{self, Rng},
        string::{String, ToString},
        vec::Vec,
    },
};

pub fn generate(word_count: usize) -> Result<Vec<String>, &'static str> {
    let entropy_bits = match word_count {
        12 => 128,
        24 => 256,
        _ => return Err("word count must be 12 or 24"),
    };
    let mut entropy = vec![0u8; entropy_bits / 8]; // Divide by 8 for bytes

    random::rng().fill_bytes(&mut entropy);

    entropy_to_mnemonic(&entropy)
}

pub fn validate(words: &[&str]) -> Result<(), String> {
    if words.len() != 12 && words.len() != 24 {
        return Err(format!("expected 12 or 24 words, got {}", words.len()));
    }

    let list = wordlist();
    let mut bits: Vec<bool> = Vec::with_capacity(words.len() * 11);

    for word in words {
        let index = list
            .binary_search(word)
            .map_err(|_| format!("Unknown word: {}", word))?;

        // Each word encodes 11 bits
        for bit in (0..11).rev() {
            bits.push((index >> bit) & 1 == 1);
        }
    }

    // Total bits = words * 11; Entropy + Checksum bit
    let total = bits.len(); // 132 for 12 words - 264 for 24
    let checksum_len = total / 33; // 4 for 12 words - 8 for 24
    let entropy_len = total - checksum_len;
    let entropy = bits_to_bytes(&bits[..entropy_len]);
    let checksum_bits = sha256_first_bits(&entropy, checksum_len);
    let provided_checksum = &bits[entropy_len..];

    if provided_checksum != checksum_bits.as_slice() {
        return Err("checksum mismatch".to_string());
    }

    Ok(())
}

fn wordlist() -> &'static [&'static str] {
    super::wordlist::BIP39
}

fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8)
        .map(|chunk| {
            chunk.iter().enumerate().fold(0u8, |byte, (index, &bit)| {
                byte | ((bit as u8) << (7 - index))
            })
            // NOTE: Most significant bit first encoding hence the (7 - i)
        })
        .collect()
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);

    for &byte in bytes {
        // NOTE: Extract bits Most significant bit first
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }

    bits
}

fn sha256_first_bits(data: &[u8], count: usize) -> Vec<bool> {
    let hash = sha256::sha256(data);
    let bits = bytes_to_bits(&hash);

    bits[..count.min(256)].to_vec()
}

fn entropy_to_mnemonic(entropy: &[u8]) -> Result<Vec<String>, &'static str> {
    let entropy_bits = entropy.len() * 8;
    let checksum_bits = entropy_bits / 32;
    let checksum = sha256_first_bits(entropy, checksum_bits);
    let mut bits: Vec<bool> = bytes_to_bits(entropy);

    // Bit stream; Entropy bits + Checksum bits
    bits.extend_from_slice(&checksum);

    let list = wordlist();

    if list.len() != 2048 {
        return Err("bip39 wordlist must have exactly 2048 entries");
    }

    let word_count = bits.len() / 11;
    let mut words = Vec::with_capacity(word_count);

    for i in 0..word_count {
        let mut index = 0usize;

        for bit in 0..11 {
            index = (index << 1) | (bits[i * 11 + bit] as usize);
        }

        words.push(list[index].to_string());
    }

    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_12_returns_12_words() {
        assert_eq!(generate(12).unwrap().len(), 12);
    }

    #[test]
    fn generate_24_returns_24_words() {
        assert_eq!(generate(24).unwrap().len(), 24);
    }

    #[test]
    fn generate_words_are_all_valid_bip39() {
        let list = wordlist();

        for word in generate(12).unwrap() {
            assert!(list.contains(&word.as_str()), "unknown word: {word}");
        }
    }

    #[test]
    fn roundtrip_12_words() {
        let words = generate(12).unwrap();
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();

        assert!(validate(&refs).is_ok());
    }

    #[test]
    fn roundtrip_24_words() {
        let words = generate(24).unwrap();
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();

        assert!(validate(&refs).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_word_counts() {
        let words = generate(12).unwrap();
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();

        assert!(validate(&[]).is_err());
        assert!(validate(&refs[..1]).is_err());
        assert!(validate(&refs[..11]).is_err());
    }

    #[test]
    fn validate_rejects_unknown_word() {
        let words = generate(12).unwrap();
        let mut refs: Vec<&str> = words.iter().map(String::as_str).collect();

        refs[4] = "poop";

        let err = validate(&refs).unwrap_err();

        assert!(err.contains("poop"));
    }

    #[test]
    fn validate_rejects_bad_checksum() {
        let words = [
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon",
        ];

        assert!(validate(&words).is_err());
    }

    #[test]
    fn validate_rejects_swapped_words() {
        // The swapped version of 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f vector should produce different
        // entropy and should return checksum mismatch
        let valid = [
            "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal",
            "winner", "thank", "yellow",
        ];
        let swapped = [
            "winner", "legal", "thank", "year", "wave", "sausage", "worth", "useful", "legal",
            "winner", "thank", "yellow",
        ];

        assert!(validate(&valid).is_ok());
        assert!(validate(&swapped).is_err());
    }

    // Known BIP39 vectors (https://github.com/trezor/python-mnemonic/blob/master/vectors.json)

    #[test]
    fn vector_12_all_zeros() {
        assert_vector(
            "00000000000000000000000000000000",
            &[
                "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                "abandon", "abandon", "abandon", "abandon", "about",
            ],
        );
    }

    #[test]
    fn vector_12_all_ones() {
        assert_vector(
            "ffffffffffffffffffffffffffffffff",
            &[
                "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo",
                "wrong",
            ],
        );
    }

    #[test]
    fn vector_12_7f() {
        assert_vector(
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            &[
                "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal",
                "winner", "thank", "yellow",
            ],
        );
    }

    #[test]
    fn vector_12_80() {
        assert_vector(
            "80808080808080808080808080808080",
            &[
                "letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid",
                "letter", "advice", "cage", "above",
            ],
        );
    }

    #[test]
    fn vector_24_all_zeros() {
        assert_vector(
            "0000000000000000000000000000000000000000000000000000000000000000",
            &[
                "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                "abandon", "abandon", "art",
            ],
        );
    }

    #[test]
    fn vector_24_all_ones() {
        assert_vector(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            &[
                "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo",
                "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo",
                "vote",
            ],
        );
    }

    fn assert_vector(entropy_hex: &str, expected: &[&str]) {
        let entropy: Vec<u8> = (0..entropy_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&entropy_hex[i..i + 2], 16).unwrap())
            .collect();

        let words = entropy_to_mnemonic(&entropy).unwrap();

        assert_eq!(words, expected, "entropy_to_mnemonic mismatch");

        let refs: Vec<&str> = words.iter().map(String::as_str).collect();

        assert!(
            validate(&refs).is_ok(),
            "validate rejected a known-good mnemonic"
        );
    }
}
