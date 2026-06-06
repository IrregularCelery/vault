pub mod sha256 {
    use crate::sys::vec::Vec;

    const SHA_256_K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let bit_len = (data.len() as u64) * 8;

        let mut msg = Vec::with_capacity(data.len() + 1 + 8 + 64);

        msg.extend_from_slice(data);
        msg.push(0x80);

        while msg.len() % 64 != 56 {
            msg.push(0x00);
        }

        msg.extend_from_slice(&bit_len.to_be_bytes());

        // Process each 512-bit (64-byte) block
        for block in msg.chunks(64) {
            let mut w = [0u32; 64];

            for i in 0..16 {
                w[i] = u32::from_be_bytes(
                    block[i * 4..i * 4 + 4]
                        .try_into()
                        .expect("SHA-256 block slicing failed: this should never happen"),
                );
            }

            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);

                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            // Using standard naming a..h matching the specification equations
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = [
                state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
            ];

            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(SHA_256_K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            state[0] = state[0].wrapping_add(a);
            state[1] = state[1].wrapping_add(b);
            state[2] = state[2].wrapping_add(c);
            state[3] = state[3].wrapping_add(d);
            state[4] = state[4].wrapping_add(e);
            state[5] = state[5].wrapping_add(f);
            state[6] = state[6].wrapping_add(g);
            state[7] = state[7].wrapping_add(h);
        }

        let mut out = [0u8; 32];

        for (i, &word) in state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }

        out
    }

    #[cfg(test)]
    mod tests {
        use crate::sys::{macros::format, string::String};

        use super::*;

        #[test]
        fn empty_string() {
            let result = sha256(b"");

            assert_eq!(
                bytes_to_hex(&result),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
        }

        #[test]
        fn abc() {
            let result = sha256(b"abc");

            assert_eq!(
                bytes_to_hex(&result),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }

        #[test]
        fn unicode_pi() {
            let result = sha256("π".as_bytes());

            assert_eq!(
                bytes_to_hex(&result),
                "2617fcb92baa83a96341de050f07a3186657090881eae6b833f66a035600f35a"
            );
        }

        #[test]
        fn long_sentence() {
            let result = sha256(b"The quick brown fox jumps over the lazy dog");

            assert_eq!(
                bytes_to_hex(&result),
                "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
            );
        }

        #[test]
        fn length_55() {
            let data = [b'a'; 55];
            let result = sha256(&data);

            assert_eq!(
                bytes_to_hex(&result),
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
            );
        }

        #[test]
        fn length_56() {
            let data = [b'a'; 56];
            let result = sha256(&data);

            assert_eq!(
                bytes_to_hex(&result),
                "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
            );
        }

        #[test]
        fn length_63() {
            let data = [b'a'; 63];
            let result = sha256(&data);

            assert_eq!(
                bytes_to_hex(&result),
                "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"
            );
        }

        #[test]
        fn length_64() {
            let data = [b'a'; 64];
            let result = sha256(&data);

            assert_eq!(
                bytes_to_hex(&result),
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
            );
        }

        #[test]
        fn length_65() {
            let data = [b'a'; 65];
            let result = sha256(&data);

            assert_eq!(
                bytes_to_hex(&result),
                "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"
            );
        }

        // Converts a byte array to a hex string
        fn bytes_to_hex(bytes: &[u8; 32]) -> String {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        }
    }
}

pub mod argon2 {
    pub use argon2::{Algorithm, Argon2, Params, Version};
}

pub mod ed25519 {
    pub use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
}

pub mod blake3 {
    pub use blake3::keyed_hash;
}
