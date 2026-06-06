#![no_std]

use gate::{
    crypto::bip39,
    sys::{
        env,
        macros::{eprintln, format, println, vec::Vec},
        string::String,
    },
};
use vault::crypto::keys::Identity;

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|arg| arg.as_str()) {
        Some("generate") => generate_identity(),
        Some("restore") => restore_identity(&args[2..]),
        _ => {
            eprintln!("Usage:");
            eprintln!("  generate identity");
            eprintln!("  restore identity");
        }
    }
}

fn generate_identity() {
    let mnemonic = bip39::generate(12).expect("entropy source failed");
    let joined = mnemonic.join(" ");

    println!("Mnemonic ({} words):", mnemonic.len());
    println!("  {}\n", joined);

    let id = Identity::from_phrase(&joined).expect("key derivation failed");

    println!("Public key: {}", bytes_to_hex(&id.public_key_bytes()));
}

fn restore_identity(words: &[String]) {
    let mnemonic: Vec<&str> = words.iter().map(|word| word.as_str()).collect();

    match bip39::validate(&mnemonic) {
        Ok(()) => {
            println!("Mnemonic valid");

            let id = Identity::from_phrase(&mnemonic.join(" ")).expect("key derivation failed");

            println!("Public key: {}", bytes_to_hex(&id.public_key_bytes()));
        }
        Err(e) => eprintln!("Error: invalid mnemonic: {}", e),
    }
}

fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
