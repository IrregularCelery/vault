#![no_std]

use vault::{crypto::identity::Identity, session::Session, storage::local};

use gate::{
    crypto::bip39,
    sys::{
        env, fs,
        macros::{eprintln, print, println, vec::Vec},
        process,
        string::String,
    },
};

const VAULT_DIR: &str = ".vault";

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|arg| arg.as_str()) {
        Some("identity") => identity(&args[2..]),
        Some("put") => put(&args[2..]),
        Some("get") => get(&args[2..]),
        Some("versions") => versions(&args[2..]),
        Some("get-version") => get_version(&args[2..]),
        Some("revert") => revert(&args[2..]),
        Some("drop-version") => drop_version(&args[2..]),
        Some("drop-current") => drop_version_current(&args[2..]),
        Some("detach-version") => detach_version(&args[2..]),
        Some("detach-current") => detach_version_current(&args[2..]),
        Some("rename") => rename(&args[2..]),
        Some("trash") => trash(&args[2..]),
        Some("restore") => restore(&args[2..]),
        Some("purge") => purge(&args[2..]),
        Some("delete") => delete(&args[2..]),
        Some("cleanup") => cleanup(&args[2..]),
        Some("list") => list(&args[2..]),
        Some("properties") => properties(&args[2..]),
        Some("verify") => verify(&args[2..]),
        _ => {
            eprintln!("Usage:");
            eprintln!(
                "  vault identity       [mnemonic_file]                                   generate or validate identity"
            );
            eprintln!(
                "                                                                         enter no parameters to generate"
            );
            eprintln!();
            eprintln!(
                "  vault put            <mnemonic_file> <vault_path> <local_file>         store a file"
            );
            eprintln!(
                "  vault get            <mnemonic_file> <vault_path> <out_file>           retrieve a file"
            );
            eprintln!(
                "  vault versions       <mnemonic_file> <vault_path>                      list all versions of a file"
            );
            eprintln!(
                "  vault get-version    <mnemonic_file> <vault_path> <version> <out_file> retrieve a specific version"
            );
            eprintln!(
                "  vault revert         <mnemonic_file> <vault_path> <version>            revert file to a version"
            );
            eprintln!(
                "  vault drop-version   <mnemonic_file> <vault_path> <version>            permanently delete a version"
            );
            eprintln!(
                "  vault drop-current   <mnemonic_file> <vault_path>                      drop current version, promote previous"
            );
            eprintln!(
                "  vault detach-version <mnemonic_file> <vault_path> <version> <new_path> detach a version into a new file"
            );
            eprintln!(
                "  vault detach-current <mnemonic_file> <vault_path> <new_path>           detach current version into a new file"
            );
            eprintln!(
                "  vault rename         <mnemonic_file> <vault_path> <new_vault_path>     rename/move a file"
            );
            eprintln!(
                "  vault trash          <mnemonic_file> <vault_path>                      trash a file (can be restored)"
            );
            eprintln!(
                "  vault restore        <mnemonic_file> <vault_path>                      restore a trashed file"
            );
            eprintln!(
                "  vault purge          <mnemonic_file> <vault_path>                      permanently delete a trashed file"
            );
            eprintln!(
                "  vault delete         <mnemonic_file> <vault_path>                      permanently delete a file"
            );
            eprintln!(
                "  vault cleanup        <mnemonic_file>                                   permanently delete all trashed files"
            );
            eprintln!(
                "  vault list           <mnemonic_file>                                   list all stored files"
            );
            eprintln!(
                "  vault properties     <mnemonic_file> <vault_path>                      show properties for a file"
            );
            eprintln!(
                "  vault verify         <mnemonic_file> [vault_path]                      verify integrity of files"
            );
            eprintln!();
            eprintln!("  <mnemonic_file> is a text file containing your 12 or 24 words.");
        }
    }
}

fn identity(args: &[String]) {
    if args.is_empty() {
        let mnemonic = bip39::generate(12).expect("entropy source failed");
        let words: Vec<&str> = mnemonic.iter().map(|s| s.as_str()).collect();

        println!("Mnemonic ({} words):", mnemonic.len());

        for chunk in words.chunks(3) {
            println!("  {:15} {:15} {:15}", chunk[0], chunk[1], chunk[2]);
        }

        let id = Identity::from_mnemonic(&words).expect("key derivation failed");

        println!("Public key: {}", bytes_to_hex(&id.public_key()));

        return;
    }

    if args.len() != 1 {
        eprintln!("Usage: vault identity [mnemonic_file]");

        process::exit(1);
    }

    let content = fs::read_to_string(&args[0]).unwrap_or_else(|e| {
        eprintln!("Cannot read mnemonic file `{}`: {}", args[0], e);

        process::exit(1);
    });
    let words: Vec<&str> = content.split_whitespace().collect();

    match Identity::from_mnemonic(&words) {
        Ok(id) => {
            println!("Mnemonic valid");
            println!("Public key: {}", bytes_to_hex(&id.public_key()));
        }
        Err(e) => {
            eprintln!("Error: invalid mnemonic: {}", e);

            process::exit(1);
        }
    }
}

fn put(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Usage: vault put <mnemonic_file> <vault_path> <local_file>");

        return;
    }

    let mut session = create_session(&args[0]);
    let file = fs::File::open(&args[2]).unwrap_or_else(|e| {
        eprintln!("Cannot open `{}`: {}", args[2], e);

        process::exit(1);
    });
    let size = file
        .metadata()
        .unwrap_or_else(|e| {
            eprintln!("Cannot retrieve the metadata for `{}`: {}", args[2], e);

            process::exit(1);
        })
        .len();
    let chunk_count = session.put(&args[1], file, size).unwrap_or_else(|e| {
        eprintln!("Session failed while putting `{}`: {}", args[1], e);

        process::exit(1);
    });

    println!(
        "Put `{}`. ({} bytes, {} chunk(s))",
        args[1], size, chunk_count
    );
}

fn get(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Usage: vault get <mnemonic_file> <vault_path> <out_file>");

        return;
    }

    let session = create_session(&args[0]);
    let mut file = fs::File::create(&args[2]).unwrap_or_else(|e| {
        eprintln!("Cannot create `{}`: {}", args[2], e);

        process::exit(1);
    });
    let bytes = session.get(&args[1], &mut file).unwrap_or_else(|e| {
        eprintln!("Session failed while getting `{}`: {}", args[1], e);

        process::exit(1);
    });

    println!("Got `{}` to {}. ({} bytes)", args[1], args[2], bytes);
}

fn versions(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: vault versions <mnemonic_file> <vault_path>");

        return;
    }

    let session = create_session(&args[0]);

    match session.versions(&args[1]) {
        None => {
            eprintln!("`{}` not found.", args[1]);

            process::exit(1);
        }
        Some(versions) if versions.is_empty() => {
            println!("`{}` has no previous versions.", args[1]);
        }
        Some(versions) => {
            println!("Versions for `{}`:", args[1]);

            for version in versions {
                println!(
                    "  [{}] size: {}, modified: {}, chunks: {}",
                    version.index + 1,
                    version.size,
                    version.modified,
                    version.chunk_count
                );
            }
        }
    }
}

fn get_version(args: &[String]) {
    if args.len() < 4 {
        eprintln!("Usage: vault get-version <mnemonic_file> <vault_path> <version> <out_file>");

        return;
    }

    let version_number: usize = args[2].parse().unwrap_or_else(|_| {
        eprintln!("Invalid version number `{}`.", args[2]);

        process::exit(1);
    });

    if version_number == 0 {
        eprintln!("Version number must be 1 or greater.");

        process::exit(1);
    }

    let session = create_session(&args[0]);
    let mut file = fs::File::create(&args[3]).unwrap_or_else(|e| {
        eprintln!("Cannot create `{}`: {}", args[3], e);

        process::exit(1);
    });
    let bytes = session
        .get_version(&args[1], version_number - 1, &mut file)
        .unwrap_or_else(|e| {
            eprintln!(
                "Session failed while getting version `{}` of `{}`: {}",
                version_number, args[1], e
            );

            process::exit(1);
        });

    println!(
        "Got version {} of `{}` to {}. ({} bytes)",
        version_number, args[1], args[3], bytes
    );
}

fn revert(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Usage: vault revert <mnemonic_file> <vault_path> <version>");

        return;
    }

    let version_number: usize = args[2].parse().unwrap_or_else(|_| {
        eprintln!("Invalid version number `{}`.", args[2]);

        process::exit(1);
    });

    if version_number == 0 {
        eprintln!("Version number must be 1 or greater.");

        process::exit(1);
    }

    let mut session = create_session(&args[0]);

    session
        .revert(&args[1], version_number - 1)
        .unwrap_or_else(|e| {
            eprintln!(
                "Session failed while reverting `{}` to version {}: {}",
                args[1], version_number, e
            );

            process::exit(1);
        });

    println!("Reverted `{}` to version {}.", args[1], version_number);
}

fn drop_version(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Usage: vault drop-version <mnemonic_file> <vault_path> <version>");

        return;
    }

    let version_number: usize = args[2].parse().unwrap_or_else(|_| {
        eprintln!("Invalid version number `{}`.", args[2]);

        process::exit(1);
    });

    if version_number == 0 {
        eprintln!("Version number must be 1 or greater.");

        process::exit(1);
    }

    let mut session = create_session(&args[0]);

    session
        .drop_version(&args[1], version_number - 1)
        .unwrap_or_else(|e| {
            eprintln!(
                "Session failed while dropping version {} of `{}`: {}",
                version_number, args[1], e
            );

            process::exit(1);
        });

    println!(
        "Dropped version {} of `{}`. Version was permanently deleted.",
        version_number, args[1]
    );
}

fn drop_version_current(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: vault drop-current <mnemonic_file> <vault_path>");

        return;
    }

    let mut session = create_session(&args[0]);

    session.drop_version_current(&args[1]).unwrap_or_else(|e| {
        eprintln!(
            "Session failed while dropping current version of `{}`: {}",
            args[1], e
        );

        process::exit(1);
    });

    println!("Dropped current version of `{}`.", args[1]);
}

fn detach_version(args: &[String]) {
    if args.len() < 4 {
        eprintln!(
            "Usage: vault detach-version <mnemonic_file> <vault_path> <version> <new_vault_path>"
        );

        return;
    }

    let version_number: usize = args[2].parse().unwrap_or_else(|_| {
        eprintln!("Invalid version number `{}`.", args[2]);

        process::exit(1);
    });

    if version_number == 0 {
        eprintln!("Version number must be 1 or greater.");

        process::exit(1);
    }

    let mut session = create_session(&args[0]);

    session
        .detach_version(&args[1], version_number - 1, &args[3])
        .unwrap_or_else(|e| {
            eprintln!(
                "Session failed while detaching version {} of `{}`: {}",
                version_number, args[1], e
            );

            process::exit(1);
        });

    println!(
        "Detached version {} of `{}` into `{}`.",
        version_number, args[1], args[3]
    );
}

fn detach_version_current(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Usage: vault detach-current <mnemonic_file> <vault_path> <new_vault_path>");

        return;
    }

    let mut session = create_session(&args[0]);

    session
        .detach_version_current(&args[1], &args[2])
        .unwrap_or_else(|e| {
            eprintln!(
                "Session failed while detaching current version of `{}`: {}",
                args[1], e
            );

            process::exit(1);
        });

    println!(
        "Detached current version of `{}` into `{}`.",
        args[1], args[2]
    );
}

fn rename(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Usage: vault rename <mnemonic_file> <vault_path> <new_vault_path>");

        return;
    }

    let mut session = create_session(&args[0]);

    session.rename(&args[1], &args[2]).unwrap_or_else(|e| {
        eprintln!("Session failed while renaming `{}`: {}", args[1], e);

        process::exit(1);
    });

    println!("Renamed `{}` to {}.", args[1], args[2]);
}

fn trash(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: vault trash <mnemonic_file> <vault_path>");

        return;
    }

    let mut session = create_session(&args[0]);

    session.trash(&args[1]).unwrap_or_else(|e| {
        eprintln!("Session failed while trashing `{}`: {}", args[1], e);

        process::exit(1);
    });

    println!(
        "Trashed `{}`. Run `purge` to permanently delete the file.",
        args[1]
    );
}

fn restore(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: vault restore <mnemonic_file> <vault_path>");

        return;
    }

    let mut session = create_session(&args[0]);

    session.restore(&args[1]).unwrap_or_else(|e| {
        eprintln!("Session failed while restoring `{}`: {}", args[1], e);

        process::exit(1);
    });

    println!("Restored `{}`. file is back in your vault.", args[1]);
}

fn purge(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: vault purge <mnemonic_file> <vault_path>");

        return;
    }

    let mut session = create_session(&args[0]);

    session.purge(&args[1]).unwrap_or_else(|e| {
        eprintln!("Session failed while purging `{}`: {}", args[1], e);

        process::exit(1);
    });

    println!("Purged `{}`. file was permanently deleted.", args[1]);
}

fn delete(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: vault delete <mnemonic_file> <vault_path>");

        return;
    }

    let mut session = create_session(&args[0]);

    session.delete(&args[1]).unwrap_or_else(|e| {
        eprintln!("Session failed while deleting `{}`: {}", args[1], e);

        process::exit(1);
    });

    println!("Deleted `{}`.", args[1]);
}

fn cleanup(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: vault cleanup <mnemonic_file>");

        return;
    }

    let mut session = create_session(&args[0]);

    let cleanedup = session.cleanup().unwrap_or_else(|e| {
        eprintln!("Session failed while cleaning up: {}", e);

        process::exit(1);
    });

    println!("Cleaned up {} chunks.", cleanedup);
}

fn list(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: vault list <mnemonic_file>");

        return;
    }

    let session = create_session(&args[0]);
    let paths = session.list();

    if paths.is_empty() {
        println!("Vault is empty.");

        return;
    }

    println!("Vault content:");

    for path in paths {
        println!("  {}", path);
    }
}

fn properties(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: vault properties <mnemonic_file> <vault_path>");

        return;
    }

    let session = create_session(&args[0]);

    match session.properties(&args[1]) {
        Some(p) => {
            println!("path: {}", args[1]);
            println!("versions: {}", p.version_count);
            println!("size: {}", p.size);
            println!("chunks: {}", p.chunk_count);
            println!("modified: {}", p.modified);
            print!("trashed: ");

            if p.trashed > 0 {
                println!("{}", p.trashed);

                return;
            }

            println!("(Not trashed)");
        }
        None => {
            eprintln!("`{}` not found.", args[1]);

            process::exit(1);
        }
    }
}

fn verify(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: vault verify <mnemonic_file> [vault_path]");

        return;
    }

    let session = create_session(&args[0]);

    if let Some(path) = args.get(1) {
        if let Err(e) = session.verify(path) {
            eprintln!("Verification failed for `{}`: {}", path, e);

            process::exit(1);
        }

        println!("`{}` verified successfully.", path);

        return;
    }

    let tampered = session.verify_all();

    if tampered.is_empty() {
        println!("All blobs verified successfully.");

        return;
    }

    eprintln!("Verification failed. Possible tampered entries:");

    for path in tampered {
        eprintln!("  {}", path);
    }

    process::exit(1)
}

fn create_session(mnemonic_file: &str) -> Session<local::Storage> {
    let content = fs::read_to_string(mnemonic_file).unwrap_or_else(|e| {
        eprintln!("Cannot read mnemonic file `{}`: {}", mnemonic_file, e);

        process::exit(1);
    });
    let words: Vec<&str> = content.split_whitespace().collect();

    let identity = Identity::from_mnemonic(&words).unwrap_or_else(|e| {
        eprintln!("Invalid identity: {}", e);

        process::exit(1);
    });
    let storage = local::Storage::new(VAULT_DIR, &identity.public_key()).unwrap_or_else(|e| {
        eprintln!("Cannot open storage at `{}`: {}", VAULT_DIR, e);

        process::exit(1);
    });

    Session::new(identity, storage).unwrap_or_else(|e| {
        eprintln!("Cannot create session: {}", e);

        process::exit(1);
    })
}

fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";

    let mut string = String::with_capacity(64);

    for &byte in bytes {
        string.push((LUT[(byte >> 4) as usize]) as char);
        string.push((LUT[(byte & 0x0f) as usize]) as char);
    }

    string
}
