use colored::*;
use hashendra::core::encoder::{encode_to_format, ENCODING_FORMATS};
use hashendra::core::hasher::{compute_hash, hash_to_hex, HashAlgorithm, HASH_ALGORITHMS};
use hashendra::safe_println;

// ──────────────────────────────────────────
// New operation handlers: hash, encode, encrypt
// ──────────────────────────────────────────

pub(crate) fn print_hash_algorithms() {
    safe_println!("{}", "Supported hash algorithms:".blue().bold());
    for algo in HASH_ALGORITHMS {
        safe_println!("  - {}", algo);
    }
}

pub(crate) fn print_encoding_formats() {
    safe_println!("{}", "Supported encoding formats:".blue().bold());
    for fmt in ENCODING_FORMATS {
        safe_println!("  - {}", fmt);
    }
}

pub(crate) fn print_encryption_ciphers() {
    safe_println!("{}", "Supported encryption ciphers:".blue().bold());
    for cipher in &["caesar", "vigenere", "affine", "rail-fence", "xor", "columnar", "atbash"] {
        safe_println!("  - {}", cipher);
    }
}

pub(crate) fn handle_hash(input: &str, algorithm: Option<&str>) -> bool {
    let algos: Vec<HashAlgorithm> = if let Some(name) = algorithm {
        match HashAlgorithm::from_name(name) {
            Some(a) => vec![a],
            None => {
                safe_println!(
                    "{} Unknown hash algorithm '{}'. Use --list-hashes to see supported algorithms.",
                    "[ERROR]".red().bold(),
                    name
                );
                return false;
            }
        }
    } else {
        // Run all algorithms
        vec![
            HashAlgorithm::Md5,
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha224,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Blake3,
        ]
    };

    let data = input.as_bytes();
    safe_println!("{}", "\n── Hash Results ──".green().bold());
    for algo in &algos {
        let digest = compute_hash(data, algo);
        let hex = hash_to_hex(&digest);
        safe_println!(
            "  {:<10} {}",
            format!("{}:", algo.name()).cyan(),
            hex
        );
    }
    true
}

pub(crate) fn handle_encode(input: &str, format: &str) -> bool {
    let result = encode_to_format(input, format);
    match result {
        Ok(encoded) => {
            safe_println!("{}", "\n── Encoded Output ──".green().bold());
            safe_println!("{}", encoded);
            true
        }
        Err(e) => {
            safe_println!(
                "{} {}",
                "[ERROR]".red().bold(),
                e
            );
            false
        }
    }
}

pub(crate) fn handle_encrypt(input: &str, cipher: &str, key: &Option<String>, _param: &Option<String>) -> bool {
    use hashendra::core::scanner::*;

    safe_println!("{}", "\n── Encrypted Output ──".green().bold());
    let result = match cipher {
        "caesar" | "rot" => {
            let shift = key.as_deref().and_then(|k| k.parse::<u8>().ok()).unwrap_or(3);
            Some(caesar_encrypt(input, shift))
        }
        "vigenere" => {
            let k = key.as_deref().unwrap_or("key");
            Some(vigenere_encrypt(input, k))
        }
        "affine" => {
            let parts: Vec<&str> = key.as_deref().unwrap_or("5,8").split(',').collect();
            let a = parts.first().and_then(|s| s.parse::<u8>().ok()).unwrap_or(5);
            let b = parts.get(1).and_then(|s| s.parse::<u8>().ok()).unwrap_or(8);
            affine_encrypt(input, a, b)
        }
        "rail-fence" | "railfence" => {
            let rails = key.as_deref().and_then(|k| k.parse::<usize>().ok()).unwrap_or(3);
            Some(rail_fence_encrypt(input, rails))
        }
        "xor" => {
            let k = key.as_deref().unwrap_or("key").as_bytes().to_vec();
            if k.is_empty() {
                safe_println!("{} Key cannot be empty for XOR cipher.", "[ERROR]".red().bold());
                return false;
            }
            let encrypted = xor_encrypt(input.as_bytes(), &k);
            let hex = encrypted.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            Some(hex)
        }
        "columnar" => {
            let k = key.as_deref().unwrap_or("key");
            Some(columnar_encrypt(input, k))
        }
        "atbash" => {
            // Atbash is self-inverse, but provide encrypt as explicit call
            let result: String = input
                .chars()
                .map(|c| match c {
                    'A'..='Z' => (b'Z' - (c as u8 - b'A')) as char,
                    'a'..='z' => (b'z' - (c as u8 - b'a')) as char,
                    _ => c,
                })
                .collect();
            Some(result)
        }
        _ => {
            safe_println!(
                "{} Unknown cipher '{}'. Use --list-ciphers to see supported ciphers.",
                "[ERROR]".red().bold(),
                cipher
            );
            return false;
        }
    };

    match result {
        Some(output) => {
            safe_println!("{}", output);
            true
        }
        None => {
            safe_println!(
                "{} Encryption failed. Check parameters.",
                "[ERROR]".red().bold()
            );
            false
        }
    }
}

// safe_print! is defined in utils/io.rs via #[macro_export]
