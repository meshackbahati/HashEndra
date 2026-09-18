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

pub(crate) fn print_encryption_ciphers() {
    safe_println!("{}", "Supported ciphers (encrypt + decrypt):".blue().bold());
    for cipher in &[
        "caesar", "atbash", "affine", "vigenere", "beaufort", "autokey", "gronsfeld", "porta",
        "rail-fence", "columnar", "polybius", "tap", "adfgx", "adfgvx",
        "four-square", "two-square", "trifid", "playfair", "bifid",
        "bacon", "substitution", "xor",
    ] {
        safe_println!("  - {}", cipher);
    }
    safe_println!("Key formats: --key SHIFT | keyword | a,b | K1,K2 | 2-char alphabet; --cipher-param for rails/period/column key.");
}

/// String key with a default.
fn str_key(key: &Option<String>, default: &str) -> String {
    key.clone().unwrap_or_else(|| default.to_string())
}

/// Split "K1,K2" keys (four-square, two-square).
fn split_key(key: &Option<String>) -> (String, String) {
    let raw = key.as_deref().unwrap_or(",");
    let mut parts = raw.splitn(2, ',');
    (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
    )
}

pub(crate) fn handle_encrypt(
    input: &str,
    cipher: &str,
    key: &Option<String>,
    param: &Option<String>,
) -> bool {
    use hashendra::core::scanner::*;
    use hashendra::detectors::classic_ciphers::*;
    use hashendra::detectors::classic_playfair::*;
    use hashendra::detectors::classic_squares::*;
    use hashendra::detectors::classic_vigenere::*;

    safe_println!("{}", "\n── Encrypted Output ──".green().bold());
    let result = match cipher {
        "caesar" | "rot" => {
            let shift = key.as_deref().and_then(|k| k.parse::<u8>().ok()).unwrap_or(3);
            Some(caesar_encrypt(input, shift))
        }
        "atbash" => Some(atbash_crypt(input)),
        "vigenere" => {
            let k = str_key(key, "key");
            Some(vigenere_encrypt(input, &k))
        }
        "beaufort" => {
            let k = str_key(key, "key");
            Some(beaufort_crypt(input, &k))
        }
        "autokey" => {
            let k = str_key(key, "key");
            Some(autokey_encrypt(input, &k))
        }
        "gronsfeld" => {
            let k = str_key(key, "2015");
            Some(gronsfeld_encrypt(input, &k))
        }
        "porta" => {
            let k = str_key(key, "key");
            Some(porta_crypt(input, &k))
        }
        "affine" => {
            let parts: Vec<&str> = key.as_deref().unwrap_or("5,8").split(',').collect();
            let a = parts.first().and_then(|s| s.parse::<u8>().ok()).unwrap_or(5);
            let b = parts.get(1).and_then(|s| s.parse::<u8>().ok()).unwrap_or(8);
            affine_encrypt(input, a, b)
        }
        "rail-fence" | "railfence" => {
            let rails = param
                .as_deref()
                .or(key.as_deref())
                .and_then(|k| k.parse::<usize>().ok())
                .unwrap_or(3);
            Some(rail_fence_encrypt(input, rails))
        }
        "columnar" => {
            let k = str_key(key, "key");
            Some(columnar_encrypt(input, &k))
        }
        "polybius" => {
            let k = key.clone().unwrap_or_default();
            Some(polybius_encrypt(input, &k))
        }
        "tap" => Some(tap_encode(input)),
        "adfgx" => {
            let (sq, col) = split_key_or_param(key, param, "KEY");
            Some(adfgx_encrypt(input, &sq, &col))
        }
        "adfgvx" => {
            let (sq, col) = split_key_or_param(key, param, "KEY");
            Some(adfgvx_encrypt(input, &sq, &col))
        }
        "four-square" | "foursquare" => {
            let (k1, k2) = split_key(key);
            Some(four_square_encrypt(input, &k1, &k2))
        }
        "two-square" | "twosquare" => {
            let (k1, k2) = split_key(key);
            Some(two_square_encrypt(input, &k1, &k2))
        }
        "trifid" => {
            let k = str_key(key, "key");
            let period = param
                .as_deref()
                .and_then(|p| p.parse::<usize>().ok())
                .unwrap_or(5);
            Some(trifid_encrypt(input, &k, period))
        }
        "playfair" => {
            let k = str_key(key, "key");
            Some(playfair_encrypt(input, &k))
        }
        "bifid" => {
            let k = str_key(key, "key");
            let period = param
                .as_deref()
                .and_then(|p| p.parse::<usize>().ok())
                .unwrap_or(5);
            Some(bifid_encrypt(input, &k, period))
        }
        "bacon" => {
            let alphabet = str_key(key, "AB");
            let mut chars = alphabet.chars();
            let (a, b) = (chars.next().unwrap_or('A'), chars.next().unwrap_or('B'));
            Some(bacon_encode(input, a, b))
        }
        "substitution" => {
            let alphabet = str_key(key, "QWERTYUIOPASDFGHJKLZXCVBNM");
            match substitution_map(&alphabet) {
                Some(map) => Some(simple_substitution_encrypt(input, &map)),
                None => {
                    safe_println!(
                        "{} Substitution key must be 26 unique letters.",
                        "[ERROR]".red().bold()
                    );
                    return false;
                }
            }
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

/// Square key from --key, column key from --cipher-param (or "K1,K2" in --key).
fn split_key_or_param(
    key: &Option<String>,
    param: &Option<String>,
    default_col: &str,
) -> (String, String) {
    if let Some(col) = param {
        return (key.clone().unwrap_or_default(), col.clone());
    }
    let (k1, k2) = split_key(key);
    if k2.is_empty() {
        (k1, default_col.to_string())
    } else {
        (k1, k2)
    }
}

/// Build a plain→cipher map from a 26-letter key string.
fn substitution_map(key: &str) -> Option<std::collections::HashMap<char, char>> {
    let letters: Vec<char> = key.to_ascii_uppercase().chars().collect();
    if letters.len() != 26 || !letters.iter().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let mut seen = std::collections::HashSet::new();
    if !letters.iter().all(|c| seen.insert(*c)) {
        return None;
    }
    Some(('A'..='Z').zip(letters).collect())
}

pub(crate) fn handle_decrypt(
    input: &str,
    cipher: &str,
    key: &Option<String>,
    param: &Option<String>,
) -> bool {
    use hashendra::core::scanner::*;
    use hashendra::detectors::classic_ciphers::*;
    use hashendra::detectors::classic_playfair::*;
    use hashendra::detectors::classic_squares::*;
    use hashendra::detectors::classic_transposition::*;
    use hashendra::detectors::classic_vigenere::*;

    safe_println!("{}", "\n── Decrypted Output ──".green().bold());
    let result = match cipher {
        "caesar" | "rot" => {
            let shift = key.as_deref().and_then(|k| k.parse::<u8>().ok()).unwrap_or(3);
            Some(caesar_encrypt(input, (26 - shift % 26) % 26))
        }
        "atbash" => Some(atbash_crypt(input)),
        "vigenere" => {
            let k = str_key(key, "key");
            Some(vigenere_decode(input, &k))
        }
        "beaufort" | "porta" => {
            // Self-reciprocal: same call decrypts.
            let k = str_key(key, "key");
            if cipher == "beaufort" {
                Some(beaufort_crypt(input, &k))
            } else {
                Some(porta_crypt(input, &k))
            }
        }
        "autokey" => {
            let k = str_key(key, "key");
            Some(autokey_decrypt(input, &k))
        }
        "gronsfeld" => {
            let k = str_key(key, "2015");
            Some(gronsfeld_decrypt(input, &k))
        }
        "affine" => {
            let parts: Vec<&str> = key.as_deref().unwrap_or("5,8").split(',').collect();
            let a = parts.first().and_then(|s| s.parse::<u8>().ok()).unwrap_or(5);
            let b = parts.get(1).and_then(|s| s.parse::<u8>().ok()).unwrap_or(8);
            affine_decrypt(input, a, b)
        }
        "rail-fence" | "railfence" => {
            let rails = param
                .as_deref()
                .or(key.as_deref())
                .and_then(|k| k.parse::<usize>().ok())
                .unwrap_or(3);
            Some(rail_fence_decode(input, rails))
        }
        "columnar" => {
            let k = str_key(key, "key");
            Some(columnar_decode(input, &columnar_order(&k)))
        }
        "polybius" => {
            let k = key.clone().unwrap_or_default();
            Some(polybius_decrypt(input, &k))
        }
        "tap" => Some(tap_decode(input)),
        "adfgx" => {
            let (sq, col) = split_key_or_param(key, param, "KEY");
            Some(adfgx_decrypt(input, &sq, &col))
        }
        "adfgvx" => {
            let (sq, col) = split_key_or_param(key, param, "KEY");
            Some(adfgvx_decrypt(input, &sq, &col))
        }
        "four-square" | "foursquare" => {
            let (k1, k2) = split_key(key);
            Some(four_square_decrypt(input, &k1, &k2))
        }
        "two-square" | "twosquare" => {
            let (k1, k2) = split_key(key);
            Some(two_square_decrypt(input, &k1, &k2))
        }
        "trifid" => {
            let k = str_key(key, "key");
            let period = param
                .as_deref()
                .and_then(|p| p.parse::<usize>().ok())
                .unwrap_or(5);
            Some(trifid_decrypt(input, &k, period))
        }
        "playfair" => {
            let k = str_key(key, "key");
            Some(playfair_decode(input, &k))
        }
        "bifid" => {
            let k = str_key(key, "key");
            let period = param
                .as_deref()
                .and_then(|p| p.parse::<usize>().ok())
                .unwrap_or(5);
            Some(bifid_decrypt(input, &k, period))
        }
        "bacon" => {
            let alphabet = str_key(key, "AB");
            let mut chars = alphabet.chars();
            let (a, b) = (chars.next().unwrap_or('A'), chars.next().unwrap_or('B'));
            bacon_decode(input, a, b)
        }
        "substitution" => {
            let alphabet = str_key(key, "QWERTYUIOPASDFGHJKLZXCVBNM");
            match substitution_map(&alphabet) {
                Some(enc_map) => {
                    let dec_map: std::collections::HashMap<char, char> =
                        enc_map.into_iter().map(|(plain, cipher)| (cipher, plain)).collect();
                    Some(simple_substitution_decode(input, &dec_map))
                }
                None => {
                    safe_println!(
                        "{} Substitution key must be 26 unique letters.",
                        "[ERROR]".red().bold()
                    );
                    return false;
                }
            }
        }
        "xor" => {
            let k = key.as_deref().unwrap_or("key").as_bytes().to_vec();
            if k.is_empty() {
                safe_println!("{} Key cannot be empty for XOR cipher.", "[ERROR]".red().bold());
                return false;
            }
            // Accept hex (what --encrypt emits) or raw bytes.
            let data = decode_hex_lossy(input);
            let decrypted = xor_encrypt(&data, &k);
            Some(String::from_utf8_lossy(&decrypted).into_owned())
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
                "{} Decryption failed. Check parameters.",
                "[ERROR]".red().bold()
            );
            false
        }
    }
}

/// Hex-decode if possible, else raw bytes (never fails).
fn decode_hex_lossy(input: &str) -> Vec<u8> {
    let clean: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len().is_multiple_of(2) && !clean.is_empty()
        && let Ok(bytes) = (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
    {
        return bytes;
    }
    input.as_bytes().to_vec()
}

// safe_print! is defined in utils/io.rs via #[macro_export]
