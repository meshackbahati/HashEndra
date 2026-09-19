use colored::*;
use hashendra::core::encoder::{encode_to_format, ENCODING_FORMATS};
use hashendra::core::hasher::{compute_hash, hash_to_hex, HashAlgorithm, HASH_ALGORITHMS};
use hashendra::safe_println;
use num_bigint::BigUint;

/// Parse a hex argument, tolerating an optional 0x prefix and whitespace.
pub(crate) fn hex_arg(s: &str, what: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() || !clean.len().is_multiple_of(2) || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        safe_println!(
            "{} {} must be even-length hex.",
            "[ERROR]".red().bold(),
            what
        );
        return None;
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).ok())
        .collect()
}

pub(crate) fn hex_key(key: &Option<String>) -> Option<Vec<u8>> {
    match key {
        Some(k) => hex_arg(k, "Key"),
        None => {
            safe_println!("{} This cipher needs --key <hex>.", "[ERROR]".red().bold());
            None
        }
    }
}

pub(crate) fn hex_key_iv(key: &Option<String>, param: &Option<String>, what: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let k = hex_key(key)?;
    let iv = match param {
        Some(p) => hex_arg(p, "IV")?,
        None => {
            safe_println!(
                "{} {} needs --cipher-param <iv/nonce-hex>.",
                "[ERROR]".red().bold(),
                what
            );
            return None;
        }
    };
    Some((k, iv))
}

pub(crate) fn hex_rsa_pair(key: &Option<String>, shape: &str) -> Option<(BigUint, BigUint)> {
    let raw = key.as_deref().unwrap_or("");
    let mut parts = raw.splitn(2, ',');
    let (a, b) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let parse = |s: &str| {
        let clean: String = s
            .trim()
            .strip_prefix("0x")
            .unwrap_or(s.trim())
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        BigUint::parse_bytes(clean.as_bytes(), 16)
    };
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => Some((x, y)),
        _ => {
            safe_println!(
                "{} RSA key must look like --key \"<hex>,<hex>\" ({}).",
                "[ERROR]".red().bold(),
                shape
            );
            None
        }
    }
}

/// Show bytes as text when UTF-8, hex otherwise.
pub(crate) fn show_bytes(bytes: &[u8]) -> String {
    match String::from_utf8(bytes.to_vec()) {
        Ok(text) => text,
        Err(_) => format!(
            "(non-UTF8, hex) {}",
            hex_of(bytes)
        ),
    }
}

pub(crate) fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn hex_bytes(input: &str, what: &str) -> Option<Vec<u8>> {
    hex_arg(input, what)
}

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

pub(crate) fn handle_hash(
    input: &str,
    algorithm: Option<&str>,
    key: &Option<String>,
    hex_input: bool,
) -> bool {
    // --hex-input: hash the decoded bytes (KDF inputs, key material).
    if hex_input {
        return match hashendra::core::scanner::decode_hex(input) {
            Some(bytes) => handle_hash_bytes(&bytes, algorithm, key),
            None => {
                safe_println!("{} Input is not valid hex.", "[ERROR]".red().bold());
                false
            }
        };
    }
    handle_hash_str(input, algorithm, key)
}

/// String-input hashing (shared tail for text and hex-decoded paths).
fn handle_hash_str(input: &str, algorithm: Option<&str>, key: &Option<String>) -> bool {
    handle_hash_bytes(input.as_bytes(), algorithm, key)
}

fn handle_hash_bytes(
    data: &[u8],
    algorithm: Option<&str>,
    key: &Option<String>,
) -> bool {
    // HMAC needs a key; everything else goes through the algorithm table.
    if let Some(name) = algorithm {
        let lower = name.to_ascii_lowercase();
        if lower == "hmac-sha256" || lower == "hmac-sha512" {
            let Some(k) = key.as_deref() else {
                safe_println!(
                    "{} HMAC needs --key <key>.",
                    "[ERROR]".red().bold()
                );
                return false;
            };
            let mac = if lower == "hmac-sha256" {
                hashendra::core::symmetric::hmac_sha256(k.as_bytes(), data)
            } else {
                hashendra::core::symmetric::hmac_sha512(k.as_bytes(), data)
            };
            safe_println!("{}", "\n── Hash Results ──".green().bold());
            safe_println!(
                "  {:<10} {}",
                format!("{}:", name).cyan(),
                mac.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            return true;
        }
    }
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

/// String key with a default.
pub(crate) fn str_key(key: &Option<String>, default: &str) -> String {
    key.clone().unwrap_or_else(|| default.to_string())
}

/// Split "K1,K2" keys (four-square, two-square).
pub(crate) fn split_key(key: &Option<String>) -> (String, String) {
    let raw = key.as_deref().unwrap_or(",");
    let mut parts = raw.splitn(2, ',');
    (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
    )
}

/// Square key from --key, column key from --cipher-param (or "K1,K2" in --key).
pub(crate) fn split_key_or_param(
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
pub(crate) fn substitution_map(key: &str) -> Option<std::collections::HashMap<char, char>> {
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

#[path = "compute_decrypt.rs"]
mod compute_decrypt;
#[path = "compute_encrypt.rs"]
mod compute_encrypt;

pub(crate) use compute_decrypt::handle_decrypt;
pub(crate) use compute_encrypt::{handle_encrypt, print_encryption_ciphers};
