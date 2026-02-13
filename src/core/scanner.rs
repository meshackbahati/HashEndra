use std::collections::HashMap;
use crate::core::patterns::{Signature, DetectionType, ScanningContext};
use crate::core::cryptanalysis::calculate_ioc;
use regex::Regex;

/// Calculates the Shannon entropy of a given byte slice.
/// Returns a value between 0.0 and 8.0.
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = HashMap::new();
    for &byte in data {
        *frequencies.entry(byte).or_insert(0) += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in frequencies.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Calculates the min-entropy of a given byte slice.
pub fn calculate_min_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = HashMap::new();
    for &byte in data {
        *frequencies.entry(byte).or_insert(0) += 1;
    }

    let max_freq = frequencies.values().cloned().max().unwrap_or(0);
    -(max_freq as f64 / data.len() as f64).log2()
}

#[derive(Debug, Clone, PartialEq)]
pub enum Charset {
    Hex,
    Base32,
    Base58,
    Base64,
    Ascii,
    Binary,
    Other,
}

/// Analyzes the character set of a string.
pub fn detect_charset(input: &str) -> Charset {
    if input.is_empty() {
        return Charset::Other;
    }

    let is_hex = input.chars().all(|c| c.is_ascii_hexdigit());
    let is_base58 = input.chars().all(|c| c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l');
    let is_base64 = input.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    let is_ascii = input.chars().all(|c| c.is_ascii());
    
    if is_hex {
        Charset::Hex
    } else if is_base58 {
        Charset::Base58
    } else if is_base64 {
        Charset::Base64
    } else if is_ascii {
        Charset::Ascii
    } else {
        Charset::Other
    }
}

/// Calculates the Levenshtein distance between two strings.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    let mut matrix = vec![vec![0; b_len + 1]; a_len + 1];

    for i in 0..=a_len { matrix[i][0] = i; }
    for j in 0..=b_len { matrix[0][j] = j; }

    for i in 1..=a_len {
        for j in 1..=b_len {
            let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[a_len][b_len]
}

/// Refines the confidence score based on entropy, charset, and other heuristics.
pub fn score_detection(input: &str, sig: &Signature, context: &ScanningContext) -> f32 {
    let mut score = sig.confidence_weight;
    
    // 1. Minimum entropy and common word check (noise reduction)
    if input.len() < 8 {
        let entropy = calculate_entropy(input.as_bytes());
        let common_words = ["test", "admin", "password", "root", "user"];
        if entropy < 2.0 || common_words.contains(&input.to_lowercase().as_str()) {
            score *= 0.3; // Aggressively downgrade non-hashy looking short strings
        }
    }

    // 2. Entropy analysis
    let entropy = calculate_entropy(input.as_bytes());
    let charset = detect_charset(input);

    // Context-Aware Intelligence
    match context {
        ScanningContext::Network => {
            if sig.name == "MD5" || sig.name == "SHA-1" {
                score *= 1.2; // Higher probability in transit (headers, session IDs)
            }
        }
        ScanningContext::Filesystem => {
            if sig.name.contains("NTLM") || sig.name.contains("Unix Crypt") {
                score *= 1.3; // Likely OS hashes found in /etc/shadow or registry
            }
        }
        ScanningContext::Database => {
            if sig.name.contains("MySQL") || sig.name.contains("PostgreSQL") || sig.name == "WordPress" {
                score *= 1.3; // Database dump context
            }
        }
        ScanningContext::Blockchain => {
            if sig.name.contains("Bitcoin") || sig.name.contains("Electrum") || sig.name == "Base58Check" {
                score *= 1.5;
            }
        }
        _ => {}
    }

    match sig.detection_type {
        DetectionType::Hash => {
            // Bayesian-like adjustment: 
            // If it looks like a hash (high entropy, hex), increase confidence.
            if charset == Charset::Hex && (3.5..4.5).contains(&entropy) {
                score *= 1.1;
            } else if charset != Charset::Hex && sig.pattern.contains("[a-fA-F0-9]") {
                // If the signature expects hex but we don't have hex
                score *= 0.5;
            }

            // Length heuristics
            let expected_len = match sig.name.as_str() {
                "MD5" | "NTLM" => 32,
                "SHA-1" => 40,
                "SHA-256" => 64,
                _ => 0,
            };
            if expected_len > 0 && input.len() != expected_len {
                score *= 0.1; // Significant penalty for wrong length
            }
        }
        DetectionType::Encoding => {
            if sig.name == "Base64" {
                if charset == Charset::Base64 {
                    score *= 1.2;
                }
                if input.contains('=') { // Padding is a strong indicator
                    score *= 1.3;
                }
            }
            if sig.name == "JWT" {
                let parts: Vec<&str> = input.split('.').collect();
                if parts.len() == 3 {
                    score = 1.0; // Very high confidence for 3 dots
                }
            }
        }
        DetectionType::Cipher => {
            let ic = calculate_ioc(input);

            if sig.name == "Caesar / ROT" {
                if ic > 0.06 {
                    score *= 1.5;
                }
            }
            if sig.name == "Vigenère" {
                if (0.04..0.06).contains(&ic) {
                    score *= 1.4;
                    let kl = detect_vigenere_key_length(input);
                    if kl > 1 {
                        score = 1.0;
                    }
                }
            }
        },
        DetectionType::Stego => {
            // Placeholder for stego scoring based on statistical anomalies
            score *= 0.5; 
        }
    }
    score.clamp(0.0, 1.0)
}

/// Preprocesses input to handle common malformations (auto-repair).
pub fn preprocess_input(input: &str) -> String {
    let mut cleaned = input.trim().to_string();
    
    // 1. Remove internal newlines and spaces
    cleaned = cleaned.replace('\n', "").replace('\r', "").replace(' ', "");

    // 2. Remove common delimiters if they appear to be part of a hex/base64 chunk
    if cleaned.contains(':') || cleaned.contains('-') || cleaned.contains('.') {
        // Only strip if the remaining characters look like hex/b64
        let stripped = cleaned.replace(':', "").replace('-', "").replace('.', "");
        if stripped.chars().all(|c| c.is_ascii_hexdigit() || c == '+' || c == '/' || c == '=') {
            cleaned = stripped;
        }
    }

    // 3. Fix Base64 padding
    if cleaned.len() % 4 != 0 && cleaned.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/') {
        let missing = 4 - (cleaned.len() % 4);
        if missing < 3 {
            cleaned.push_str(&"=".repeat(missing));
        }
    }

    cleaned
}

/// Extracts metadata from named capture groups in the regex.
pub fn extract_parameters(input: &str, re: &Regex, param_names: &[String]) -> HashMap<String, String> {
    let mut params = HashMap::new();
    if let Some(caps) = re.captures(input) {
        for name in param_names {
            if let Some(m) = caps.name(name) {
                params.insert(name.clone(), m.as_str().to_string());
            }
        }
    }
    params
}

pub fn detect_vigenere_key_length(input: &str) -> usize {
    let clean: String = input.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    if clean.len() < 20 { return 0; }

    for kl in 2..15 {
        let mut groups = vec![String::new(); kl];
        for (i, c) in clean.chars().enumerate() {
            groups[i % kl].push(c);
        }

        let mut avg_ic = 0.0;
        for g in &groups {
            avg_ic += calculate_ioc(g);
        }
        avg_ic /= kl as f32;

        if avg_ic > 0.06 {
            return kl;
        }
    }
    0
}

/// Attempts to decode Base64 safely.
pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    // Basic manual base64 decode (for zero-dep requirement)
    // Actually, let's use a simple heuristic or a small loop for common cases
    // to avoid adding external crates if possible, though 'base64' crate is common.
    // The prompt said "zero heavy dependencies", but 'regex', 'rayon' are already there.
    // I'll implement a simple one for common characters.
    let mut data = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    for c in input.chars() {
        if c == '=' { break; }
        if let Some(val) = chars.find(c) {
            buffer = (buffer << 6) | (val as u32);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                data.push((buffer >> bits) as u8);
            }
        }
    }
    if data.is_empty() { None } else { Some(data) }
}

/// Attempts to decode Hex safely.
pub fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    let mut iter = input.chars().peekable();
    while let Some(c1) = iter.next() {
        if let Some(c2) = iter.next() {
            if let (Some(v1), Some(v2)) = (c1.to_digit(16), c2.to_digit(16)) {
                data.push(((v1 << 4) | v2) as u8);
            } else {
                return None;
            }
        }
    }
    if data.is_empty() { None } else { Some(data) }
}

/// Decodes URL-encoded (percent-encoded) strings.
pub fn decode_url(input: &str) -> Option<String> {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let mut hex = String::new();
            if let Some(h1) = chars.next() { hex.push(h1); }
            if let Some(h2) = chars.next() { hex.push(h2); }
            if let Ok(v) = u8::from_str_radix(&hex, 16) {
                result.push(v as char);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    if result == input { None } else { Some(result) }
}

/// Decodes Base32 (RFC 4648).
pub fn decode_base32(input: &str) -> Option<Vec<u8>> {
    let _alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let input = input.trim_end_matches('=');
    let mut bits = 0u32;
    let mut bit_count = 0u32;
    let mut result = Vec::new();

    for &b in input.as_bytes() {
        let val = if b >= b'A' && b <= b'Z' {
            (b - b'A') as u32
        } else if b >= b'2' && b <= b'7' {
            (b - b'2' + 26) as u32
        } else if b >= b'a' && b <= b'z' {
            (b - b'a') as u32
        } else {
            return None;
        };

        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            result.push((bits >> (bit_count - 8)) as u8);
            bit_count -= 8;
        }
    }
    if result.is_empty() { None } else { Some(result) }
}

/// Decodes Base58 (Bitcoin/Flickr alphabet).
pub fn decode_base58(input: &str) -> Option<Vec<u8>> {
    use num_bigint::BigUint;

    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut value = BigUint::from(0u32);
    let b58_base = BigUint::from(58u32);

    for &b in input.as_bytes() {
        if let Some(pos) = alphabet.iter().position(|&x| x == b) {
            value = value * &b58_base + BigUint::from(pos);
        } else {
            return None;
        }
    }
    
    let mut result = value.to_bytes_be();
    // Prepend zeros for '1's at the beginning of input (leading zeroes in Base58)
    for &b in input.as_bytes() {
        if b == b'1' {
            result.insert(0, 0);
        } else {
            break;
        }
    }
    if result.is_empty() && !input.is_empty() && input.chars().all(|c| c == '1') {
        Some(vec![0; input.len()])
    } else if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Brute-forces ROT ciphers (1-25).
pub fn rot_brute_force(input: &str) -> Vec<(u8, String)> {
    let mut results = Vec::new();
    for shift in 1..26u8 {
        let decoded: String = input.chars().map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let rotated = (((c as u8 - base) + (26 - shift)) % 26) + base;
                rotated as char
            } else {
                c
            }
        }).collect();
        results.push((shift, decoded));
    }
    results
}

/// Attempts to crack single-byte XOR.
pub fn xor_crack(input: &[u8]) -> Vec<(u8, String, f64)> {
    let mut results = Vec::new();
    for key in 0..=255u8 {
        let xored: Vec<u8> = input.iter().map(|&b| b ^ key).collect();
        // Simple heuristic: count printable characters
        let printable = xored.iter().filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace()).count();
        let score = printable as f64 / xored.len() as f64;
        
        if score > 0.8 {
            if let Ok(s) = String::from_utf8(xored) {
                results.push((key, s, score));
            }
        }
    }
    results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
    results
}


