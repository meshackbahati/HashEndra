use crate::core::cryptanalysis::{calculate_ioc, chi_squared_score, contains_english_patterns};
use crate::core::patterns::{DetectionType, ScanningContext, Signature};
use regex::Regex;
use std::collections::HashMap;

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

    // Check more specific formats first to avoid misclassification
    // Base58: alphanumeric excluding 0, O, I, l — check before Binary and Hex
    let has_only_01 = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .all(|c| c == '0' || c == '1');
    let has_both_01 = input.chars().any(|c| c == '0') && input.chars().any(|c| c == '1');

    let has_base64_specific = input.contains('+') || input.contains('/') || input.contains('=');
    let is_base58 = input.len() >= 4
        && !has_base64_specific
        && input
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l');
    let is_hex = input.chars().all(|c| c.is_ascii_hexdigit());
    let is_base32 = input
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | '2'..='7' | '='))
        && input.chars().any(|c| matches!(c, '2'..='7'));
    let is_base64 = input
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    let is_ascii = input.chars().all(|c| c.is_ascii());

    // Order matters: more specific checks before general ones.
    // Base32 before Base58 because Base32 (A-Z,2-7) is a subset of Base58.
    // Base58 before Base64 because Base58 is a subset of Base64 (without +/=).
    if is_hex {
        Charset::Hex
    } else if is_base32 {
        Charset::Base32
    } else if is_base58 {
        Charset::Base58
    } else if is_base64 {
        Charset::Base64
    } else if has_only_01 && has_both_01 {
        Charset::Binary
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

    for i in 0..=a_len {
        matrix[i][0] = i;
    }
    for j in 0..=b_len {
        matrix[0][j] = j;
    }

    for i in 1..=a_len {
        for j in 1..=b_len {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[a_len][b_len]
}

fn common_plaintext_marker_count(input: &str) -> usize {
    let markers = [
        "the", "and", "ing", "ion", "that", "with", "from", "hello", "world", "flag", "password",
        "admin", "http", "json",
    ];
    markers
        .iter()
        .filter(|marker| input.contains(**marker))
        .count()
}

fn has_known_binary_magic(data: &[u8]) -> bool {
    matches!(
        data,
        [0x1f, 0x8b, ..]
            | [0x50, 0x4b, 0x03, 0x04, ..]
            | [0x89, 0x50, 0x4e, 0x47, ..]
            | [0xff, 0xd8, 0xff, ..]
            | [0x7f, 0x45, 0x4c, 0x46, ..]
            | [0x25, 0x50, 0x44, 0x46, ..]
            | [0x4d, 0x5a, ..]
    )
}

fn english_likelihood(input: &str) -> f32 {
    let alpha_count = input.chars().filter(|c| c.is_ascii_alphabetic()).count();
    if alpha_count < 4 {
        return 0.0;
    }

    let lower = input.to_lowercase();
    let marker_component = (common_plaintext_marker_count(&lower).min(3) as f32) / 3.0;
    let bigram_component = contains_english_patterns(&lower).clamp(0.0, 1.0);
    let chi_component = (1.0 - (chi_squared_score(input) / 150.0)).clamp(0.0, 1.0);
    let vowel_count = input.chars().filter(|c| "aeiouAEIOU".contains(*c)).count() as f32;
    let vowel_ratio = vowel_count / alpha_count as f32;
    let vowel_component = (1.0 - ((vowel_ratio - 0.38).abs() / 0.38)).clamp(0.0, 1.0);

    (marker_component * 0.45
        + bigram_component * 0.20
        + chi_component * 0.25
        + vowel_component * 0.10)
        .clamp(0.0, 1.0)
}

pub fn decoded_payload_confidence(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    if has_known_binary_magic(data) {
        return 1.0;
    }

    let printable = data
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count() as f32
        / data.len() as f32;
    let controls = data
        .iter()
        .filter(|&&b| b.is_ascii_control() && !b.is_ascii_whitespace())
        .count() as f32
        / data.len() as f32;

    if let Ok(text) = std::str::from_utf8(data) {
        let trimmed = text.trim();
        // Only boost structured data confidence if there's meaningful content
        let structured = if trimmed.len() >= 6
            && (trimmed.starts_with('{')
                || trimmed.starts_with('[')
                || trimmed.starts_with("<?xml")
                || serde_json::from_str::<serde_json::Value>(trimmed).is_ok())
        {
            0.35
        } else {
            0.0
        };

        return (printable * 0.45
            + (1.0 - controls).clamp(0.0, 1.0) * 0.15
            + english_likelihood(text) * 0.40
            + structured)
            .clamp(0.0, 1.0);
    }

    (printable * 0.55 + (1.0 - controls).clamp(0.0, 1.0) * 0.20).clamp(0.0, 1.0)
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
            if sig.name.contains("NTLM")
                || sig.name.contains("MS-Cash")
                || sig.name.contains("Unix Crypt")
            {
                score *= 1.3; // Likely OS hashes found in /etc/shadow or registry
            }
        }
        ScanningContext::Memory => {
            if sig.name.contains("NTLM") || sig.name.contains("MS-Cash") || sig.name == "Base64" {
                score *= 1.2;
            }
        }
        ScanningContext::Database => {
            if sig.name.contains("MySQL")
                || sig.name.contains("PostgreSQL")
                || sig.name == "WordPress"
            {
                score *= 1.3; // Database dump context
            }
        }
        ScanningContext::Blockchain => {
            if sig.name.contains("Bitcoin")
                || sig.name.contains("Electrum")
                || sig.name == "Base58Check"
            {
                score *= 1.5;
            }
        }
        _ => {}
    }

    match sig.detection_type {
        DetectionType::Hash => {
            let is_bare_hex_pattern =
                sig.pattern.starts_with("^[a-fA-F0-9]{") && sig.pattern.ends_with("}$");

            // Bayesian-like adjustment:
            // If it looks like a hash (high entropy, hex), increase confidence.
            if charset == Charset::Hex && (3.5..4.5).contains(&entropy) {
                score *= 1.1;
            } else if charset != Charset::Hex && sig.pattern.contains("[a-fA-F0-9]") {
                // If the signature expects hex but we don't have hex
                score *= 0.5;
            }

            if is_bare_hex_pattern && entropy < 3.0 {
                score *= 0.5;
            }

            if input.starts_with('$') && !sig.pattern.starts_with(r"^\$") {
                score *= 0.2;
            }

            if !input.starts_with('$') && sig.pattern.starts_with(r"^\$") {
                score *= 0.05;
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
        DetectionType::Encoding => match sig.name.as_str() {
            "Hex" => {
                if input.len() % 2 != 0 {
                    score *= 0.4;
                }

                match decode_hex(input) {
                    Some(decoded) => score *= 0.55 + decoded_payload_confidence(&decoded) * 0.70,
                    None => score *= 0.1,
                }

                if matches!(input.len(), 32 | 40 | 48 | 56 | 64 | 80 | 96 | 128) && entropy > 3.2 {
                    score *= 0.35;
                }
            }
            "Base64" => {
                if input.len() < 8 {
                    score *= 0.3;
                }
                if charset == Charset::Base64 {
                    score *= 1.1;
                }
                if input.contains('=') {
                    score *= 1.15;
                }

                match decode_base64(input) {
                    Some(decoded) => score *= 0.55 + decoded_payload_confidence(&decoded) * 0.75,
                    None => score *= 0.1,
                }

                if charset == Charset::Hex || input.chars().all(|c| c.is_ascii_hexdigit()) {
                    score *= 0.1;
                }
            }
            "Base64 URL" => {
                if input.contains('-') || input.contains('_') {
                    score *= 1.2;
                } else {
                    score *= 0.75;
                }

                match decode_base64_url(input) {
                    Some(decoded) => score *= 0.55 + decoded_payload_confidence(&decoded) * 0.75,
                    None => score *= 0.1,
                }
            }
            "Base32" => {
                if input.len() < 8 {
                    score *= 0.4;
                }

                match decode_base32(input) {
                    Some(decoded) => score *= 0.55 + decoded_payload_confidence(&decoded) * 0.70,
                    None => score *= 0.1,
                }
            }
            "Base58" => {
                if input.len() < 12 {
                    score *= 0.4;
                }
                if input.chars().all(|c| c.is_ascii_hexdigit()) && input.len() % 2 == 0 {
                    score *= 0.08;
                }

                match decode_base58(input) {
                    Some(decoded) => score *= 0.50 + decoded_payload_confidence(&decoded) * 0.70,
                    None => score *= 0.1,
                }
            }
            "JWT" => {
                let parts: Vec<&str> = input.split('.').collect();
                if parts.len() == 3 {
                    let header_ok = decode_base64_url(parts[0])
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
                        .is_some();
                    let payload_ok = decode_base64_url(parts[1])
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
                        .is_some();
                    score = if header_ok && payload_ok {
                        1.0
                    } else {
                        score * 0.2
                    };
                } else {
                    score *= 0.05;
                }
            }
            "Base85 (Adobe)" => match decode_ascii85(input) {
                Some(decoded) => score *= 0.55 + decoded_payload_confidence(&decoded) * 0.75,
                None => score *= 0.1,
            },
            "Octal" => match decode_octal(input) {
                Some(decoded) => score *= 0.55 + decoded_payload_confidence(&decoded) * 0.70,
                None => score *= 0.1,
            },
            "URL Encoding" => {
                if !input.contains('%') && !input.contains('+') {
                    score *= 0.05;
                } else if let Some(decoded) = decode_url(input) {
                    score *= 0.60 + decoded_payload_confidence(decoded.as_bytes()) * 0.60;
                }
            }
            "Quoted-Printable" => match decode_quoted_printable(input) {
                Some(decoded) => score *= 0.55 + decoded_payload_confidence(&decoded) * 0.70,
                None => score *= 0.1,
            },
            "HTML Entities" => match decode_html_entities(input) {
                Some(decoded) => {
                    score *= 0.60 + decoded_payload_confidence(decoded.as_bytes()) * 0.60
                }
                None => score *= 0.1,
            },
            "Morse Code" => {
                if let Some(decoded) = decode_morse(input) {
                    score *= 0.55 + decoded_payload_confidence(decoded.as_bytes()) * 0.60;
                } else if !input.contains('.') && !input.contains('-') {
                    score *= 0.05;
                }
            }
            "Binary (0/1)" => {
                let bit_count = input.chars().filter(|c| *c == '0' || *c == '1').count();
                if bit_count < 8 {
                    score *= 0.1;
                }
                match decode_binary(input) {
                    Some(decoded) => score *= 0.55 + decoded_payload_confidence(&decoded) * 0.70,
                    None => score *= 0.1,
                }
            }
            _ => {}
        },
        DetectionType::Cipher => {
            let alpha_count = input.chars().filter(|c| c.is_ascii_alphabetic()).count();
            let lower = input.to_lowercase();
            let marker_count = common_plaintext_marker_count(&lower);
            let ic = calculate_ioc(input);
            let english_score = english_likelihood(input);

            if alpha_count < 8 {
                score *= 0.15;
            }

            if input.contains(' ') || marker_count > 0 || english_score > 0.65 {
                score *= 0.1;
            }

            if sig.name == "Caesar / ROT" {
                if !input.contains(' ') && marker_count == 0 && alpha_count >= 10 {
                    if ic > 0.055 {
                        score *= 1.1;
                    } else {
                        score *= 0.6;
                    }
                } else {
                    score *= 0.15;
                }
            }
            if sig.name == "Vigenère" {
                if !input.contains(' ')
                    && marker_count == 0
                    && alpha_count >= 20
                    && (0.035..0.055).contains(&ic)
                {
                    score *= 1.4;
                    let kl = detect_vigenere_key_length(input);
                    if kl > 1 {
                        score = 1.0;
                    } else {
                        score *= 0.5;
                    }
                } else {
                    score *= 0.2;
                }
            }
        }
        DetectionType::Stego => {
            // Placeholder for stego scoring based on statistical anomalies
            score *= 0.5;
        }
    }
    score.clamp(0.0, 1.0)
}

/// Preprocesses input to handle common malformations (auto-repair).
/// Only strips whitespace and delimiters when confident the input is
/// a hash or encoded string; preserves structure for other formats.
pub fn preprocess_input(input: &str) -> String {
    let trimmed = input.trim();

    // Fast path: if input has spaces or common delimiters, check if it
    // looks like a hash/encoding before stripping
    let has_structural_chars = trimmed.contains(' ')
        || trimmed.contains(':')
        || trimmed.contains('-')
        || trimmed.contains('.')
        || trimmed.contains('\n');

    if !has_structural_chars {
        return trimmed.to_string();
    }

    let mut cleaned = trimmed.replace('\n', "").replace('\r', "");

    // Only strip spaces and delimiters if the remaining chars are hex/base64-like
    let no_space = cleaned.replace(' ', "");
    let stripped = no_space
        .replace(':', "")
        .replace('-', "")
        .replace('.', "");

    let is_hash_like = stripped.len() >= 8
        && stripped
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '+' || c == '/' || c == '=');

    if is_hash_like {
        cleaned = no_space;
        let further = stripped;
        if further
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '+' || c == '/' || c == '=')
        {
            cleaned = further;
        }

        // Fix Base64 padding
        if cleaned.len() % 4 != 0
            && cleaned
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        {
            let missing = 4 - (cleaned.len() % 4);
            if missing < 3 {
                cleaned.push_str(&"=".repeat(missing));
            }
        }
    }

    cleaned
}

/// Extracts metadata from named capture groups in the regex.
pub fn extract_parameters(
    input: &str,
    re: &Regex,
    param_names: &[String],
) -> HashMap<String, String> {
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

fn is_bare_hex_signature(sig: &Signature) -> bool {
    matches!(sig.detection_type, DetectionType::Hash)
        && sig.pattern.starts_with("^[a-fA-F0-9]{")
        && sig.pattern.ends_with("}$")
}

pub fn apply_ambiguity_penalties(
    input: &str,
    context: &ScanningContext,
    matches: &mut [(Signature, crate::core::patterns::DetectionResult)],
) {
    let is_hex = input.chars().all(|c| c.is_ascii_hexdigit());

    // Hex-based hash ambiguity (MD5 vs NTLM vs SHA-256 etc.)
    if is_hex && matches!(input.len(), 32 | 40 | 48 | 56 | 64 | 80 | 96 | 128) {
        let bare_hash_count = matches
            .iter()
            .filter(|(sig, _)| is_bare_hex_signature(sig))
            .count();

        if bare_hash_count > 1 {
            let ambiguity_factor = match context {
                ScanningContext::Filesystem | ScanningContext::Memory => 0.85,
                ScanningContext::Blockchain => 0.88,
                ScanningContext::Database => 0.84,
                ScanningContext::Network => 0.82,
                ScanningContext::Generic => 0.80,
            };

            for (sig, result) in matches.iter_mut() {
                if is_bare_hex_signature(sig) {
                    result.confidence = (result.confidence * ambiguity_factor).min(0.89);
                }

                if sig.name == "Hex" {
                    result.confidence = result.confidence.min(0.35);
                }
            }
        }
    }

    // Non-hex encoding ambiguity (Base64 vs Base64 URL vs JWT vs Base85)
    let encoding_names = [
        "Base64", "Base64 URL", "JWT", "Base85 (Adobe)", "Base32", "Base58",
    ];
    let encoding_match_count = matches
        .iter()
        .filter(|(sig, _)| encoding_names.contains(&sig.name.as_str()))
        .count();

    if encoding_match_count > 1 {
        for (sig, result) in matches.iter_mut() {
            if encoding_names.contains(&sig.name.as_str()) {
                result.confidence *= 0.90;
            }
        }
    }
}

pub fn detect_vigenere_key_length(input: &str) -> usize {
    let clean: String = input.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    if clean.len() < 20 {
        return 0;
    }

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
    decode_base64_generic(input, false)
}

pub fn decode_base64_url(input: &str) -> Option<Vec<u8>> {
    decode_base64_generic(input, true)
}

fn decode_base64_generic(input: &str, url_safe: bool) -> Option<Vec<u8>> {
    let mut normalized = input.trim().to_string();
    if normalized.is_empty() {
        return None;
    }

    if url_safe {
        normalized = normalized.replace('-', "+").replace('_', "/");
        match normalized.len() % 4 {
            0 => {}
            2 | 3 => normalized.push_str(&"=".repeat(4 - (normalized.len() % 4))),
            _ => return None,
        }
    } else if normalized.len() % 4 != 0 {
        return None;
    }

    let chunk_count = normalized.len() / 4;
    let mut data = Vec::with_capacity(chunk_count * 3);

    for (chunk_idx, chunk) in normalized.as_bytes().chunks(4).enumerate() {
        let mut values = [0u8; 4];
        let mut padding = 0usize;

        for (i, &b) in chunk.iter().enumerate() {
            values[i] = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => 26 + b - b'a',
                b'0'..=b'9' => 52 + b - b'0',
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    padding += 1;
                    0
                }
                _ => return None,
            };

            if b == b'=' && i < 2 {
                return None;
            }

            if b != b'=' && padding > 0 {
                return None;
            }
        }

        if padding > 0 && chunk_idx + 1 != chunk_count {
            return None;
        }

        let triple = ((values[0] as u32) << 18)
            | ((values[1] as u32) << 12)
            | ((values[2] as u32) << 6)
            | (values[3] as u32);

        data.push(((triple >> 16) & 0xFF) as u8);
        if padding < 2 {
            data.push(((triple >> 8) & 0xFF) as u8);
        }
        if padding == 0 {
            data.push((triple & 0xFF) as u8);
        }
    }

    if data.is_empty() { None } else { Some(data) }
}

/// Attempts to decode Hex safely.
pub fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let normalized = input
        .replace("\\x", " ")
        .replace("\\X", " ")
        .replace("0x", " ")
        .replace("0X", " ");
    if normalized != input || input.chars().any(|c| c.is_ascii_whitespace()) {
        let joined: String = normalized.split_whitespace().collect();
        if joined.is_empty()
            || joined.len() % 2 != 0
            || !joined.chars().all(|c| c.is_ascii_hexdigit())
        {
            return None;
        }
        return decode_hex(&joined);
    }

    if input.len() % 2 != 0 {
        return None;
    }

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
            if let Some(h1) = chars.next() {
                hex.push(h1);
            }
            if let Some(h2) = chars.next() {
                hex.push(h2);
            }
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

pub fn decode_binary(input: &str) -> Option<Vec<u8>> {
    let normalized = input.replace("0b", " ").replace("0B", " ");
    let bits: String = normalized
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if bits.is_empty() || bits.len() % 8 != 0 || !bits.chars().all(|c| c == '0' || c == '1') {
        return None;
    }

    let mut result = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.as_bytes().chunks(8) {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | u8::from(bit == b'1');
        }
        result.push(byte);
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

pub fn decode_octal(input: &str) -> Option<Vec<u8>> {
    let normalized = input
        .replace("0o", " ")
        .replace("0O", " ")
        .replace('\\', " ");
    let compact: String = normalized
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    if compact.is_empty() || !compact.chars().all(|c| matches!(c, '0'..='7')) {
        return None;
    }

    let groups: Vec<String> = if normalized.chars().any(|c| c.is_ascii_whitespace()) {
        normalized
            .split_whitespace()
            .map(|group| group.to_string())
            .collect()
    } else if compact.len() % 3 == 0 {
        compact
            .as_bytes()
            .chunks(3)
            .map(|chunk| String::from_utf8(chunk.to_vec()).ok())
            .collect::<Option<Vec<_>>>()?
    } else {
        return None;
    };

    let mut decoded = Vec::with_capacity(groups.len());
    for group in groups {
        if group.is_empty() || group.len() > 3 {
            return None;
        }

        let value = u8::from_str_radix(&group, 8).ok()?;
        decoded.push(value);
    }

    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

pub fn decode_ascii85(input: &str) -> Option<Vec<u8>> {
    let trimmed = input.trim();

    // Strip optional Adobe delimiters
    let body = if trimmed.starts_with("<~") && trimmed.ends_with("~>") {
        &trimmed[2..trimmed.len().saturating_sub(2)]
    } else if trimmed.starts_with("<~") {
        &trimmed[2..]
    } else {
        trimmed
    };

    if body.is_empty() {
        return None;
    }

    let mut data = Vec::new();
    let mut block = Vec::with_capacity(5);

    for ch in body.chars().filter(|c| !c.is_ascii_whitespace()) {
        if ch == 'z' {
            if !block.is_empty() {
                return None;
            }
            data.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }

        if !('!'..='u').contains(&ch) {
            return None;
        }

        block.push((ch as u32) - 33);
        if block.len() == 5 {
            let value = block.iter().fold(0u32, |acc, digit| acc * 85 + digit);
            data.extend_from_slice(&value.to_be_bytes());
            block.clear();
        }
    }

    if !block.is_empty() {
        let original_len = block.len();
        block.resize(5, 84);
        let value = block.iter().fold(0u32, |acc, digit| acc * 85 + digit);
        let bytes = value.to_be_bytes();
        data.extend_from_slice(&bytes[..original_len - 1]);
    }

    if data.is_empty() { None } else { Some(data) }
}

pub fn decode_quoted_printable(input: &str) -> Option<Vec<u8>> {
    if !input.contains('=') {
        return None;
    }

    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut changed = false;

    while i < bytes.len() {
        if bytes[i] == b'=' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                changed = true;
                i += 2;
                continue;
            }

            if i + 2 < bytes.len() && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                changed = true;
                i += 3;
                continue;
            }

            if i + 2 < bytes.len() {
                let pair = &input[i + 1..i + 3];
                if let Ok(value) = u8::from_str_radix(pair, 16) {
                    decoded.push(value);
                    changed = true;
                    i += 3;
                    continue;
                }
            }
        }

        decoded.push(bytes[i]);
        i += 1;
    }

    if changed { Some(decoded) } else { None }
}

pub fn decode_html_entities(input: &str) -> Option<String> {
    if !input.contains('&') {
        return None;
    }

    let mut result = String::new();
    let mut chars = input.chars().peekable();
    let mut changed = false;

    while let Some(ch) = chars.next() {
        if ch != '&' {
            result.push(ch);
            continue;
        }

        let mut entity = String::new();
        while let Some(&next) = chars.peek() {
            entity.push(next);
            chars.next();
            if next == ';' || entity.len() > 10 {
                break;
            }
        }

        let decoded = if entity.ends_with(';') {
            match &entity[..entity.len() - 1] {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some(' '),
                value if value.starts_with("#x") || value.starts_with("#X") => {
                    u32::from_str_radix(&value[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                value if value.starts_with('#') => {
                    value[1..].parse::<u32>().ok().and_then(char::from_u32)
                }
                _ => None,
            }
        } else {
            None
        };

        if let Some(decoded_char) = decoded {
            result.push(decoded_char);
            changed = true;
        } else {
            result.push('&');
            result.push_str(&entity);
        }
    }

    if changed { Some(result) } else { None }
}

pub fn decode_morse(input: &str) -> Option<String> {
    if !input.contains('.') && !input.contains('-') {
        return None;
    }

    let mut words = Vec::new();
    for word in input.trim().split('/') {
        let word = word.trim();
        if word.is_empty() {
            continue;
        }

        let mut decoded = String::new();
        for symbol in word.split_whitespace() {
            let ch = match symbol {
                ".-" => 'A',
                "-..." => 'B',
                "-.-." => 'C',
                "-.." => 'D',
                "." => 'E',
                "..-." => 'F',
                "--." => 'G',
                "...." => 'H',
                ".." => 'I',
                ".---" => 'J',
                "-.-" => 'K',
                ".-.." => 'L',
                "--" => 'M',
                "-." => 'N',
                "---" => 'O',
                ".--." => 'P',
                "--.-" => 'Q',
                ".-." => 'R',
                "..." => 'S',
                "-" => 'T',
                "..-" => 'U',
                "...-" => 'V',
                ".--" => 'W',
                "-..-" => 'X',
                "-.--" => 'Y',
                "--.." => 'Z',
                "-----" => '0',
                ".----" => '1',
                "..---" => '2',
                "...--" => '3',
                "....-" => '4',
                "....." => '5',
                "-...." => '6',
                "--..." => '7',
                "---.." => '8',
                "----." => '9',
                _ => return None,
            };
            decoded.push(ch);
        }

        if !decoded.is_empty() {
            words.push(decoded);
        }
    }

    if words.is_empty() {
        None
    } else {
        Some(words.join(" "))
    }
}

/// Decodes Base32 (RFC 4648).
pub fn decode_base32(input: &str) -> Option<Vec<u8>> {
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
            if bit_count > 0 {
                bits &= (1 << bit_count) - 1;
            } else {
                bits = 0;
            }
        }
    }

    if bit_count > 0 && bits != 0 {
        return None;
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
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
        let decoded: String = input
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                    let rotated = (((c as u8 - base) + (26 - shift)) % 26) + base;
                    rotated as char
                } else {
                    c
                }
            })
            .collect();
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
        let printable = xored
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();
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

/// Encrypts text using a Caesar/ROT cipher (forward direction).
pub fn caesar_encrypt(input: &str, shift: u8) -> String {
    let shift = shift % 26;
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let rotated = (((c as u8 - base) + shift) % 26) + base;
                rotated as char
            } else {
                c
            }
        })
        .collect()
}

/// Encrypts text using a Vigenere cipher (forward direction).
pub fn vigenere_encrypt(input: &str, key: &str) -> String {
    if key.is_empty() {
        return input.to_string();
    }
    let key_upper: Vec<u8> = key.to_uppercase().bytes().collect();
    let mut key_idx = 0;
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let shift = key_upper[key_idx % key_upper.len()] - b'A';
                key_idx += 1;
                let rotated = (((c as u8 - base) + shift) % 26) + base;
                rotated as char
            } else {
                c
            }
        })
        .collect()
}

/// Encrypts text using an Affine cipher (forward direction): E(x) = (ax + b) mod 26.
pub fn affine_encrypt(input: &str, a: u8, b: u8) -> Option<String> {
    let valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
    if !valid_a.contains(&a) {
        return None;
    }
    Some(
        input
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                    let x = c as u8 - base;
                    let encrypted = ((a as u16 * x as u16 + b as u16) % 26) as u8;
                    (encrypted + base) as char
                } else {
                    c
                }
            })
            .collect(),
    )
}

/// Encrypts text using a Rail Fence cipher (forward direction).
pub fn rail_fence_encrypt(input: &str, rails: usize) -> String {
    if rails <= 1 || rails >= input.len() {
        return input.to_string();
    }
    let chars: Vec<char> = input.chars().collect();
    let mut fence = vec![Vec::new(); rails];
    let mut row = 0usize;
    let mut down = true;

    for &c in &chars {
        fence[row].push(c);
        if down {
            if row + 1 >= rails {
                down = false;
                if row > 0 { row -= 1; }
            } else {
                row += 1;
            }
        } else {
            if row == 0 {
                down = true;
                if row + 1 < rails { row += 1; }
            } else {
                row -= 1;
            }
        }
    }

    fence.into_iter().flatten().collect()
}

/// Encrypts bytes using XOR with a repeating key.
pub fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Encrypts using columnar transposition (forward direction).
pub fn columnar_encrypt(input: &str, key: &str) -> String {
    if key.is_empty() {
        return input.to_string();
    }
    let chars: Vec<char> = input.chars().collect();
    let cols = key.len();
    let rows = (chars.len() + cols - 1) / cols;
    let mut grid = vec![vec![' '; cols]; rows];

    for (i, &c) in chars.iter().enumerate() {
        grid[i / cols][i % cols] = c;
    }

    // Sort columns by key order
    let mut col_order: Vec<(usize, u8)> = key.bytes().enumerate().collect();
    col_order.sort_by_key(|&(_, b)| b);

    let mut result = String::with_capacity(chars.len());
    for &(col, _) in &col_order {
        for row in 0..rows {
            if grid[row][col] != ' ' || row * cols + col < chars.len() {
                result.push(grid[row][col]);
            }
        }
    }
    result
}
