use crate::core::cryptanalysis::{chi_squared_score, contains_english_patterns};
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
    let is_ascii = input.is_ascii();

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

    for (i, row) in matrix.iter_mut().enumerate() {
        row[0] = i;
    }
    if let Some(first) = matrix.first_mut() {
        for (j, cell) in first.iter_mut().enumerate() {
            *cell = j;
        }
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

pub mod codecs;
pub mod decode;
pub mod score;

pub use codecs::*;
pub use decode::*;
pub use score::*;
