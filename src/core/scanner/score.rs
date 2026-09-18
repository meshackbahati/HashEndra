use super::codecs::{decode_base32, decode_base58};
use super::decode::{
    decode_ascii85, decode_base64, decode_base64_url, decode_binary, decode_hex,
    decode_html_entities, decode_morse, decode_octal, decode_quoted_printable, decode_url,
};
use super::{calculate_entropy, common_plaintext_marker_count, decoded_payload_confidence};
use super::{detect_charset, english_likelihood, Charset};
use crate::core::cryptanalysis::calculate_ioc;
use crate::core::patterns::{DetectionType, ScanningContext, Signature};
use regex::Regex;
use std::collections::HashMap;

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
        ScanningContext::Blockchain
            if (sig.name.contains("Bitcoin")
                || sig.name.contains("Electrum")
                || sig.name == "Base58Check")
            => {
                score *= 1.5;
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
                if !input.len().is_multiple_of(2) {
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
                if input.chars().all(|c| c.is_ascii_hexdigit()) && input.len().is_multiple_of(2) {
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
        DetectionType::Key => {
            // Key/cert patterns are near-literal; trust the authored weight.
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

    let mut cleaned = trimmed.replace(['\n', '\r'], "");

    // Only strip spaces and delimiters if the remaining chars are hex/base64-like
    let no_space = cleaned.replace(' ', "");
    let stripped = no_space
        .replace([':', '-', '.'], "");

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
        if !cleaned.len().is_multiple_of(4)
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
