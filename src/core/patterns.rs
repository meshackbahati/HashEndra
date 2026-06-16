use crate::detectors::ciphers::get_cipher_signatures;
use crate::detectors::encodings::get_encoding_signatures;
use crate::detectors::hashes::get_hash_signatures;
use crate::detectors::stego::get_stego_signatures;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityRating {
    Secure,   // Modern, strong algorithms (e.g., Argon2, SHA-3)
    Weak,     // Not broken but fast/older (e.g., SHA-1, PBKDF2 with low iterations)
    Broken,   // Known collision attacks (e.g., MD5)
    Insecure, // Trivial to crack (e.g., 40-bit RC4, 56-bit DES)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanningContext {
    Generic,
    Network,    // Captured traffic (pcap)
    Filesystem, // /etc/shadow, registry hives
    Database,   // SQL dumps, CMS user tables
    Memory,     // RAM dumps, process memory
    Blockchain, // Wallet files, block headers
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionType {
    Hash,
    Encoding,
    Cipher,
    Stego,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub name: String,
    pub description: String,
    pub pattern: String,
    pub detection_type: DetectionType,
    pub confidence_weight: f32,
    pub common_name: Option<String>,
    pub hashcat_mode: Option<u32>,
    pub john_format: Option<String>,
    pub security_rating: Option<SecurityRating>,
    pub compliance_refs: Vec<String>, // e.g., ["PCI DSS 4.0", "NIST SP 800-63"]
    pub parameters: Vec<String>,      // Names of capturing groups in the pattern
}

lazy_static! {
    pub static ref ALL_SIGNATURES: Vec<Signature> = {
        let mut sigs = get_hash_signatures();
        sigs.extend(get_encoding_signatures());
        sigs.extend(get_cipher_signatures());
        sigs.extend(get_stego_signatures());

        // Load external signatures if present
        match load_external_signatures() {
            Ok(external) => sigs.extend(external),
            Err(e) => eprintln!("WARN: {}", e),
        }

        sigs
    };

    pub static ref COMPILED_PATTERNS: Vec<(Signature, Regex)> = {
        let mut compiled = Vec::with_capacity(ALL_SIGNATURES.len());
        for s in ALL_SIGNATURES.iter() {
            match Regex::new(&s.pattern) {
                Ok(re) => compiled.push((s.clone(), re)),
                Err(e) => {
                    eprintln!(
                        "WARN: signature \"{}\" has malformed regex pattern \"{}\": {}",
                        s.name, s.pattern, e
                    );
                }
            }
        }
        compiled
    };

    /// Number of external (user-defined) signatures loaded.
    pub static ref EXTERNAL_SIGNATURE_COUNT: usize = {
        match load_external_signatures() {
            Ok(sigs) => sigs.len(),
            Err(_) => 0,
        }
    };
}

fn load_external_signatures() -> Result<Vec<Signature>, String> {
    let home = std::env::var("HOME").map_err(|e| format!("cannot determine HOME directory: {}", e))?;
    let path = format!("{}/.hashendra/signatures.json", home);
    load_external_signatures_from_path(&path)
}

/// Load custom signatures from a specific JSON file path.
pub fn load_external_signatures_from_path(path: &str) -> Result<Vec<Signature>, String> {
    if !std::path::Path::new(path).exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path, e))?;
    let sigs: Vec<Signature> = serde_json::from_str(&content)
        .map_err(|e| format!("malformed JSON in {}: {}", path, e))?;
    Ok(sigs)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub name: String,
    pub description: String,
    pub confidence: f32,
    pub security_rating: Option<SecurityRating>,
    pub compliance_refs: Vec<String>,
    pub extracted_parameters: HashMap<String, String>,
    pub common_name: Option<String>,
    pub hashcat_mode: Option<u32>,
    pub john_format: Option<String>,
}

pub fn scan_input(input: &str, context: ScanningContext) -> Vec<DetectionResult> {
    let preprocessed = crate::core::scanner::preprocess_input(input);
    let mut matched = Vec::new();

    for (sig, re) in COMPILED_PATTERNS.iter() {
        let match_target = if matches!(sig.detection_type, DetectionType::Stego) {
            input
        } else {
            &preprocessed
        };

        if re.is_match(match_target) {
            let confidence = crate::core::scanner::score_detection(match_target, sig, &context);
            let parameters =
                crate::core::scanner::extract_parameters(match_target, re, &sig.parameters);

            let result = DetectionResult {
                name: sig.name.clone(),
                description: sig.description.clone(),
                confidence,
                security_rating: sig.security_rating.clone(),
                compliance_refs: sig.compliance_refs.clone(),
                extracted_parameters: parameters,
                common_name: sig.common_name.clone(),
                hashcat_mode: sig.hashcat_mode,
                john_format: sig.john_format.clone(),
            };

            if result.confidence >= 0.20 {
                matched.push((sig.clone(), result));
            }
        }
    }

    crate::core::scanner::apply_ambiguity_penalties(&preprocessed, &context, &mut matched);

    let mut results: Vec<DetectionResult> = matched.into_iter().map(|(_, result)| result).collect();
    results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    results
}
