use std::collections::HashMap;
use regex::Regex;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use crate::detectors::hashes::get_hash_signatures;
use crate::detectors::encodings::get_encoding_signatures;
use crate::detectors::ciphers::get_cipher_signatures;
use crate::detectors::stego::get_stego_signatures;

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
    Network,     // Captured traffic (pcap)
    Filesystem,  // /etc/shadow, registry hives
    Database,    // SQL dumps, CMS user tables
    Memory,      // RAM dumps, process memory
    Blockchain,  // Wallet files, block headers
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
        if let Ok(external) = load_external_signatures() {
            sigs.extend(external);
        }
        
        sigs
    };

    pub static ref COMPILED_PATTERNS: Vec<(Signature, Regex)> = ALL_SIGNATURES
        .iter()
        .map(|s| (s.clone(), Regex::new(&s.pattern).unwrap_or_else(|_| Regex::new("").unwrap())))
        .collect();
}

fn load_external_signatures() -> Result<Vec<Signature>, Box<dyn std::error::Error>> {
    let home = std::env::var("HOME")?;
    let path = format!("{}/.hashendra/signatures.json", home);
    if std::path::Path::new(&path).exists() {
        let content = std::fs::read_to_string(path)?;
        let sigs: Vec<Signature> = serde_json::from_str(&content)?;
        Ok(sigs)
    } else {
        Ok(Vec::new())
    }
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
    let mut results = Vec::new();

    for (sig, re) in COMPILED_PATTERNS.iter() {
        let match_target = if matches!(sig.detection_type, DetectionType::Stego) {
            input
        } else {
            &preprocessed
        };

        if re.is_match(match_target) {
            let confidence = crate::core::scanner::score_detection(match_target, sig, &context);
            let parameters = crate::core::scanner::extract_parameters(match_target, re, &sig.parameters);
            
            results.push(DetectionResult {
                name: sig.name.clone(),
                description: sig.description.clone(),
                confidence,
                security_rating: sig.security_rating.clone(),
                compliance_refs: sig.compliance_refs.clone(),
                extracted_parameters: parameters,
                common_name: sig.common_name.clone(),
                hashcat_mode: sig.hashcat_mode,
                john_format: sig.john_format.clone(),
            });
        }
    }

    results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    results
}
