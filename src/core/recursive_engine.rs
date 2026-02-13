use std::sync::{Arc, Mutex};
use crate::core::scanner::{decode_base64, decode_hex, decode_url, decode_base32};

#[derive(Debug, Clone)]
pub struct DecodeStep {
    pub layer: usize,
    pub decoder: String,
    pub result: String,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct DecodeResult {
    pub original: String,
    pub final_result: String,
    pub steps: Vec<DecodeStep>,
    pub layers_unwrapped: usize,
}

/// The core engine for recursive auto-unwrapping.
/// Supports depth-limited search with cycle detection across
/// encoding, encryption, and obfuscation layers.
pub struct RecursiveEngine {
    max_depth: usize,
    history: Arc<Mutex<Vec<String>>>,
}

impl RecursiveEngine {
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth,
            history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Attempts to deep-decrypt the input by following the highest-confidence
    /// decoding path at each layer, up to `max_depth` layers.
    pub fn explore_paths(&self, input: &str) -> DecodeResult {
        let mut steps = Vec::new();
        let mut current = input.to_string();
        let mut depth = 0;

        {
            let mut hist = self.history.lock().unwrap();
            hist.push(current.clone());
        }

        while depth < self.max_depth {
            let next_candidates = self.get_decoding_candidates(&current, depth);
            if next_candidates.is_empty() {
                break;
            }

            // Follow the highest-confidence candidate at each layer.
            let best = next_candidates.into_iter()
                .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap())
                .unwrap();

            current = best.result.clone();
            steps.push(best);
            depth += 1;

            let mut hist = self.history.lock().unwrap();
            if hist.contains(&current) {
                break; // Cycle detected
            }
            hist.push(current.clone());
        }

        DecodeResult {
            original: input.to_string(),
            final_result: current,
            steps,
            layers_unwrapped: depth,
        }
    }

    /// Generates all plausible decoding candidates for a given input at a given depth.
    fn get_decoding_candidates(&self, input: &str, depth: usize) -> Vec<DecodeStep> {
        let mut candidates = Vec::new();

        // --- Deterministic format decoders (highest priority) ---

        if let Some(dec) = decode_hex(input) {
            if let Ok(s) = String::from_utf8(dec) {
                if self.is_valid_plaintext(&s) {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Hex".to_string(),
                        result: s,
                        confidence: 1.1,
                    });
                }
            }
        }

        if let Some(dec) = decode_base64(input) {
            if let Ok(s) = String::from_utf8(dec) {
                if self.is_valid_plaintext(&s) {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Base64".to_string(),
                        result: s,
                        confidence: 1.0,
                    });
                }
            }
        }

        if let Some(dec) = decode_url(input) {
            if dec != input {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "URL".to_string(),
                    result: dec,
                    confidence: 1.0,
                });
            }
        }

        if let Some(dec) = decode_base32(input) {
            if let Ok(s) = String::from_utf8(dec) {
                if self.is_valid_plaintext(&s) {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Base32".to_string(),
                        result: s,
                        confidence: 0.9,
                    });
                }
            }
        }

        // --- Cheap monoalphabetic crackers (always try) ---
        // Caesar/ROT and Atbash are O(26) and IoC-preserving, so we try them
        // unconditionally. We keep the result only if it's strictly better
        // than the input (lower Chi-Squared score).
        // Skip if input already contains spaces (clear plaintext indicator).
        if !input.contains(' ') {
            use crate::detectors::classic_ciphers::{caesar_auto_crack, atbash_decode};

            let input_chi = crate::core::cryptanalysis::chi_squared_score(input);
            let (_, caesar_res, caesar_score) = caesar_auto_crack(input);
            // Only accept if Chi-Squared improved by at least 20%
            if caesar_score < input_chi * 0.8 && caesar_res != input {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "Caesar/ROT".to_string(),
                    result: caesar_res,
                    confidence: 0.8,
                });
            }

            let atbash_res = atbash_decode(input);
            if self.is_valid_plaintext(&atbash_res) && atbash_res != input {
                let atbash_chi = crate::core::cryptanalysis::chi_squared_score(&atbash_res);
                if atbash_chi < input_chi * 0.8 {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Atbash".to_string(),
                        result: atbash_res,
                        confidence: 0.6,
                    });
                }
            }
        }

        // --- Expensive statistical crackers (gated) ---
        // Only apply these if the input looks like ciphertext.
        if self.is_likely_ciphertext(input) {
            use crate::detectors::classic_ciphers::{
                vigenere_auto_crack, rail_fence_auto_crack, affine_auto_crack,
            };

            // Vigenere
            let (_, vig_res, vig_score) = vigenere_auto_crack(input);
            if vig_score < 70.0 && vig_res != input {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "Vigenere".to_string(),
                    result: vig_res,
                    confidence: 0.7,
                });
            }

            // Affine
            let (_, _, affine_res, affine_score) = affine_auto_crack(input);
            if affine_score < 50.0 && affine_res != input {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "Affine".to_string(),
                    result: affine_res,
                    confidence: 0.75,
                });
            }

            // Rail Fence
            let (_, rail_res, rail_score) = rail_fence_auto_crack(input);
            if rail_score < 60.0 && rail_res != input {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "Rail Fence".to_string(),
                    result: rail_res,
                    confidence: 0.65,
                });
            }
        }

        // Multi-byte XOR (only attempt on hex-like or raw input)
        if let Ok(input_bytes) = hex::decode(input)
            .or_else(|_| Ok::<Vec<u8>, ()>(input.as_bytes().to_vec()))
        {
            if let Some((_, xor_res, xor_score)) =
                crate::core::cryptanalysis::multi_byte_xor_crack(&input_bytes)
            {
                if xor_score > 0.8 && xor_res != input {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "XOR (Multi-byte)".to_string(),
                        result: xor_res,
                        confidence: xor_score,
                    });
                }
            }
        }

        candidates
    }

    /// Heuristic: returns true if the input looks like it could be ciphertext
    /// (no spaces, no common English words, long enough to be worth cracking).
    fn is_likely_ciphertext(&self, input: &str) -> bool {
        // Too short to be meaningful ciphertext
        if input.len() < 8 { return false; }

        // Spaces are a strong indicator of plaintext
        if input.contains(' ') { return false; }

        // Common English words in the lowercase version indicate plaintext
        let lower = input.to_lowercase();
        let plaintext_markers = ["the", "and", "for", "you", "are", "hello", "world", "flag"];
        for marker in &plaintext_markers {
            if lower.contains(marker) { return false; }
        }

        // If it contains braces with readable content inside, it's likely a decoded flag
        if let (Some(open), Some(close)) = (input.find('{'), input.rfind('}')) {
            if open < close {
                let inside = &input[open+1..close];
                // If the inside contains spaces or common words, it's decoded
                if inside.contains(' ') {
                    return false;
                }
                let inside_lower = inside.to_lowercase();
                for marker in &plaintext_markers {
                    if inside_lower.contains(marker) { return false; }
                }
            }
        }

        // Use IoC to check if text already has English-like letter distribution.
        // English IoC is ~0.065; random/cipher text is ~0.038.
        // If IoC > 0.055, it's likely already plaintext.
        let alpha_only: String = input.chars().filter(|c| c.is_ascii_alphabetic()).collect();
        if alpha_only.len() >= 10 {
            let ioc = crate::core::cryptanalysis::calculate_ioc(&alpha_only);
            if ioc > 0.055 {
                return false;
            }
        }

        true
    }

    /// Validates whether a decoded string looks like plausible plaintext
    /// or a recognized binary format (JSON, XML, Gzip, PE, ELF).
    fn is_valid_plaintext(&self, s: &str) -> bool {
        let bytes = s.as_bytes();

        // Structured text formats
        if s.starts_with('{') || s.starts_with('[') || s.starts_with("<?xml") {
            return true;
        }

        // Gzip magic: 1f 8b
        if bytes.len() > 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
            return true;
        }

        // PE magic: MZ
        if bytes.len() > 2 && bytes[0] == b'M' && bytes[1] == b'Z' {
            return true;
        }

        // ELF magic: 7f 45 4c 46
        if bytes.len() > 4
            && bytes[0] == 0x7f
            && bytes[1] == b'E'
            && bytes[2] == b'L'
            && bytes[3] == b'F'
        {
            return true;
        }

        // Fallback: printable ASCII with minimum length
        s.len() >= 3
            && s.chars()
                .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
    }
}
