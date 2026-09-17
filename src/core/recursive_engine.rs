use crate::core::scanner::{
    decode_ascii85, decode_base32, decode_base58, decode_base64, decode_binary, decode_hex,
    decode_html_entities, decode_morse, decode_octal, decode_quoted_printable, decode_url,
};
use super::engine_rules::{
    is_likely_ciphertext, is_meaningful_plaintext_candidate, is_valid_plaintext,
    should_stop_on_result, xor_result_beats_input,
};
use std::sync::{Arc, Mutex};

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
    /// True only when the final result tripped the plaintext stop rule.
    /// False means "best effort ran out", not "decoded".
    pub confident_stop: bool,
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
        let mut confident_stop = false;

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
            // total_cmp: NaN confidence can never panic the sort.
            let Some(best) = next_candidates
                .into_iter()
                .max_by(|a, b| a.confidence.total_cmp(&b.confidence))
            else {
                break;
            };

            current = best.result.clone();
            steps.push(best);
            depth += 1;

            let mut hist = self.history.lock().unwrap();
            if hist.contains(&current) {
                break; // Cycle detected
            }
            hist.push(current.clone());

            if should_stop_on_result(&current) {
                confident_stop = true;
                break;
            }
        }

        DecodeResult {
            original: input.to_string(),
            final_result: current,
            steps,
            layers_unwrapped: depth,
            confident_stop,
        }
    }

    /// Generates all plausible decoding candidates for a given input at a given depth.
    fn get_decoding_candidates(&self, input: &str, depth: usize) -> Vec<DecodeStep> {
        let mut candidates = Vec::new();

        // --- Deterministic format decoders (highest priority) ---

        if let Some(dec) = decode_hex(input)
            && let Ok(s) = String::from_utf8(dec)
                && is_valid_plaintext(&s) {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Hex".to_string(),
                        result: s,
                        confidence: 1.1,
                    });
                }

        if let Some(dec) = decode_base64(input)
            && let Ok(s) = String::from_utf8(dec)
                && is_valid_plaintext(&s) {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Base64".to_string(),
                        result: s,
                        confidence: 1.0,
                    });
                }

        if let Some(dec) = decode_url(input)
            && dec != input {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "URL".to_string(),
                    result: dec,
                    confidence: 1.0,
                });
            }

        if let Some(dec) = decode_base32(input)
            && let Ok(s) = String::from_utf8(dec)
                && is_valid_plaintext(&s) {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Base32".to_string(),
                        result: s,
                        confidence: 0.9,
                    });
                }

        if let Some(dec) = decode_base58(input)
            && let Ok(s) = String::from_utf8(dec)
                && is_valid_plaintext(&s) {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Base58".to_string(),
                        result: s,
                        confidence: 0.85,
                    });
                }

        if let Some(dec) = decode_binary(input)
            && let Ok(s) = String::from_utf8(dec)
                && is_valid_plaintext(&s) {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Binary".to_string(),
                        result: s,
                        confidence: 0.95,
                    });
                }

        if let Some(dec) = decode_octal(input)
            && let Ok(s) = String::from_utf8(dec)
                && is_valid_plaintext(&s) {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Octal".to_string(),
                        result: s,
                        confidence: 0.95,
                    });
                }

        if let Some(dec) = decode_ascii85(input)
            && let Ok(s) = String::from_utf8(dec)
                && is_valid_plaintext(&s) {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Ascii85".to_string(),
                        result: s,
                        confidence: 0.95,
                    });
                }

        if let Some(dec) = decode_quoted_printable(input)
            && let Ok(s) = String::from_utf8(dec)
                && is_valid_plaintext(&s) {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Quoted-Printable".to_string(),
                        result: s,
                        confidence: 0.90,
                    });
                }

        if let Some(dec) = decode_html_entities(input)
            && is_valid_plaintext(&dec) {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "HTML Entities".to_string(),
                    result: dec,
                    confidence: 0.90,
                });
            }

        if let Some(dec) = decode_morse(input)
            && is_valid_plaintext(&dec) {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "Morse".to_string(),
                    result: dec,
                    confidence: 0.90,
                });
            }

        if input
            .chars()
            .all(|c| matches!(c, 'A' | 'B' | 'a' | 'b' | ' ' | '\t' | '\n'))
        {
            use crate::detectors::classic_ciphers::bacon_decode;

            if let Some(dec) = bacon_decode(input, 'A', 'B')
                && is_valid_plaintext(&dec) && dec != input {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "Baconian".to_string(),
                        result: dec,
                        confidence: 0.80,
                    });
                }
        }

        // --- Cheap monoalphabetic crackers (always try) ---
        // Caesar/ROT and Atbash are O(26) and IoC-preserving, so we try them
        // unconditionally. We keep the result only if it's strictly better
        // than the input (lower Chi-Squared score).
        // Skip only if the input already reads as finished plaintext —
        // a spaced-out sentence like "Hello World" must not gain a layer,
        // but spaced *ciphertext* ("Uryyb Jbeyq") still gets cracked.
        if !should_stop_on_result(input) {
            use crate::core::cryptanalysis::chi_squared_score;
            use crate::core::scanner::rot_brute_force;
            use crate::detectors::classic_ciphers::atbash_decode;

            let input_chi = chi_squared_score(input);

            // All 26 shifts, best Chi-Squared first.
            let mut shifts: Vec<(f32, String)> = rot_brute_force(input)
                .into_iter()
                .filter(|(_, decoded)| decoded != input)
                .map(|(_, decoded)| {
                    let chi = chi_squared_score(&decoded);
                    (chi, decoded)
                })
                .filter(|(chi, _)| *chi < input_chi * 0.8)
                .collect();
            shifts.sort_by(|a, b| a.0.total_cmp(&b.0));

            // Prefer a shift that lands on recognizable plaintext: on short
            // inputs Chi-Squared alone picks winners by luck, but a result
            // containing real markers ("hello", "flag", spaces) is evidence.
            let pick = shifts
                .iter()
                .find(|(_, decoded)| should_stop_on_result(decoded))
                .or_else(|| shifts.first());
            if let Some((_, caesar_res)) = pick {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "Caesar/ROT".to_string(),
                    result: caesar_res.clone(),
                    confidence: 0.8,
                });
            }

            let atbash_res = atbash_decode(input);
            if is_valid_plaintext(&atbash_res) && atbash_res != input {
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
        // Only apply these if the input looks like ciphertext, is long enough
        // for statistics to mean anything (parameter estimation needs data;
        // below these floors Chi-Squared picks winners by luck), and only keep
        // results that strictly beat the input's own Chi-Squared score.
        // Absolute thresholds are meaningless across lengths; a crack must
        // make the text look *more* English, not just hit a magic number.
        if is_likely_ciphertext(input) {
            use crate::detectors::classic_ciphers::{
                affine_auto_crack, columnar_auto_crack, rail_fence_auto_crack, vigenere_auto_crack,
            };
            use crate::core::cryptanalysis::chi_squared_score;

            let input_chi = chi_squared_score(input);
            let text_len = input.chars().count();

            // Vigenere (period estimation needs data)
            let (_, vig_res, vig_score) = vigenere_auto_crack(input);
            if text_len >= 30 && vig_score < input_chi * 0.8 && vig_res != input {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "Vigenere".to_string(),
                    result: vig_res,
                    confidence: 0.7,
                });
            }

            // Affine (key estimation needs data)
            let (_, _, affine_res, affine_score) = affine_auto_crack(input);
            if text_len >= 30 && affine_score < input_chi * 0.8 && affine_res != input {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "Affine".to_string(),
                    result: affine_res,
                    confidence: 0.75,
                });
            }

            // Rail Fence (exact search over rails, but scoring still needs text)
            let (_, rail_res, rail_score) = rail_fence_auto_crack(input);
            if text_len >= 20 && rail_score < input_chi * 0.8 && rail_res != input {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "Rail Fence".to_string(),
                    result: rail_res,
                    confidence: 0.65,
                });
            }

            // Columnar Transposition (same reasoning as Rail Fence)
            let (_, columnar_res, columnar_score) = columnar_auto_crack(input);
            if text_len >= 20 && columnar_score < input_chi * 0.8 && columnar_res != input {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "Columnar".to_string(),
                    result: columnar_res,
                    confidence: 0.60,
                });
            }
        }

        // Multi-byte XOR (only attempt on hex-like or raw input).
        // Same bar as single-byte: recognizably English and strictly better.
        if let Ok(input_bytes) =
            hex::decode(input).or_else(|_| Ok::<Vec<u8>, ()>(input.as_bytes().to_vec()))
        {
            let input_chi = crate::core::cryptanalysis::chi_squared_score(input);
            let single_byte = crate::core::scanner::xor_crack(&input_bytes)
                .into_iter()
                .find(|(_, decoded, score)| {
                    *score > 0.85
                        && is_meaningful_plaintext_candidate(decoded)
                        && decoded != input
                        && xor_result_beats_input(decoded, input_chi)
                });
            if let Some((_, xor_res, xor_score)) = single_byte {
                candidates.push(DecodeStep {
                    layer: depth,
                    decoder: "XOR (Single-byte)".to_string(),
                    result: xor_res,
                    confidence: (xor_score as f32).min(0.72),
                });
            }

            if let Some((_, xor_res, xor_score)) =
                crate::core::cryptanalysis::multi_byte_xor_crack(&input_bytes)
                && xor_score > 0.8
                    && is_meaningful_plaintext_candidate(&xor_res)
                    && xor_res != input
                    && xor_result_beats_input(&xor_res, input_chi)
                {
                    candidates.push(DecodeStep {
                        layer: depth,
                        decoder: "XOR (Multi-byte)".to_string(),
                        result: xor_res,
                        confidence: xor_score.min(0.78),
                    });
                }
        }

        candidates
    }

}

#[cfg(test)]
#[path = "recursive_engine_tests.rs"]
mod tests;
