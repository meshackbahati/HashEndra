use colored::*;
use hashendra::core::recursive_engine::RecursiveEngine;
use hashendra::core::scanner::decode_base64_url;
use hashendra::safe_println;

/// Decode one JWT segment: pretty JSON when possible, raw text otherwise.
pub(crate) fn format_jwt_segment(segment: &str) -> Option<String> {
    let decoded = decode_base64_url(segment)?;
    let text = String::from_utf8(decoded).ok()?;
    Some(match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(json) => serde_json::to_string_pretty(&json).unwrap(),
        Err(_) => format!("{} (raw)", text),
    })
}

/// Runs deep-decrypt and reports success only on reaching plaintext.
/// Returns false when nothing unwrapped or no clear result was reached.
pub(crate) fn handle_deep_decrypt(input: &str) -> bool {
    let engine = RecursiveEngine::new(10);
    safe_println!(
        "[SCAN] Starting deep recursive unwrapping for: {}",
        input.white().bold()
    );

    let result = engine.explore_paths(input);

    for step in result.steps {
        safe_println!(
            "  [LAYER {}] Detected: {} -> {}",
            step.layer + 1,
            step.decoder.yellow(),
            step.result.green()
        );
    }

    if result.layers_unwrapped > 0 && result.confident_stop {
        safe_println!(
            "\n[OK] Fully decrypted in {} layers",
            result.layers_unwrapped
        );
        safe_println!(
            "[FINISH] Final Payload: {}",
            result.final_result.cyan().bold()
        );
        true
    } else if result.layers_unwrapped > 0 {
        safe_println!(
            "\n[i] Stopped after {} layer(s) without reaching clear plaintext.",
            result.layers_unwrapped
        );
        safe_println!(
            "[i] Best candidate so far: {}",
            result.final_result.cyan().bold()
        );
        false
    } else {
        safe_println!("\n[FAIL] No layers could be automatically unwrapped.");
        false
    }
}

pub(crate) fn handle_decode(input: &str, _context_str: &str) -> bool {
    // Delegate to RecursiveEngine for consistency with --deep-decrypt
    let engine = RecursiveEngine::new(10);
    let result = engine.explore_paths(input);

    for step in &result.steps {
        safe_println!(
            "  Layer {}: Decoded {} -> {}",
            step.layer + 1,
            step.decoder.yellow(),
            step.result.green()
        );
    }

    if result.layers_unwrapped > 0 && result.confident_stop {
        safe_println!(
            "[OK] Decoded {} layers to: {}",
            result.layers_unwrapped,
            result.final_result.cyan().bold()
        );
        true
    } else if result.layers_unwrapped > 0 {
        safe_println!(
            "[i] Unwrapped {} layer(s) but found no clear plaintext: {}",
            result.layers_unwrapped,
            result.final_result.cyan().bold()
        );
        false
    } else {
        safe_println!("[FAIL] No automatic decoding layers found.");
        false
    }
}

pub(crate) fn handle_rot(input: &str) -> bool {
    use hashendra::core::cryptanalysis::chi_squared_score;
    use hashendra::core::scanner::rot_brute_force;
    safe_println!("[ROT] Brute-forcing ROT for: {}", input);
    let results = rot_brute_force(input);
    let mut scored: Vec<(u8, String, f32)> = results
        .into_iter()
        .map(|(shift, decoded)| (shift, decoded.clone(), chi_squared_score(&decoded)))
        .collect();
    scored.sort_by(|a, b| a.2.total_cmp(&b.2));
    // `*` is the single best chi-squared match; `+` marks the other
    // plausible ones. On short inputs chi-squared is noisy — the top hit
    // is a suggestion, not a verdict.
    for (n, (shift, decoded, chi)) in scored.iter().enumerate() {
        let marker = if n == 0 {
            "* "
        } else if *chi < 150.0 {
            "+ "
        } else {
            "  "
        };
        safe_println!("  {}{:02}: {} (chi2={:.1})", marker, shift, decoded, chi);
    }
    true
}

pub(crate) fn handle_xor(input: &str) -> bool {
    use hashendra::core::scanner::{decode_hex, xor_crack};
    safe_println!("[XOR] Attempting single-byte XOR crack...");

    // Try as raw ASCII bytes first (the most common use case)
    let raw_results = xor_crack(input.as_bytes());
    if !raw_results.is_empty() {
        safe_println!("  [as raw ASCII bytes]:");
        for (key, decoded, score) in raw_results.iter().take(3) {
            safe_println!("    Key 0x{:02x} (Score {:.2}): {}", key, score, decoded);
        }
        return true;
    }

    // Fall back to hex-decoded if input looks like hex and raw didn't work
    if input.len().is_multiple_of(2)
        && input.chars().all(|c| c.is_ascii_hexdigit())
        && let Some(bytes) = decode_hex(input) {
        let hex_results = xor_crack(&bytes);
        if !hex_results.is_empty() {
            safe_println!("  [as hex-decoded bytes]:");
            for (key, decoded, score) in hex_results.iter().take(3) {
                safe_println!("    Key 0x{:02x} (Score {:.2}): {}", key, score, decoded);
            }
            return true;
        }
    }

    safe_println!("[FAIL] No plaintext found with XOR crack.");
    false
}
