/// Heuristic: returns true if the input looks like it could be ciphertext
/// (no spaces, no common English words, long enough to be worth cracking).
pub(crate) fn is_likely_ciphertext(input: &str) -> bool {
    // Too short to be meaningful ciphertext
    if input.len() < 8 {
        return false;
    }

    // Spaces are a strong indicator of plaintext
    if input.contains(' ') {
        return false;
    }

    // Statistical crackers need letters to work with. Digit-heavy
    // strings (hex digests, counters) produce noise, not cracks.
    let alpha_count = input.chars().filter(|c| c.is_ascii_alphabetic()).count();
    if alpha_count < 8 {
        return false;
    }
    if alpha_count * 5 < input.len() * 2 {
        // fewer than 40% alphabetic
        return false;
    }

    // Common English words in the lowercase version indicate plaintext
    let lower = input.to_lowercase();
    let plaintext_markers = ["the", "and", "for", "you", "are", "hello", "world", "flag"];
    for marker in &plaintext_markers {
        if lower.contains(marker) {
            return false;
        }
    }

    // If it contains braces with readable content inside, it's likely a decoded flag
    if let (Some(open), Some(close)) = (input.find('{'), input.rfind('}'))
        && open < close {
            let inside = &input[open + 1..close];
            // If the inside contains spaces or common words, it's decoded
            if inside.contains(' ') {
                return false;
            }
            let inside_lower = inside.to_lowercase();
            for marker in &plaintext_markers {
                if inside_lower.contains(marker) {
                    return false;
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
pub(crate) fn is_valid_plaintext(s: &str) -> bool {
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

/// XOR acceptance rule: printable-ratio alone admits garbage on short
/// inputs, so the result must also read as English (absolute bar) and
/// read *more* English than the input (relative bar).
pub(crate) fn xor_result_beats_input(decoded: &str, input_chi: f32) -> bool {
    let chi = crate::core::cryptanalysis::chi_squared_score(decoded);
    chi < 150.0 && chi < input_chi
}

pub(crate) fn should_stop_on_result(s: &str) -> bool {
    let lower = s.to_lowercase();
    let markers = ["the", "and", "hello", "world", "flag", "json", "http"];
    is_meaningful_plaintext_candidate(s)
        && (s.contains(' ')
            || crate::core::cryptanalysis::contains_english_patterns(&lower) > 0.08
            || markers.iter().any(|marker| lower.contains(marker)))
}

pub(crate) fn is_meaningful_plaintext_candidate(s: &str) -> bool {
    if !is_valid_plaintext(s) {
        return false;
    }

    let alpha_count = s.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let lower = s.to_lowercase();
    let english_markers = [
        "the", "and", "ing", "ion", "hello", "world", "flag", "http", "json",
    ];
    let english_like = crate::core::cryptanalysis::contains_english_patterns(&lower) > 0.08
        || english_markers.iter().any(|marker| lower.contains(marker));

    (alpha_count >= 4 && english_like)
        || s.starts_with('{')
        || s.starts_with('[')
        || s.starts_with("<?xml")
        || s.contains("://")
        || ((s.contains('{') || s.contains('_')) && english_like)
}
