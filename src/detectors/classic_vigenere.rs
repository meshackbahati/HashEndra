//! Vigenère-family ciphers: Beaufort, Autokey, Gronsfeld, Porta.
//!
//! Conventions (matching the rest of the crate): case is preserved,
//! non-letters pass through untouched, and the key advances only on
//! alphabetic characters. Empty keys return the input unchanged.

/// Beaufort encrypt: C = (K - P) mod 26. Self-reciprocal, so this one
/// function both encrypts and decrypts.
pub fn beaufort_crypt(text: &str, key: &str) -> String {
    let shifts = alpha_shifts(key);
    if shifts.is_empty() {
        return text.to_string();
    }
    let mut key_idx = 0;
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let p = c as u8 - base;
                let k = shifts[key_idx % shifts.len()];
                key_idx += 1;
                (base + (k + 26 - p) % 26) as char
            } else {
                c
            }
        })
        .collect()
}

/// Autokey encrypt: the key is extended with the plaintext itself.
pub fn autokey_encrypt(text: &str, key: &str) -> String {
    let mut shifts = alpha_shifts(key);
    if shifts.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
            let p = c as u8 - base;
            let k = shifts[0];
            shifts.remove(0);
            shifts.push(p);
            out.push((base + (p + k) % 26) as char);
        } else {
            out.push(c);
        }
    }
    out
}

/// Autokey decrypt: the key is extended with recovered plaintext.
pub fn autokey_decrypt(text: &str, key: &str) -> String {
    let mut shifts = alpha_shifts(key);
    if shifts.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
            let v = c as u8 - base;
            let k = shifts[0];
            shifts.remove(0);
            let p = (v + 26 - k) % 26;
            shifts.push(p);
            out.push((base + p) as char);
        } else {
            out.push(c);
        }
    }
    out
}

/// Gronsfeld encrypt: Vigenère with a digit key (0-9 shifts).
pub fn gronsfeld_encrypt(text: &str, key: &str) -> String {
    let shifts = digit_shifts(key);
    if shifts.is_empty() {
        return text.to_string();
    }
    shift_text(text, &shifts, true)
}

/// Gronsfeld decrypt.
pub fn gronsfeld_decrypt(text: &str, key: &str) -> String {
    let shifts = digit_shifts(key);
    if shifts.is_empty() {
        return text.to_string();
    }
    shift_text(text, &shifts, false)
}

/// Porta encrypt. Self-reciprocal: the same function decrypts.
/// Tableau from the 13 reciprocal alphabets (A/B share table 0, …, Y/Z table 12).
pub fn porta_crypt(text: &str, key: &str) -> String {
    const TABLE: [&str; 13] = [
        "NOPQRSTUVWXYZABCDEFGHIJKLM",
        "OPQRSTUVWXYZNMABCDEFGHIJKL",
        "PQRSTUVWXYZNOLMABCDEFGHIJK",
        "QRSTUVWXYZNOPKLMABCDEFGHIJ",
        "RSTUVWXYZNOPQJKLMABCDEFGHI",
        "STUVWXYZNOPQRIJKLMABCDEFGH",
        "TUVWXYZNOPQRSHIJKLMABCDEFG",
        "UVWXYZNOPQRSTGHIJKLMABCDEF",
        "VWXYZNOPQRSTUFGHIJKLMABCDE",
        "WXYZNOPQRSTUVEFGHIJKLMABCD",
        "XYZNOPQRSTUVWDEFGHIJKLMABC",
        "YZNOPQRSTUVWXCDEFGHIJKLMAB",
        "ZNOPQRSTUVWXYBCDEFGHIJKLMA",
    ];
    let keys: Vec<usize> = key
        .to_ascii_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| (c as u8 - b'A') as usize / 2)
        .collect();
    if keys.is_empty() {
        return text.to_string();
    }
    let mut key_idx = 0;
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let upper = c.to_ascii_uppercase() as u8 - b'A';
                let row = TABLE[keys[key_idx % keys.len()]].as_bytes();
                key_idx += 1;
                let mapped = row[upper as usize] as char;
                if c.is_ascii_uppercase() {
                    mapped
                } else {
                    mapped.to_ascii_lowercase()
                }
            } else {
                c
            }
        })
        .collect()
}

/// Key letters → 0-25 shifts, skipping anything non-alphabetic.
fn alpha_shifts(key: &str) -> Vec<u8> {
    key.to_ascii_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c as u8 - b'A')
        .collect()
}

/// Key digits → 0-9 shifts, skipping anything else.
fn digit_shifts(key: &str) -> Vec<u8> {
    key.chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c as u8 - b'0')
        .collect()
}

/// Apply repeating shifts forward (encrypt) or backward (decrypt).
fn shift_text(text: &str, shifts: &[u8], forward: bool) -> String {
    let mut key_idx = 0;
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let p = c as u8 - base;
                let k = shifts[key_idx % shifts.len()];
                key_idx += 1;
                let v = if forward {
                    (p + k) % 26
                } else {
                    (p + 26 - k % 26) % 26
                };
                (base + v) as char
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beaufort_known_answer() {
        // C = (K - P): key LEMON on "ATTACKATDAWN".
        assert_eq!(beaufort_crypt("ATTACKATDAWN", "LEMON"), "LLTOLBETLNPR");
    }

    #[test]
    fn beaufort_is_reciprocal() {
        let cipher = beaufort_crypt("Hello, World!", "KEY");
        assert_eq!(beaufort_crypt(&cipher, "KEY"), "Hello, World!");
    }

    #[test]
    fn autokey_roundtrip() {
        let cipher = autokey_encrypt("ATTACKATDAWN", "QUEENLY");
        assert_eq!(cipher, "QNXEPVYTWTWP");
        assert_eq!(autokey_decrypt(&cipher, "QUEENLY"), "ATTACKATDAWN");
    }

    #[test]
    fn gronsfeld_roundtrip() {
        // Gronsfeld 2015 on ABC ≈ Vigenere key B (1)? No: digits shift as-is.
        assert_eq!(gronsfeld_encrypt("ABC", "123"), "BDF");
        assert_eq!(gronsfeld_decrypt("BDF", "123"), "ABC");
    }

    #[test]
    fn porta_known_answer() {
        // "abcdefghi" with key "key" (table rows 5,2,12 cycling).
        assert_eq!(porta_crypt("abcdefghi", "key"), "sqovtrywu");
    }

    #[test]
    fn porta_tables_are_involutions() {
        // Every row must map back: the whole point of Porta.
        const ROWS: [&str; 13] = [
            "NOPQRSTUVWXYZABCDEFGHIJKLM",
            "OPQRSTUVWXYZNMABCDEFGHIJKL",
            "PQRSTUVWXYZNOLMABCDEFGHIJK",
            "QRSTUVWXYZNOPKLMABCDEFGHIJ",
            "RSTUVWXYZNOPQJKLMABCDEFGHI",
            "STUVWXYZNOPQRIJKLMABCDEFGH",
            "TUVWXYZNOPQRSHIJKLMABCDEFG",
            "UVWXYZNOPQRSTGHIJKLMABCDEF",
            "VWXYZNOPQRSTUFGHIJKLMABCDE",
            "WXYZNOPQRSTUVEFGHIJKLMABCD",
            "XYZNOPQRSTUVWDEFGHIJKLMABC",
            "YZNOPQRSTUVWXCDEFGHIJKLMAB",
            "ZNOPQRSTUVWXYBCDEFGHIJKLMA",
        ];
        for row in ROWS {
            let bytes = row.as_bytes();
            for (i, &b) in bytes.iter().enumerate() {
                let back = bytes[(b - b'A') as usize];
                assert_eq!(back, b'A' + i as u8, "row not reciprocal: {row}");
            }
        }
    }

    #[test]
    fn porta_is_reciprocal_on_text() {
        let cipher = porta_crypt("The Quick Brown Fox!", "SECRET");
        assert_eq!(porta_crypt(&cipher, "SECRET"), "The Quick Brown Fox!");
    }

    #[test]
    fn empty_keys_pass_through() {
        assert_eq!(beaufort_crypt("ABC", ""), "ABC");
        assert_eq!(autokey_encrypt("ABC", ""), "ABC");
        assert_eq!(autokey_decrypt("ABC", ""), "ABC");
        assert_eq!(gronsfeld_encrypt("ABC", ""), "ABC");
        assert_eq!(porta_crypt("ABC", ""), "ABC");
    }
}
