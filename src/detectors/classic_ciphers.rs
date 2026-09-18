use crate::core::cryptanalysis::chi_squared_score;
use std::sync::atomic::{AtomicU32, Ordering};

/// Automatically cracks a Caesar/ROT cipher by testing all 26 shifts
/// and choosing the one with the best Chi-Squared score.
pub fn caesar_auto_crack(text: &str) -> (u8, String, f32) {
    let mut best_shift = 0;
    let mut best_text = text.to_string();
    let mut best_score = f32::MAX;

    for shift in 0..26 {
        let decoded: String = text
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                    let rotated =
                        (((c as u8 - base) as i16 + (26 - shift) as i16) % 26) as u8 + base;
                    rotated as char
                } else {
                    c
                }
            })
            .collect();

        let score = chi_squared_score(&decoded);
        if score < best_score {
            best_score = score;
            best_shift = shift as u8;
            best_text = decoded;
        }
    }

    (best_shift, best_text, best_score)
}

/// Atbash transform (alphabet reversal). Self-inverse: encrypt and decrypt
/// are the same call.
pub fn atbash_crypt(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                (b'Z' - (c as u8 - b'A')) as char
            } else if c.is_ascii_lowercase() {
                (b'z' - (c as u8 - b'a')) as char
            } else {
                c
            }
        })
        .collect()
}

/// Decodes an Atbash cipher (alphabet reversal).
pub fn atbash_decode(text: &str) -> String {
    atbash_crypt(text)
}

/// Automatically cracks an Affine cipher (ax + b mod 26).
/// Tests all 12 valid values of 'a' and 26 values of 'b'.
pub fn affine_auto_crack(text: &str) -> (u8, u8, String, f32) {
    let valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
    let mut best_a = 1;
    let mut best_b = 0;
    let mut best_text = text.to_string();
    let mut best_score = f32::MAX;

    for &a in &valid_a {
        // Find modular multiplicative inverse of 'a' mod 26
        let mut a_inv = 0;
        for i in 0..26 {
            if (a * i) % 26 == 1 {
                a_inv = i;
                break;
            }
        }

        for b in 0..26 {
            let decoded: String = text
                .chars()
                .map(|c| {
                    if c.is_ascii_alphabetic() {
                        let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                        let x = c as u8 - base;
                        // Formula: D(y) = a_inv * (y - b) mod 26
                        let res = (a_inv * (x as i32 - b + 26)) % 26;
                        (res as u8 + base) as char
                    } else {
                        c
                    }
                })
                .collect();

            let score = chi_squared_score(&decoded);
            if score < best_score {
                best_score = score;
                best_a = a as u8;
                best_b = b as u8;
                best_text = decoded;
            }
        }
    }

    (best_a, best_b, best_text, best_score)
}

/// Decodes an Affine cipher with the given (a, b) key: D(y) = a_inv * (y - b).
/// Returns None when `a` has no inverse mod 26.
///
/// ```
/// use hashendra::detectors::classic_ciphers::affine_decrypt;
/// assert_eq!(affine_decrypt("RCLLA", 5, 8).as_deref(), Some("HELLO"));
/// ```
pub fn affine_decrypt(text: &str, a: u8, b: u8) -> Option<String> {
    let a_inv = (0..26).find(|i| (a as u16 * i) % 26 == 1)? as u8;
    Some(
        text.chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                    let x = c as u8 - base;
                    let res = (a_inv as u16 * (x as u16 + 26 - b as u16 % 26)) % 26;
                    (res as u8 + base) as char
                } else {
                    c
                }
            })
            .collect(),
    )
}

/// Encodes Baconian cipher: A-Z to 5-bit groups using `char_a`/`char_b`.
/// Inverse of `bacon_decode`; always produces the 26-letter variant.
pub fn bacon_encode(text: &str, char_a: char, char_b: char) -> String {
    text.to_ascii_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| {
            let val = c as u8 - b'A';
            (0..5)
                .map(|idx| {
                    if val & (1 << (4 - idx)) != 0 {
                        char_b
                    } else {
                        char_a
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Decodes Baconian cipher (5-bit binary encoded as two types of characters).
/// Supports the standard 24-character variant and the 26-character complete variant.
pub fn bacon_decode(text: &str, char_a: char, char_b: char) -> Option<String> {
    let clean: String = text
        .chars()
        .map(|c| c.to_ascii_uppercase())
        .filter(|&c| c == char_a || c == char_b)
        .collect();

    if !clean.len().is_multiple_of(5) {
        return None;
    }

    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut decoded = String::new();

    for i in (0..clean.len()).step_by(5) {
        let chunk = &clean[i..i + 5];
        let mut val = 0;
        for (idx, c) in chunk.chars().enumerate() {
            if c == char_b {
                val |= 1 << (4 - idx);
            }
        }

        if val < 26 {
            decoded.push(alphabet.chars().nth(val as usize)?);
        }
    }

    Some(decoded)
}

/// Decodes a Vigenere cipher with a given key.
pub fn vigenere_decode(text: &str, key: &str) -> String {
    let key: Vec<u8> = key
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c as u8 - b'a')
        .collect();

    if key.is_empty() {
        return text.to_string();
    }

    let mut key_idx = 0;
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let shift = key[key_idx % key.len()];
                key_idx += 1;
                let val = (((c as u8 - base) as i16 + (26 - shift as i16)) % 26) as u8 + base;
                val as char
            } else {
                c
            }
        })
        .collect()
}

/// Automatically cracks a Vigenere cipher by Estimating the period (IoC)
/// and then cracking each column as a Caesar cipher.
pub fn vigenere_auto_crack(text: &str) -> (String, String, f32) {
    use crate::core::cryptanalysis::{chi_squared_score, estimate_vigenere_period};

    let periods = estimate_vigenere_period(text, 20);
    if periods.is_empty() {
        return ("".to_string(), text.to_string(), 1000.0);
    }

    let mut best_key = String::new();
    let mut best_text = text.to_string();
    let mut best_score = f32::MAX;

    // Test top 3 estimated periods
    for &(p, _) in periods.iter().take(3) {
        let mut key = String::new();
        let chars: Vec<char> = text.chars().filter(|c| c.is_ascii_alphabetic()).collect();
        let column_len = (chars.len() as f32 / p as f32).ceil() as usize;

        for i in 0..p {
            let mut column = String::with_capacity(column_len);
            for j in (i..chars.len()).step_by(p) {
                column.push(chars[j]);
            }
            let (shift, _, _) = caesar_auto_crack(&column);
            key.push((b'a' + shift) as char);
        }

        let decoded = vigenere_decode(text, &key);
        let score = chi_squared_score(&decoded);
        if score < best_score {
            best_score = score;
            best_key = key;
            best_text = decoded;
        }
    }

    (best_key, best_text, best_score)
}

/// Decodes a simple substitution cipher with a given alphabet mapping.
pub fn simple_substitution_decode(
    text: &str,
    alphabet_map: &std::collections::HashMap<char, char>,
) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                *alphabet_map.get(&c).unwrap_or(&c)
            } else if c.is_ascii_lowercase() {
                alphabet_map
                    .get(&c.to_ascii_uppercase())
                    .map(|&rc| rc.to_ascii_lowercase())
                    .unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

/// Applies a monoalphabetic substitution map in the forward direction
/// (plain → cipher). This is the inverse of `simple_substitution_decode`:
/// build the map the other way round. Unmapped letters pass through.
pub fn simple_substitution_encrypt(
    text: &str,
    alphabet_map: &std::collections::HashMap<char, char>,
) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                *alphabet_map.get(&c).unwrap_or(&c)
            } else if c.is_ascii_lowercase() {
                alphabet_map
                    .get(&c.to_ascii_uppercase())
                    .map(|&rc| rc.to_ascii_lowercase())
                    .unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

/// Automatically cracks a simple substitution cipher using Hill Climbing.
pub fn simple_substitution_auto_crack(text: &str) -> (String, String, f32) {
    use crate::core::cryptanalysis::quadgram_score;
    use std::collections::HashMap;

    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let alpha: Vec<char> = alphabet.chars().collect();
    let mut current_map: Vec<char> = alpha.clone();
    let mut best_score = -10000.0;
    let mut best_map = current_map.clone();
    seed_from_input(text);

    for _ in 0..1000 {
        let mut test_map = current_map.clone();
        let i = (rand_simple() % 26) as usize;
        let j = (rand_simple() % 26) as usize;
        test_map.swap(i, j);

        let mut mapping = HashMap::new();
        for (&a, &c) in alpha.iter().zip(test_map.iter()) {
            mapping.insert(a, c);
        }

        let decoded = simple_substitution_decode(text, &mapping);
        let score = quadgram_score(&decoded);

        if score > best_score {
            best_score = score;
            current_map = test_map.clone();
            best_map = test_map.clone();
        }
    }

    let mut mapping = HashMap::new();
    let mut key_str = String::new();
    for (&a, &c) in alpha.iter().zip(best_map.iter()) {
        mapping.insert(a, c);
        key_str.push(c);
    }

    (
        key_str,
        simple_substitution_decode(text, &mapping),
        best_score,
    )
}


static SEED: AtomicU32 = AtomicU32::new(12345);

/// Deterministic LCG for hill-climbing restarts. Atomic so the cracker stays
/// sound if it ever runs off the main thread; sequence matches the old
/// single-threaded order when uncontended.
fn rand_simple() -> u32 {
    let mut prev = SEED.load(Ordering::Relaxed);
    loop {
        let next = prev
            .wrapping_mul(1103515245)
            .wrapping_add(12345);
        match SEED.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next & 0x7FFFFFFF,
            Err(actual) => prev = actual,
        }
    }
}

/// Reseed the hill-climber from the input. Same input cracks identically on
/// every run; different inputs still explore different paths.
fn seed_from_input(text: &str) {
    let mut h: u32 = 0x811C_9DC5;
    for b in text.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    SEED.store(h | 1, Ordering::Relaxed);
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution_crack_is_deterministic() {
        let text = "ZIT ZQWYBTEU QF NBS BPRZQ QMHM NFTO XFKH QEBBO";
        let first = simple_substitution_auto_crack(text);
        let second = simple_substitution_auto_crack(text);
        assert_eq!(first, second);
    }

    #[test]
    fn bacon_roundtrip() {
        assert_eq!(bacon_encode("AB", 'A', 'B'), "AAAAAAAAAB");
        assert_eq!(bacon_decode("AAAAAAAAAB", 'A', 'B').as_deref(), Some("AB"));
    }

    #[test]
    fn substitution_roundtrip() {
        use std::collections::HashMap;
        let enc_map: HashMap<char, char> =
            [('H', 'Q'), ('I', 'X')].into_iter().collect();
        let dec_map: HashMap<char, char> =
            [('Q', 'H'), ('X', 'I')].into_iter().collect();
        let cipher = simple_substitution_encrypt("HI there", &enc_map);
        assert_eq!(cipher, "QX tqere");
        assert_eq!(simple_substitution_decode(&cipher, &dec_map), "HI there");
    }
}
