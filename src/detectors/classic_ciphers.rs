use crate::core::cryptanalysis::chi_squared_score;

/// Automatically cracks a Caesar/ROT cipher by testing all 26 shifts
/// and choosing the one with the best Chi-Squared score.
pub fn caesar_auto_crack(text: &str) -> (u8, String, f32) {
    let mut best_shift = 0;
    let mut best_text = text.to_string();
    let mut best_score = f32::MAX;

    for shift in 0..26 {
        let decoded: String = text.chars().map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let rotated = (((c as u8 - base) as i16 + (26 - shift) as i16) % 26) as u8 + base;
                rotated as char
            } else {
                c
            }
        }).collect();

        let score = chi_squared_score(&decoded);
        if score < best_score {
            best_score = score;
            best_shift = shift as u8;
            best_text = decoded;
        }
    }

    (best_shift, best_text, best_score)
}

/// Decodes an Atbash cipher (alphabet reversal).
pub fn atbash_decode(text: &str) -> String {
    text.chars().map(|c| {
        if c.is_ascii_uppercase() {
            (b'Z' - (c as u8 - b'A')) as char
        } else if c.is_ascii_lowercase() {
            (b'z' - (c as u8 - b'a')) as char
        } else {
            c
        }
    }).collect()
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
            let decoded: String = text.chars().map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                    let x = c as u8 - base;
                    // Formula: D(y) = a_inv * (y - b) mod 26
                    let res = (a_inv * (x as i32 - b as i32 + 26)) % 26;
                    (res as u8 + base) as char
                } else {
                    c
                }
            }).collect();

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

/// Decodes Baconian cipher (5-bit binary encoded as two types of characters).
/// Supports the standard 24-character variant and the 26-character complete variant.
pub fn bacon_decode(text: &str, char_a: char, char_b: char) -> Option<String> {
    let clean: String = text.chars()
        .map(|c| c.to_ascii_uppercase())
        .filter(|&c| c == char_a || c == char_b)
        .collect();
    
    if clean.len() % 5 != 0 { return None; }

    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut decoded = String::new();

    for i in (0..clean.len()).step_by(5) {
        let chunk = &clean[i..i+5];
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
    let key: Vec<u8> = key.to_ascii_lowercase().chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c as u8 - b'a')
        .collect();
    
    if key.is_empty() { return text.to_string(); }

    let mut key_idx = 0;
    text.chars().map(|c| {
        if c.is_ascii_alphabetic() {
            let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
            let shift = key[key_idx % key.len()];
            key_idx += 1;
            let val = (((c as u8 - base) as i16 + (26 - shift as i16)) % 26) as u8 + base;
            val as char
        } else {
            c
        }
    }).collect()
}

/// Automatically cracks a Vigenere cipher by Estimating the period (IoC)
/// and then cracking each column as a Caesar cipher.
pub fn vigenere_auto_crack(text: &str) -> (String, String, f32) {
    use crate::core::cryptanalysis::{estimate_vigenere_period, chi_squared_score};

    let periods = estimate_vigenere_period(text, 20);
    if periods.is_empty() { return ("".to_string(), text.to_string(), 1000.0); }

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

/// Decodes a Rail Fence cipher with a given number of rails.
pub fn rail_fence_decode(text: &str, rails: usize) -> String {
    if rails <= 1 { return text.to_string(); }
    
    let mut fence = vec![vec!['\0'; text.len()]; rails];
    let mut rail = 0;
    let mut direction = 1;

    // Mark the rail positions
    for i in 0..text.len() {
        fence[rail][i] = '*';
        if rail == 0 { direction = 1; }
        else if rail == rails - 1 { direction = -1; }
        rail = (rail as i32 + direction) as usize;
    }

    // Fill the rail positions with text characters
    let mut iter = text.chars();
    for r in 0..rails {
        for c in 0..text.len() {
            if fence[r][c] == '*' {
                if let Some(ch) = iter.next() {
                    fence[r][c] = ch;
                }
            }
        }
    }

    // Read in zigzag order
    let mut result = String::new();
    rail = 0;
    direction = 1;
    for i in 0..text.len() {
        result.push(fence[rail][i]);
        if rail == 0 { direction = 1; }
        else if rail == rails - 1 { direction = -1; }
        rail = (rail as i32 + direction) as usize;
    }

    result
}

/// Automatically cracks a Rail Fence cipher by testing rails 2 to 10.
pub fn rail_fence_auto_crack(text: &str) -> (usize, String, f32) {
    use crate::core::cryptanalysis::chi_squared_score;
    let mut best_rails = 2;
    let mut best_text = text.to_string();
    let mut best_score = f32::MAX;

    for rails in 2..=10 {
        let decoded = rail_fence_decode(text, rails);
        let score = chi_squared_score(&decoded);
        if score < best_score {
            best_score = score;
            best_rails = rails;
            best_text = decoded;
        }
    }

    (best_rails, best_text, best_score)
}

/// Decodes a Columnar Transposition cipher with a given key (permutation).
pub fn columnar_decode(text: &str, key: &[usize]) -> String {
    let cols = key.len();
    let rows = (text.len() as f32 / cols as f32).ceil() as usize;
    let mut grid = vec![vec![' '; cols]; rows];
    
    // Fill the grid column by column according to the key
    let mut chars = text.chars();
    for &col_idx in key {
        for r in 0..rows {
            if let Some(c) = chars.next() {
                grid[r][col_idx] = c;
            }
        }
    }

    // Read row by row
    let mut result = String::new();
    for r in 0..rows {
        for c in 0..cols {
            result.push(grid[r][c]);
        }
    }
    result.trim().to_string()
}

/// Automatically cracks a simple Columnar Transposition by testing small column counts.
pub fn columnar_auto_crack(text: &str) -> (Vec<usize>, String, f32) {
    use crate::core::cryptanalysis::chi_squared_score;
    use itertools::Itertools;

    let mut best_key = vec![0];
    let mut best_text = text.to_string();
    let mut best_score = f32::MAX;

    // Test column sizes 2..=5 (permutations grow fast!)
    for size in 2..=5 {
        let permutations = (0..size).permutations(size);
        for p in permutations {
            let decoded = columnar_decode(text, &p);
            let score = chi_squared_score(&decoded);
            if score < best_score {
                best_score = score;
                best_key = p;
                best_text = decoded;
            }
        }
    }

    (best_key, best_text, best_score)
}

/// Decodes a simple substitution cipher with a given alphabet mapping.
pub fn simple_substitution_decode(text: &str, alphabet_map: &std::collections::HashMap<char, char>) -> String {
    text.chars().map(|c| {
        if c.is_ascii_uppercase() {
            *alphabet_map.get(&c).unwrap_or(&c)
        } else if c.is_ascii_lowercase() {
            alphabet_map.get(&c.to_ascii_uppercase())
                .map(|&rc| rc.to_ascii_lowercase())
                .unwrap_or(c)
        } else {
            c
        }
    }).collect()
}

/// Automatically cracks a simple substitution cipher using Hill Climbing.
pub fn simple_substitution_auto_crack(text: &str) -> (String, String, f32) {
    use crate::core::cryptanalysis::quadgram_score;
    use std::collections::HashMap;

    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut current_map: Vec<char> = alphabet.chars().collect();
    let mut best_score = -10000.0;
    let mut best_map = current_map.clone();

    for _ in 0..1000 {
        let mut test_map = current_map.clone();
        let i = (rand_simple() % 26) as usize;
        let j = (rand_simple() % 26) as usize;
        test_map.swap(i, j);

        let mut mapping = HashMap::new();
        for (idx, &c) in test_map.iter().enumerate() {
            mapping.insert(alphabet.chars().nth(idx).unwrap(), c);
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
    for (i, &c) in best_map.iter().enumerate() {
        mapping.insert(alphabet.chars().nth(i).unwrap(), c);
        key_str.push(c);
    }

    (key_str, simple_substitution_decode(text, &mapping), best_score)
}

/// Decodes a Playfair cipher with a given keyword and 5x5 grid (J=I).
pub fn playfair_decode(text: &str, key: &str) -> String {
    let mut grid = vec!['\0'; 25];
    let mut key_chars = Vec::new();
    let alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // No 'J'
    
    let key = key.to_uppercase().replace('J', "I");
    for c in key.chars().chain(alphabet.chars()) {
        if c.is_ascii_alphabetic() && !key_chars.contains(&c) {
            key_chars.push(c);
        }
    }
    grid.copy_from_slice(&key_chars[..25]);

    let find_pos = |c: char| {
        let c = if c == 'J' { 'I' } else { c };
        grid.iter().position(|&x| x == c).unwrap_or(0)
    };

    let clean: Vec<char> = text.to_uppercase().chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let mut result = String::new();

    for i in (0..clean.len()).step_by(2) {
        if i + 1 >= clean.len() { break; }
        let p1 = find_pos(clean[i]);
        let p2 = find_pos(clean[i+1]);
        
        let (r1, c1) = (p1 / 5, p1 % 5);
        let (r2, c2) = (p2 / 5, p2 % 5);

        if r1 == r2 {
            result.push(grid[r1 * 5 + (c1 + 4) % 5]);
            result.push(grid[r2 * 5 + (c2 + 4) % 5]);
        } else if c1 == c2 {
            result.push(grid[((r1 + 4) % 5) * 5 + c1]);
            result.push(grid[((r2 + 4) % 5) * 5 + c2]);
        } else {
            result.push(grid[r1 * 5 + c2]);
            result.push(grid[r2 * 5 + c1]);
        }
    }
    result
}

/// Decodes a Bifid cipher (period 5 by default).
pub fn bifid_decode(text: &str, key: &str, period: usize) -> String {
    let mut grid = vec!['\0'; 25];
    let mut key_chars = Vec::new();
    let alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // No 'J'
    
    let key = key.to_uppercase().replace('J', "I");
    for c in key.chars().chain(alphabet.chars()) {
        if c.is_ascii_alphabetic() && !key_chars.contains(&c) {
            key_chars.push(c);
        }
    }
    grid.copy_from_slice(&key_chars[..25]);

    let find_pos = |c: char| {
        let c = if c == 'J' { 'I' } else { c };
        let p = grid.iter().position(|&x| x == c).unwrap_or(0);
        (p / 5, p % 5)
    };

    let clean: Vec<char> = text.to_uppercase().chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let mut coords = Vec::new();
    for i in (0..clean.len()).step_by(period) {
        let chunk_size = std::cmp::min(period, clean.len() - i);
        let mut rows = Vec::new();
        let mut cols = Vec::new();
        for j in 0..chunk_size {
            let (r, c) = find_pos(clean[i+j]);
            rows.push(r);
            cols.push(c);
        }
        coords.extend(rows);
        coords.extend(cols);
    }

    let mut result = String::new();
    for i in (0..coords.len()).step_by(2) {
        result.push(grid[coords[i] * 5 + coords[i+1]]);
    }
    result
}

fn rand_simple() -> u32 {
    static mut SEED: u32 = 12345;
    unsafe {
        SEED = SEED.wrapping_mul(1103515245).wrapping_add(12345);
        SEED & 0x7FFFFFFF
    }
}
