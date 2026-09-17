/// Decodes Base32 (RFC 4648).
pub fn decode_base32(input: &str) -> Option<Vec<u8>> {
    let input = input.trim_end_matches('=');
    let mut bits = 0u32;
    let mut bit_count = 0u32;
    let mut result = Vec::new();

    for &b in input.as_bytes() {
        let val = if b.is_ascii_uppercase() {
            (b - b'A') as u32
        } else if (b'2'..=b'7').contains(&b) {
            (b - b'2' + 26) as u32
        } else if b.is_ascii_lowercase() {
            (b - b'a') as u32
        } else {
            return None;
        };

        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            result.push((bits >> (bit_count - 8)) as u8);
            bit_count -= 8;
            if bit_count > 0 {
                bits &= (1 << bit_count) - 1;
            } else {
                bits = 0;
            }
        }
    }

    if bit_count > 0 && bits != 0 {
        return None;
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Decodes Base58 (Bitcoin/Flickr alphabet).
pub fn decode_base58(input: &str) -> Option<Vec<u8>> {
    use num_bigint::BigUint;

    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut value = BigUint::from(0u32);
    let b58_base = BigUint::from(58u32);

    for &b in input.as_bytes() {
        {
            let pos = alphabet.iter().position(|&x| x == b)?;
            value = value * &b58_base + BigUint::from(pos);
        }
    }

    let mut result = value.to_bytes_be();
    // Prepend zeros for '1's at the beginning of input (leading zeroes in Base58)
    for &b in input.as_bytes() {
        if b == b'1' {
            result.insert(0, 0);
        } else {
            break;
        }
    }
    if result.is_empty() && !input.is_empty() && input.chars().all(|c| c == '1') {
        Some(vec![0; input.len()])
    } else if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Brute-forces ROT ciphers (1-25).
pub fn rot_brute_force(input: &str) -> Vec<(u8, String)> {
    let mut results = Vec::new();
    for shift in 1..26u8 {
        let decoded: String = input
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                    let rotated = (((c as u8 - base) + (26 - shift)) % 26) + base;
                    rotated as char
                } else {
                    c
                }
            })
            .collect();
        results.push((shift, decoded));
    }
    results
}

/// Attempts to crack single-byte XOR.
pub fn xor_crack(input: &[u8]) -> Vec<(u8, String, f64)> {
    let mut results = Vec::new();
    for key in 0..=255u8 {
        let xored: Vec<u8> = input.iter().map(|&b| b ^ key).collect();
        // Simple heuristic: count printable characters
        let printable = xored
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();
        let score = printable as f64 / xored.len() as f64;

        if score > 0.8
            && let Ok(s) = String::from_utf8(xored) {
                results.push((key, s, score));
            }
    }
    results.sort_by(|a, b| b.2.total_cmp(&a.2));
    results
}

/// Encrypts text using a Caesar/ROT cipher (forward direction).
pub fn caesar_encrypt(input: &str, shift: u8) -> String {
    let shift = shift % 26;
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let rotated = (((c as u8 - base) + shift) % 26) + base;
                rotated as char
            } else {
                c
            }
        })
        .collect()
}

/// Encrypts text using a Vigenere cipher (forward direction).
pub fn vigenere_encrypt(input: &str, key: &str) -> String {
    if key.is_empty() {
        return input.to_string();
    }
    let key_upper: Vec<u8> = key.to_uppercase().bytes().collect();
    let mut key_idx = 0;
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let shift = key_upper[key_idx % key_upper.len()] - b'A';
                key_idx += 1;
                let rotated = (((c as u8 - base) + shift) % 26) + base;
                rotated as char
            } else {
                c
            }
        })
        .collect()
}

/// Encrypts text using an Affine cipher (forward direction): E(x) = (ax + b) mod 26.
pub fn affine_encrypt(input: &str, a: u8, b: u8) -> Option<String> {
    let valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
    if !valid_a.contains(&a) {
        return None;
    }
    Some(
        input
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                    let x = c as u8 - base;
                    let encrypted = ((a as u16 * x as u16 + b as u16) % 26) as u8;
                    (encrypted + base) as char
                } else {
                    c
                }
            })
            .collect(),
    )
}

/// Encrypts text using a Rail Fence cipher (forward direction).
pub fn rail_fence_encrypt(input: &str, rails: usize) -> String {
    if rails <= 1 || rails >= input.len() {
        return input.to_string();
    }
    let chars: Vec<char> = input.chars().collect();
    let mut fence = vec![Vec::new(); rails];
    let mut row = 0usize;
    let mut down = true;

    for &c in &chars {
        fence[row].push(c);
        if down {
            if row + 1 >= rails {
                down = false;
                row = row.saturating_sub(1);
            } else {
                row += 1;
            }
        } else {
            if row == 0 {
                down = true;
                if row + 1 < rails { row += 1; }
            } else {
                row -= 1;
            }
        }
    }

    fence.into_iter().flatten().collect()
}

/// Encrypts bytes using XOR with a repeating key.
pub fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Encrypts using columnar transposition (forward direction).
pub fn columnar_encrypt(input: &str, key: &str) -> String {
    if key.is_empty() {
        return input.to_string();
    }
    let chars: Vec<char> = input.chars().collect();
    let cols = key.len();
    let rows = chars.len().div_ceil(cols);
    let mut grid = vec![vec![' '; cols]; rows];

    for (i, &c) in chars.iter().enumerate() {
        grid[i / cols][i % cols] = c;
    }

    // Sort columns by key order
    let mut col_order: Vec<(usize, u8)> = key.bytes().enumerate().collect();
    col_order.sort_by_key(|&(_, b)| b);

    let mut result = String::with_capacity(chars.len());
    for &(col, _) in &col_order {
    for (row, grid_row) in grid.iter().enumerate() {
        if grid_row[col] != ' ' || row * cols + col < chars.len() {
            result.push(grid_row[col]);
        }
    }
    }
    result
}
