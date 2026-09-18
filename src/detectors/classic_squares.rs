//! Square-based classical ciphers: Polybius, Tap code, ADFGX/ADFGVX,
//! Four-Square, Two-Square, Trifid.
//!
//! Conventions: squares are uppercase A-Z with I/J merged (except ADFGVX,
//! which uses A-Z0-9 in 6x6). Digraph ciphers drop non-letters and pad odd
//! lengths with X. Columnar tie-breaks go left to right; this matches the
//! common implementations but state it when exchanging with other tools.

/// Build a keyed square: keyword letters first (deduped), then the rest of
/// `alphabet` in order. Only alphabet members enter the square (anything
/// else, including digits in a 5x5 key, is skipped); `merge_from` maps onto
/// `merge_to` first (e.g. J→I).
pub fn keyed_square(key: &str, alphabet: &str, merge_from: char, merge_to: char) -> Vec<char> {
    let mut square = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for mut c in key.to_ascii_uppercase().chars().chain(alphabet.chars()) {
        if c == merge_from {
            c = merge_to;
        }
        if !alphabet.contains(c) {
            continue;
        }
        if seen.insert(c) {
            square.push(c);
        }
    }
    square
}

fn clean_alpha(text: &str, merge_from: char, merge_to: char) -> Vec<char> {
    text.to_ascii_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| if c == merge_from { merge_to } else { c })
        .collect()
}

/// Polybius encrypt: letters → 1-based row/col digit pairs ("HELLO" → "2315313134").
pub fn polybius_encrypt(text: &str, key: &str) -> String {
    let square = keyed_square(key, "ABCDEFGHIKLMNOPQRSTUVWXYZ", 'J', 'I');
    clean_alpha(text, 'J', 'I')
        .iter()
        .map(|c| {
            let pos = square.iter().position(|&x| x == *c).unwrap_or(0);
            format!("{}{}", pos / 5 + 1, pos % 5 + 1)
        })
        .collect()
}

/// Polybius decrypt: digit pairs → letters. A trailing lone digit is dropped.
pub fn polybius_decrypt(text: &str, key: &str) -> String {
    let square = keyed_square(key, "ABCDEFGHIKLMNOPQRSTUVWXYZ", 'J', 'I');
    let digits: Vec<u8> = text
        .chars()
        .filter(|c| ('1'..='5').contains(c))
        .map(|c| c as u8 - b'1')
        .collect();
    digits
        .chunks(2)
        .filter(|pair| pair.len() == 2)
        .map(|pair| square[(pair[0] as usize) * 5 + pair[1] as usize])
        .collect()
}

/// Tap code encode. Dots for row and column, letters joined by " / ".
/// Merges C/K per the traditional tap table: "HI" → ".. ... / .. ....".
pub fn tap_encode(text: &str) -> String {
    // Traditional tap layout with C/K sharing a cell.
    const ROWS: [&str; 5] = ["ABCDE", "FGHIJ", "LMNOP", "QRSTU", "VWXYZ"];
    let mut letters = Vec::new();
    for mut c in text.to_ascii_uppercase().chars() {
        if c == 'K' {
            c = 'C';
        }
        if !c.is_ascii_alphabetic() {
            if c == ' ' {
                letters.push("//".to_string());
            }
            continue;
        }
        let mut done = false;
        for (r, row) in ROWS.iter().enumerate() {
            if let Some(col) = row.chars().position(|x| x == c) {
                letters.push(format!("{} {}", ".".repeat(r + 1), ".".repeat(col + 1)));
                done = true;
                break;
            }
        }
        if !done {
            // J is absent from the traditional table; spell it out.
            if c == 'J' {
                letters.push(tap_encode("I"));
            }
        }
    }
    letters.join(" / ")
}

/// Tap code decode. Accepts the format `tap_encode` produces.
pub fn tap_decode(text: &str) -> String {
    const ROWS: [&str; 5] = ["ABCDE", "FGHIJ", "LMNOP", "QRSTU", "VWXYZ"];
    let mut out = String::new();
    for letter in text.split(" / ") {
        if letter.trim() == "//" || letter.trim().is_empty() {
            out.push(' ');
            continue;
        }
        let mut parts = letter.trim().split(' ');
        let (row, col) = (parts.next().unwrap_or("").len(), parts.next().unwrap_or("").len());
        if (1..=5).contains(&row)
            && (1..=5).contains(&col)
            && let Some(c) = ROWS[row - 1].chars().nth(col - 1) {
                out.push(c);
            }
    }
    out
}

/// ADFGX encrypt: 5x5 fractionation (I/J merged) + keyed columnar transposition.
pub fn adfgx_encrypt(text: &str, square_key: &str, col_key: &str) -> String {
    fractionate_encrypt(text, square_key, col_key, false)
}

/// ADFGX decrypt.
pub fn adfgx_decrypt(text: &str, square_key: &str, col_key: &str) -> String {
    fractionate_decrypt(text, square_key, col_key, false)
}

/// ADFGVX encrypt: 6x6 fractionation over A-Z0-9 (digits kept) + transposition.
pub fn adfgvx_encrypt(text: &str, square_key: &str, col_key: &str) -> String {
    fractionate_encrypt(text, square_key, col_key, true)
}

/// ADFGVX decrypt.
pub fn adfgvx_decrypt(text: &str, square_key: &str, col_key: &str) -> String {
    fractionate_decrypt(text, square_key, col_key, true)
}

fn fractionate_encrypt(text: &str, square_key: &str, col_key: &str, six: bool) -> String {
    let labels: &[char] = if six {
        &['A', 'D', 'F', 'G', 'V', 'X']
    } else {
        &['A', 'D', 'F', 'G', 'X']
    };
    let (dim, alphabet): (usize, String) = if six {
        (6, ('A'..='Z').chain('0'..='9').collect())
    } else {
        (5, "ABCDEFGHIKLMNOPQRSTUVWXYZ".to_string())
    };
    let square = keyed_square(square_key, &alphabet, 'J', 'I');
    let clean: Vec<char> = if six {
        text.to_ascii_uppercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect()
    } else {
        clean_alpha(text, 'J', 'I')
    };
    let mut frac = Vec::with_capacity(clean.len() * 2);
    for c in clean {
        if let Some(pos) = square.iter().position(|&x| x == c) {
            frac.push(labels[pos / dim]);
            frac.push(labels[pos % dim]);
        }
    }
    columnar_read(&frac, col_key)
}

fn fractionate_decrypt(text: &str, square_key: &str, col_key: &str, six: bool) -> String {
    let labels: &[char] = if six {
        &['A', 'D', 'F', 'G', 'V', 'X']
    } else {
        &['A', 'D', 'F', 'G', 'X']
    };
    let (dim, alphabet): (usize, String) = if six {
        (6, ('A'..='Z').chain('0'..='9').collect())
    } else {
        (5, "ABCDEFGHIKLMNOPQRSTUVWXYZ".to_string())
    };
    let square = keyed_square(square_key, &alphabet, 'J', 'I');
    let clean: Vec<char> = text
        .to_ascii_uppercase()
        .chars()
        .filter(|c| labels.contains(c))
        .collect();
    let frac = columnar_unread(&clean, col_key);
    frac.chunks(2)
        .filter(|pair| pair.len() == 2)
        .map(|pair| {
            let row = labels.iter().position(|&x| x == pair[0]).unwrap_or(0);
            let col = labels.iter().position(|&x| x == pair[1]).unwrap_or(0);
            square
                .get(row * dim + col)
                .copied()
                .unwrap_or('?')
        })
        .collect()
}

/// Columnar transposition read: fill rows left to right, read columns in
/// key-alphabetical order (ties go left to right).
fn columnar_read(frac: &[char], col_key: &str) -> String {
    let key: Vec<char> = col_key.to_ascii_uppercase().chars().collect();
    if key.is_empty() || frac.is_empty() {
        return frac.iter().collect();
    }
    let cols = key.len();
    let mut order: Vec<usize> = (0..cols).collect();
    order.sort_by_key(|&i| (key[i], i));
    let mut out = String::with_capacity(frac.len());
    for &col in &order {
        let mut i = col;
        while i < frac.len() {
            out.push(frac[i]);
            i += cols;
        }
    }
    out
}

/// Inverse of `columnar_read`.
fn columnar_unread(text: &[char], col_key: &str) -> Vec<char> {
    let key: Vec<char> = col_key.to_ascii_uppercase().chars().collect();
    if key.is_empty() || text.is_empty() {
        return text.to_vec();
    }
    let cols = key.len();
    let base = text.len() / cols;
    let extra = text.len() % cols;
    let mut order: Vec<usize> = (0..cols).collect();
    order.sort_by_key(|&i| (key[i], i));
    // Encryption fills rows left to right, so the first `extra` grid
    // positions hold one more cell. Split the ciphertext (which arrives
    // in read order) using those positional lengths.
    let mut lens = vec![base; cols];
    for len in lens.iter_mut().take(extra) {
        *len += 1;
    }
    let mut columns: Vec<Vec<char>> = vec![Vec::new(); cols];
    let mut pos = 0;
    for &col in &order {
        columns[col] = text[pos..pos + lens[col]].to_vec();
        pos += lens[col];
    }
    let rows = base + usize::from(extra > 0);
    let mut out = Vec::with_capacity(text.len());
    for r in 0..rows {
        for column in &columns {
            if let Some(&ch) = column.get(r) {
                out.push(ch);
            }
        }
    }
    out
}

/// Four-Square encrypt (digraphs; non-letters dropped, odd length padded with X).
pub fn four_square_encrypt(text: &str, key1: &str, key2: &str) -> String {
    let plain: Vec<char> = "ABCDEFGHIKLMNOPQRSTUVWXYZ".chars().collect();
    let top_right = keyed_square(key1, "ABCDEFGHIKLMNOPQRSTUVWXYZ", 'J', 'I');
    let bottom_left = keyed_square(key2, "ABCDEFGHIKLMNOPQRSTUVWXYZ", 'J', 'I');
    digraph_map(text, |a, b| {
        let pa = plain.iter().position(|&x| x == a).unwrap_or(0);
        let pb = plain.iter().position(|&x| x == b).unwrap_or(0);
        [top_right[pa / 5 * 5 + pb % 5], bottom_left[pb / 5 * 5 + pa % 5]]
    })
}

/// Four-Square decrypt.
pub fn four_square_decrypt(text: &str, key1: &str, key2: &str) -> String {
    let plain: Vec<char> = "ABCDEFGHIKLMNOPQRSTUVWXYZ".chars().collect();
    let top_right = keyed_square(key1, "ABCDEFGHIKLMNOPQRSTUVWXYZ", 'J', 'I');
    let bottom_left = keyed_square(key2, "ABCDEFGHIKLMNOPQRSTUVWXYZ", 'J', 'I');
    digraph_map(text, |a, b| {
        let pa = top_right.iter().position(|&x| x == a).unwrap_or(0);
        let pb = bottom_left.iter().position(|&x| x == b).unwrap_or(0);
        [plain[pa / 5 * 5 + pb % 5], plain[pb / 5 * 5 + pa % 5]]
    })
}

/// Two-Square encrypt, horizontal variant: plaintext digraphs read from the
/// two plain top squares, ciphertext from the keyed bottom squares.
pub fn two_square_encrypt(text: &str, key1: &str, key2: &str) -> String {
    let plain: Vec<char> = "ABCDEFGHIKLMNOPQRSTUVWXYZ".chars().collect();
    let bottom_left = keyed_square(key1, "ABCDEFGHIKLMNOPQRSTUVWXYZ", 'J', 'I');
    let bottom_right = keyed_square(key2, "ABCDEFGHIKLMNOPQRSTUVWXYZ", 'J', 'I');
    digraph_map(text, |a, b| {
        let pa = plain.iter().position(|&x| x == a).unwrap_or(0);
        let pb = plain.iter().position(|&x| x == b).unwrap_or(0);
        [
            bottom_left[pa / 5 * 5 + pb % 5],
            bottom_right[pb / 5 * 5 + pa % 5],
        ]
    })
}

/// Two-Square decrypt (horizontal variant).
pub fn two_square_decrypt(text: &str, key1: &str, key2: &str) -> String {
    let plain: Vec<char> = "ABCDEFGHIKLMNOPQRSTUVWXYZ".chars().collect();
    let bottom_left = keyed_square(key1, "ABCDEFGHIKLMNOPQRSTUVWXYZ", 'J', 'I');
    let bottom_right = keyed_square(key2, "ABCDEFGHIKLMNOPQRSTUVWXYZ", 'J', 'I');
    digraph_map(text, |a, b| {
        let pa = bottom_left.iter().position(|&x| x == a).unwrap_or(0);
        let pb = bottom_right.iter().position(|&x| x == b).unwrap_or(0);
        [
            plain[pa / 5 * 5 + pb % 5],
            plain[pb / 5 * 5 + pa % 5],
        ]
    })
}

/// Apply a digraph mapping over cleaned, even-padded input.
fn digraph_map(text: &str, f: impl Fn(char, char) -> [char; 2]) -> String {
    let mut clean = clean_alpha(text, 'J', 'I');
    if clean.len() % 2 == 1 {
        clean.push('X');
    }
    let mut out = String::with_capacity(clean.len());
    for pair in clean.chunks(2) {
        for c in f(pair[0], pair[1]) {
            out.push(c);
        }
    }
    out
}

/// Trifid encrypt over A-Z plus '.', period-grouped. Non-alphabet chars dropped.
pub fn trifid_encrypt(text: &str, key: &str, period: usize) -> String {
    let tables = trifid_tables(key);
    let clean: Vec<char> = text
        .to_ascii_uppercase()
        .chars()
        .filter(|c| tables.iter().any(|t| t.contains(c)))
        .collect();
    let period = period.max(1);
    let mut out = String::with_capacity(clean.len());
    for block in clean.chunks(period) {
        let mut rows = [Vec::new(), Vec::new(), Vec::new()];
        for &c in block {
            let (t, r, col) = trifid_coords(&tables, c);
            rows[0].push(t);
            rows[1].push(r);
            rows[2].push(col);
        }
        let flat: Vec<usize> = rows.concat();
        for triple in flat.chunks(3) {
            out.push(tables[triple[0]][triple[1] * 3 + triple[2]]);
        }
    }
    out
}

/// Trifid decrypt.
pub fn trifid_decrypt(text: &str, key: &str, period: usize) -> String {
    let tables = trifid_tables(key);
    let clean: Vec<char> = text
        .to_ascii_uppercase()
        .chars()
        .filter(|c| tables.iter().any(|t| t.contains(c)))
        .collect();
    let period = period.max(1);
    let mut out = String::with_capacity(clean.len());
    for block in clean.chunks(period) {
        // Concatenating the output chars' coordinates rebuilds the flat
        // row stream exactly as encryption wrote it: thirds are t, r, c.
        let n = block.len();
        let mut flat = Vec::with_capacity(3 * n);
        for c in block {
            let (t, r, col) = trifid_coords(&tables, *c);
            flat.push(t);
            flat.push(r);
            flat.push(col);
        }
        for i in 0..n {
            out.push(tables[flat[i]][flat[n + i] * 3 + flat[2 * n + i]]);
        }
    }
    out
}

/// Three keyed 3x3 layers over A-Z plus '.'.
fn trifid_tables(key: &str) -> [Vec<char>; 3] {
    let mut alpha: Vec<char> = ('A'..='Z').chain(std::iter::once('.')).collect();
    let mut tables = [Vec::new(), Vec::new(), Vec::new()];
    let mut seen = std::collections::HashSet::new();
    let mut cells = Vec::new();
    for c in key.to_ascii_uppercase().chars() {
        if (c.is_ascii_uppercase() || c == '.') && seen.insert(c) {
            cells.push(c);
        }
    }
    for c in alpha.drain(..) {
        if seen.insert(c) {
            cells.push(c);
        }
    }
    cells.truncate(27);
    for (i, c) in cells.into_iter().enumerate() {
        tables[i / 9].push(c);
    }
    tables
}

fn trifid_coords(tables: &[Vec<char>; 3], c: char) -> (usize, usize, usize) {
    for (t, table) in tables.iter().enumerate() {
        if let Some(pos) = table.iter().position(|&x| x == c) {
            return (t, pos / 3, pos % 3);
        }
    }
    (0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polybius_known_answer() {
        // Standard square, no key: HELLO → 23 15 31 31 34.
        assert_eq!(polybius_encrypt("HELLO", ""), "2315313134");
        assert_eq!(polybius_decrypt("2315313134", ""), "HELLO");
    }

    #[test]
    fn polybius_drops_trailing_lone_digit() {
        assert_eq!(polybius_decrypt("231531313", ""), "HELL");
    }

    #[test]
    fn tap_known_answer() {
        assert_eq!(tap_encode("HI"), ".. ... / .. ....");
        assert_eq!(tap_decode(".. ... / .. ...."), "HI");
    }

    #[test]
    fn tap_roundtrip_with_space() {
        assert_eq!(tap_decode(&tap_encode("HELLO WORLD")), "HELLO WORLD");
    }

    #[test]
    fn adfgx_hand_computed() {
        // "HELLO", standard square, column key "KEY" → "FFADXFGAAF".
        assert_eq!(adfgx_encrypt("HELLO", "", "KEY"), "FFADXFGAAF");
        assert_eq!(adfgx_decrypt("FFADXFGAAF", "", "KEY"), "HELLO");
    }

    #[test]
    fn adfgx_roundtrip() {
        let cipher = adfgx_encrypt("THE QUICK BROWN FOX", "SECRET", "ZEBRA");
        assert!(cipher.chars().all(|c| "ADFGX".contains(c)));
        assert_eq!(adfgx_decrypt(&cipher, "SECRET", "ZEBRA"), "THEQUICKBROWNFOX");
    }

    #[test]
    fn adfgvx_roundtrip_keeps_digits() {
        let cipher = adfgvx_encrypt("ATTACK AT 1200 AM", "SECRET", "KEY");
        assert!(cipher.chars().all(|c| "ADFGVX".contains(c)));
        assert_eq!(adfgvx_decrypt(&cipher, "SECRET", "KEY"), "ATTACKAT1200AM");
    }

    #[test]
    fn four_square_roundtrip() {
        let cipher = four_square_encrypt("HELLO WORLD", "EXAMPLE", "KEYWORD");
        assert_eq!(four_square_decrypt(&cipher, "EXAMPLE", "KEYWORD"), "HELLOWORLD");
    }

    #[test]
    fn two_square_roundtrip() {
        let cipher = two_square_encrypt("HELLO WORLD", "EXAMPLE", "KEYWORD");
        assert_eq!(two_square_decrypt(&cipher, "EXAMPLE", "KEYWORD"), "HELLOWORLD");
    }

    #[test]
    fn trifid_roundtrip() {
        let cipher = trifid_encrypt("HELLO WORLD.", "SECRET", 5);
        assert_eq!(trifid_decrypt(&cipher, "SECRET", 5), "HELLOWORLD.");
    }

    #[test]
    fn trifid_odd_tail_block() {
        // Last block shorter than the period must still round-trip.
        let cipher = trifid_encrypt("ABCDEFGHIJ", "K", 5);
        assert_eq!(trifid_decrypt(&cipher, "K", 5), "ABCDEFGHIJ");
    }
}
