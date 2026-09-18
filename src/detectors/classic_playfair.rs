/// Encodes a Playfair cipher: same-row shifts right, same-column shifts
/// down, otherwise the rectangle corners. Odd trailing letters are dropped,
/// matching the decoder.
pub fn playfair_encrypt(text: &str, key: &str) -> String {
    let grid = square_grid(key);

    let find_pos = |c: char| {
        let c = if c == 'J' { 'I' } else { c };
        grid.iter().position(|&x| x == c).unwrap_or(0)
    };

    let clean: Vec<char> = text
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    let mut result = String::new();

    for i in (0..clean.len()).step_by(2) {
        if i + 1 >= clean.len() {
            break;
        }
        let p1 = find_pos(clean[i]);
        let p2 = find_pos(clean[i + 1]);

        let (r1, c1) = (p1 / 5, p1 % 5);
        let (r2, c2) = (p2 / 5, p2 % 5);

        if r1 == r2 {
            result.push(grid[r1 * 5 + (c1 + 1) % 5]);
            result.push(grid[r2 * 5 + (c2 + 1) % 5]);
        } else if c1 == c2 {
            result.push(grid[((r1 + 1) % 5) * 5 + c1]);
            result.push(grid[((r2 + 1) % 5) * 5 + c2]);
        } else {
            result.push(grid[r1 * 5 + c2]);
            result.push(grid[r2 * 5 + c1]);
        }
    }
    result
}

/// Decodes a Playfair cipher with a given keyword and 5x5 grid (J=I).
pub fn playfair_decode(text: &str, key: &str) -> String {
    let grid = square_grid(key);

    let find_pos = |c: char| {
        let c = if c == 'J' { 'I' } else { c };
        grid.iter().position(|&x| x == c).unwrap_or(0)
    };

    let clean: Vec<char> = text
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    let mut result = String::new();

    for i in (0..clean.len()).step_by(2) {
        if i + 1 >= clean.len() {
            break;
        }
        let p1 = find_pos(clean[i]);
        let p2 = find_pos(clean[i + 1]);

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

/// Builds the keyed 5x5 Bifid/Playfair grid (J merged into I).
fn square_grid(key: &str) -> [char; 25] {
    let mut grid = ['\0'; 25];
    let mut key_chars = Vec::new();
    let alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // No 'J'

    let key = key.to_uppercase().replace('J', "I");
    for c in key.chars().chain(alphabet.chars()) {
        if c.is_ascii_alphabetic() && !key_chars.contains(&c) {
            key_chars.push(c);
        }
    }
    grid.copy_from_slice(&key_chars[..25]);
    grid
}

/// Encodes a Bifid cipher with a keyword, 5x5 grid (J=I), and period.
/// Fractionate per period block, regroup rows-then-columns, re-pair.
/// Reference vector (practicalcryptography.com): key "phqgmeaylnofdxkrcvszwbuti",
/// period 5, "DEFENDTHEEASTWALLOFTHECASTLE" → "FFYHMKHYCPLIASHADTRLHCCHLBLR".
pub fn bifid_encrypt(text: &str, key: &str, period: usize) -> String {
    let grid = square_grid(key);

    let find_pos = |c: char| {
        let c = if c == 'J' { 'I' } else { c };
        let p = grid.iter().position(|&x| x == c).unwrap_or(0);
        (p / 5, p % 5)
    };

    let clean: Vec<char> = text
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    let mut coords = Vec::new();
    for i in (0..clean.len()).step_by(period) {
        let chunk_size = std::cmp::min(period, clean.len() - i);
        let mut rows = Vec::new();
        let mut cols = Vec::new();
        for j in 0..chunk_size {
            let (r, c) = find_pos(clean[i + j]);
            rows.push(r);
            cols.push(c);
        }
        coords.extend(rows);
        coords.extend(cols);
    }

    let mut result = String::new();
    for i in (0..coords.len()).step_by(2) {
        result.push(grid[coords[i] * 5 + coords[i + 1]]);
    }
    result
}

/// Decodes a Bifid cipher: the inverse regrouping. Per period block, the
/// flat coordinate stream splits back into row and column halves, and each
/// plaintext letter takes one coordinate from each half.
pub fn bifid_decrypt(text: &str, key: &str, period: usize) -> String {
    let grid = square_grid(key);
    let period = period.max(1);

    let clean: Vec<char> = text
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| if c == 'J' { 'I' } else { c })
        .collect();
    let mut result = String::new();
    for block in clean.chunks(period) {
        let mut flat = Vec::with_capacity(block.len() * 2);
        for &c in block {
            let pos = grid.iter().position(|&x| x == c).unwrap_or(0);
            flat.push(pos / 5);
            flat.push(pos % 5);
        }
        let n = block.len();
        for j in 0..n {
            result.push(grid[flat[j] * 5 + flat[n + j]]);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bifid_reference_vector() {
        // practicalcryptography.com worked example.
        let key = "phqgmeaylnofdxkrcvszwbuti";
        let plain = "DEFENDTHEEASTWALLOFTHECASTLE";
        let cipher = "FFYHMKHYCPLIASHADTRLHCCHLBLR";
        assert_eq!(bifid_encrypt(plain, key, 5), cipher);
        assert_eq!(bifid_decrypt(cipher, key, 5), plain);
    }

    #[test]
    fn playfair_wikipedia_vector_decodes() {
        // Ciphertext from the textbook example (prepared plaintext had an X filler).
        assert_eq!(
            playfair_decode("BMODZBXDNABEKUDMUIXMMOUVIF", "PLAYFAIREXAMPLE"),
            "HIDETHEGOLDINTHETREXESTUMP"
        );
    }

    #[test]
    fn playfair_roundtrip() {
        // Even length, no double letters, no J.
        let cipher = playfair_encrypt("HIDETHEGOLDINTHETRES", "PLAYFAIREXAMPLE");
        assert_eq!(playfair_decode(&cipher, "PLAYFAIREXAMPLE"), "HIDETHEGOLDINTHETRES");
    }

}
