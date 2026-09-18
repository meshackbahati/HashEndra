/// Rail index for each step of a zigzag traversal.
/// Shared by the mark and read passes so the direction logic lives in one place.
pub(crate) fn zigzag_rails(len: usize, rails: usize) -> Vec<usize> {    let mut seq = Vec::with_capacity(len);
    let (mut rail, mut direction) = (0i32, 1i32);
    for _ in 0..len {
        seq.push(rail as usize);
        if rail == 0 {
            direction = 1;
        } else if rail == rails as i32 - 1 {
            direction = -1;
        }
        rail += direction;
    }
    seq
}

/// Decodes a Rail Fence cipher with a given number of rails.
///
/// ```
/// use hashendra::detectors::classic_transposition::rail_fence_decode;
/// assert_eq!(rail_fence_decode("HELLO", 1), "HELLO");
/// ```
pub fn rail_fence_decode(text: &str, rails: usize) -> String {
    if rails <= 1 {
        return text.to_string();
    }

    let mut fence = vec![vec!['\0'; text.len()]; rails];

    // Mark the rail positions
    for (i, rail) in zigzag_rails(text.len(), rails).into_iter().enumerate() {
        fence[rail][i] = '*';
    }

    // Fill the rail positions with text characters
    let mut iter = text.chars();
    for row in fence.iter_mut() {
        for cell in row.iter_mut() {
            if *cell == '*'
                && let Some(ch) = iter.next() {
                    *cell = ch;
                }
        }
    }

    // Read in zigzag order
    let mut result = String::new();
    for (i, rail) in zigzag_rails(text.len(), rails).into_iter().enumerate() {
        result.push(fence[rail][i]);
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

/// Column order for a string key: indices sorted by key byte,
/// ties broken left to right. Byte-based to match `columnar_encrypt`
/// exactly; use ASCII keys.
pub fn columnar_order(key: &str) -> Vec<usize> {
    let bytes = key.as_bytes();
    let mut order: Vec<usize> = (0..bytes.len()).collect();
    order.sort_by_key(|&i| (bytes[i], i));
    order
}

/// Decodes a Columnar Transposition cipher with a given key (permutation).
///
/// A single-column key is the identity:
///
/// ```
/// use hashendra::detectors::classic_transposition::columnar_decode;
/// assert_eq!(columnar_decode("AB", &[0]), "AB");
/// ```
pub fn columnar_decode(text: &str, key: &[usize]) -> String {
    let cols = key.len();
    let rows = (text.len() as f32 / cols as f32).ceil() as usize;
    let mut grid = vec![vec![' '; cols]; rows];

    // Fill the grid column by column according to the key
    let mut chars = text.chars();
    for &col_idx in key {
        for row in grid.iter_mut() {
            if let Some(c) = chars.next() {
                row[col_idx] = c;
            }
        }
    }

    // Read row by row
    let mut result = String::new();
    for row in &grid {
        result.extend(row.iter());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zigzag_sequence_goes_down_then_up() {
        assert_eq!(zigzag_rails(8, 3), vec![0, 1, 2, 1, 0, 1, 2, 1]);
    }

    #[test]
    fn zigzag_two_rails_alternates() {
        assert_eq!(zigzag_rails(5, 2), vec![0, 1, 0, 1, 0]);
    }

    #[test]
    fn rail_fence_single_rail_is_identity() {
        assert_eq!(rail_fence_decode("ATTACK AT DAWN", 1), "ATTACK AT DAWN");
    }

    #[test]
    fn rail_fence_known_answer() {
        // Textbook vector: "WEAREDISCOVEREDFLEEATONCE" encoded with 3 rails.
        assert_eq!(
            rail_fence_decode("WECRLTEERDSOEEFEAOCAIVDEN", 3),
            "WEAREDISCOVEREDFLEEATONCE"
        );
    }

    #[test]
    fn columnar_single_column_is_identity() {
        assert_eq!(columnar_decode("HELLO WORLD", &[0]), "HELLO WORLD");
    }
}
