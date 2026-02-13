
/// Standard English letter frequencies (A-Z)
pub const ENGLISH_FREQS: [f32; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
    0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
    0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
];

/// Calculates the Index of Coincidence (IoC) of a string.
/// Values around 0.0667 suggest English plaintext.
/// Values around 0.0385 suggest random distribution (polyalphabetic encryption).
pub fn calculate_ioc(text: &str) -> f32 {
    let chars: Vec<char> = text.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    
    let n = chars.len() as f32;
    if n <= 1.0 { return 0.0; }

    let mut counts = [0f32; 26];
    for c in chars {
        counts[(c as u8 - b'a') as usize] += 1.0;
    }

    let sum: f32 = counts.iter().map(|&f| f * (f - 1.0)).sum();
    sum / (n * (n - 1.0))
}

/// Calculates the Chi-Squared statistic of the text against English frequencies.
/// Lower values indicate a closer match to English.
pub fn chi_squared_score(text: &str) -> f32 {
    let chars: Vec<char> = text.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    
    let n = chars.len() as f32;
    if n == 0.0 { return f32::MAX; }

    let mut counts = [0f32; 26];
    for c in chars {
        counts[(c as u8 - b'a') as usize] += 1.0;
    }

    let mut score = 0.0;
    for i in 0..26 {
        let expected = ENGLISH_FREQS[i] * n;
        score += (counts[i] - expected).powi(2) / expected;
    }
    score
}

/// Estimates the period (key length) of a polyalphabetic cipher using the Index of Coincidence.
pub fn estimate_vigenere_period(text: &str, max_period: usize) -> Vec<(usize, f32)> {
    let chars: Vec<char> = text.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    
    let mut results = Vec::new();
    for p in 1..=max_period.min(chars.len() / 2) {
        let mut sum_ioc = 0.0;
        for i in 0..p {
            let column: String = chars.iter().step_by(p).skip(i).collect();
            sum_ioc += calculate_ioc(&column);
        }
        results.push((p, sum_ioc / p as f32));
    }
    
    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    results
}

/// Checks if a string contains common English bigrams.
pub fn contains_english_patterns(text: &str) -> f32 {
    let common_bigrams = ["th", "he", "in", "er", "an", "re", "ed", "on", "es", "st"];
    let text = text.to_lowercase();
    let mut matches = 0;
    let mut total = 0;
    
    for i in 0..text.len().saturating_sub(1) {
        if i + 2 > text.len() { break; }
        let bigram = &text[i..i+2];
        if common_bigrams.contains(&bigram) {
            matches += 1;
        }
        total += 1;
    }
    
    if total == 0 { 0.0 } else { matches as f32 / total as f32 }
}

/// A small set of common English quadgrams and their log-probabilities.
/// In a production environment, this would be a much larger dictionary.
pub const QUADGRAMS: &[(&str, f32)] = &[
    ("TION", -4.4), ("NTHE", -4.48), ("THER", -4.5), ("THAT", -4.55), ("OFTH", -4.6),
    ("EDAN", -4.65), ("ANDT", -4.7), ("IONS", -4.75), ("THEY", -4.8), ("INGT", -4.85),
    ("HERE", -4.9), ("Tion", -4.95), ("MENT", -5.0), ("THEI", -5.05), ("STHE", -5.1),
    ("WHER", -5.15), ("TTHE", -5.2), ("HAND", -5.25), ("ATTH", -5.3), ("ROME", -5.35),
    ("THIS", -5.4), ("THES", -5.45), ("WITH", -5.5), ("HAVE", -5.55), ("FROM", -5.6),
    ("THEM", -5.65), ("WHIC", -5.7), ("WASF", -5.75), ("OFTV", -5.8), ("ANDI", -5.85),
];

/// Scores text based on English quadgram log-probabilities.
/// Returns a negative value; higher (closer to zero) is better.
pub fn quadgram_score(text: &str) -> f32 {
    let text = text.to_uppercase();
    let mut score = 0.0;
    let mut count = 0;

    for i in 0..text.len().saturating_sub(3) {
        let quad = &text[i..i+4];
        if quad.chars().all(|c| c.is_ascii_alphabetic()) {
            if let Some(&(_, log_p)) = QUADGRAMS.iter().find(|(q, _)| *q == quad) {
                score += log_p;
            } else {
                score += -10.0; // Penalty for unknown quadgrams
            }
            count += 1;
        }
    }

    if count == 0 { -100.0 } else { score / count as f32 }
}

/// Calculates the Hamming distance between two byte slices.
pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum()
}

/// Estimates the likely key length for a repeating-key XOR cipher.
pub fn estimate_xor_key_length(data: &[u8], max_key_len: usize) -> Vec<(usize, f32)> {
    let mut distances = Vec::new();

    for key_len in 2..=max_key_len {
        let iters = 4;
        if data.len() < key_len * (iters + 1) { break; }
        
        let mut sum_dist = 0.0;
        for i in 0..iters {
            let chunk1 = &data[i * key_len..(i + 1) * key_len];
            let chunk2 = &data[(i + 1) * key_len..(i + 2) * key_len];
            sum_dist += hamming_distance(chunk1, chunk2) as f32 / key_len as f32;
        }
        
        distances.push((key_len, sum_dist / iters as f32));
    }

    distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    distances
}

/// Cracks multi-byte (repeating-key) XOR by estimating key length 
/// and then cracking each byte column as single-byte XOR.
pub fn multi_byte_xor_crack(data: &[u8]) -> Option<(Vec<u8>, String, f32)> {
    let key_lengths = estimate_xor_key_length(data, 32);
    if key_lengths.is_empty() { return None; }

    let mut best_score = 0.0;
    let mut best_key = Vec::new();
    let mut best_text = String::new();

    // Test top 3 estimated key lengths
    for &(len, _) in key_lengths.iter().take(3) {
        let mut key = Vec::with_capacity(len);
        for i in 0..len {
            let mut col = Vec::new();
            for j in (i..data.len()).step_by(len) {
                col.push(data[j]);
            }
            
            // Find best single-byte XOR key for this column
            let mut col_best_key = 0;
            let mut col_best_score = 0.0;
            for k in 0..=255u8 {
                let decoded: Vec<u8> = col.iter().map(|&b| b ^ k).collect();
                let printable = decoded.iter().filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace()).count();
                let score = printable as f32 / decoded.len() as f32;
                if score > col_best_score {
                    col_best_score = score;
                    col_best_key = k;
                }
            }
            key.push(col_best_key);
        }

        let decoded: Vec<u8> = data.iter().enumerate().map(|(i, &b)| b ^ key[i % len]).collect();
        if let Ok(s) = String::from_utf8(decoded) {
            let total_printable = s.chars().filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()).count();
            let score = total_printable as f32 / s.len() as f32;
            if score > best_score {
                best_score = score;
                best_key = key.clone();
                best_text = s;
            }
        }
    }

    if best_score > 0.8 && !best_key.iter().all(|&k| k == 0) {
        // Reject identity keys and weak results
        let alpha_count = best_text.chars().filter(|c| c.is_ascii_alphabetic()).count();
        let alpha_ratio = alpha_count as f32 / best_text.len().max(1) as f32;
        if alpha_ratio > 0.6 {
            Some((best_key, best_text, best_score))
        } else {
            None
        }
    } else {
        None
    }
}
