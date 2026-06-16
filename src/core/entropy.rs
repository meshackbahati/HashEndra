use serde::Serialize;

const ENTROPY_WINDOW: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct EntropyBoundary {
    pub offset: usize,
    pub entropy_before: f64,
    pub entropy_after: f64,
    pub delta: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntropyProfile {
    pub total_size: usize,
    pub overall_entropy: f64,
    pub segments: Vec<EntropySegment>,
    pub boundaries: Vec<EntropyBoundary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntropySegment {
    pub offset: usize,
    pub length: usize,
    pub entropy: f64,
    pub classification: &'static str,
}

/// Computes Shannon entropy of a byte slice.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] = freq[b as usize].saturating_add(1);
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Computes a rolling entropy profile over a sliding window.
/// Returns per-window entropy values at stride intervals.
pub fn rolling_entropy(data: &[u8], window_size: usize, stride: usize) -> Vec<(usize, f64)> {
    if data.is_empty() || window_size == 0 {
        return Vec::new();
    }
    let stride = stride.max(1);
    let mut profile = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let end = (offset + window_size).min(data.len());
        let e = shannon_entropy(&data[offset..end]);
        profile.push((offset, e));
        offset = offset.saturating_add(stride);
        if offset >= data.len() {
            break;
        }
    }
    profile
}

/// Scans for boundaries where entropy changes significantly.
/// A boundary is marked when |entropy_delta| > threshold.
pub fn detect_boundaries(
    data: &[u8],
    window_size: usize,
    stride: usize,
    threshold: f64,
) -> Vec<EntropyBoundary> {
    if data.len() < window_size * 2 {
        return Vec::new();
    }
    let profile = rolling_entropy(data, window_size, stride);
    let mut boundaries = Vec::new();

    for pair in profile.windows(2) {
        let delta = (pair[1].1 - pair[0].1).abs();
        if delta >= threshold {
            let boundary_offset = (pair[0].0 + pair[1].0) / 2;
            boundaries.push(EntropyBoundary {
                offset: boundary_offset,
                entropy_before: pair[0].1,
                entropy_after: pair[1].1,
                delta,
            });
        }
    }
    boundaries
}

/// Produces an overall entropy profile with segment classifications.
pub fn entropy_profile(data: &[u8]) -> EntropyProfile {
    let overall = shannon_entropy(data);
    let window = ENTROPY_WINDOW.min(data.len().max(1));
    let stride = window / 4;
    let raw = rolling_entropy(data, window, stride);

    let mut segments = Vec::new();
    let mut seg_start = 0usize;
    if raw.is_empty() {
        return EntropyProfile {
            total_size: data.len(),
            overall_entropy: overall,
            segments,
            boundaries: Vec::new(),
        };
    }
    let mut seg_entropy = raw[0].1;
    let mut seg_frames = vec![seg_entropy];

    for &(offset, ent) in &raw[1..] {
        let delta = (ent - seg_entropy).abs();
        if delta > 0.5 || offset - seg_start > window * 4 {
            let avg = seg_frames.iter().sum::<f64>() / seg_frames.len() as f64;
            segments.push(EntropySegment {
                offset: seg_start,
                length: offset - seg_start,
                entropy: avg,
                classification: classify_entropy(avg),
            });
            seg_start = offset;
            seg_entropy = ent;
            seg_frames.clear();
        }
        seg_frames.push(ent);
    }

    // Last segment
    if !seg_frames.is_empty() {
        let avg = seg_frames.iter().sum::<f64>() / seg_frames.len() as f64;
        let length = data.len() - seg_start;
        if length > 0 {
            segments.push(EntropySegment {
                offset: seg_start,
                length,
                entropy: avg,
                classification: classify_entropy(avg),
            });
        }
    }

    // Detect strong boundaries (high delta)
    let boundaries = detect_boundaries(data, window, stride, 1.0);

    EntropyProfile {
        total_size: data.len(),
        overall_entropy: overall,
        segments,
        boundaries,
    }
}

fn classify_entropy(e: f64) -> &'static str {
    if e < 1.0 {
        "low (text/header)"
    } else if e < 3.0 {
        "medium (semi-random)"
    } else if e < 4.5 {
        "high (compressed)"
    } else {
        "very high (encrypted/random)"
    }
}

/// ASCII visualization of the entropy profile.
pub fn visualize_entropy(data: &[u8], width: usize) -> String {
    let window = ENTROPY_WINDOW.min(data.len().max(1));
    let stride = data.len().max(width) / width;
    let profile = rolling_entropy(data, window, stride.max(1));
    let max_entropy = 8.0f64;
    let mut output = String::new();

    output.push_str(&format!("Entropy profile ({} windows):\n", profile.len()));
    for (offset, ent) in &profile {
        let bar_len = ((ent / max_entropy) * width as f64) as usize;
        let bar: String = std::iter::repeat('█').take(bar_len.min(width)).collect();
        let offset_kb = *offset as f64 / 1024.0;
        output.push_str(&format!("{:>8.1}KB |{:<width$}  {:.2}\n", offset_kb, bar, ent, width = width));
    }
    output.push_str(&format!("Overall entropy: {:.2} bits/byte", shannon_entropy(data)));

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_data_has_zero_entropy() {
        let data = vec![0x00u8; 1024];
        let e = shannon_entropy(&data);
        assert!((e - 0.0).abs() < 0.001);
    }

    #[test]
    fn high_entropy_for_random_data() {
        let data: Vec<u8> = std::iter::repeat(0u8..=255).flatten().take(1024).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.5);
    }

    #[test]
    fn detects_entropy_boundaries() {
        let mut data = vec![0x00u8; 4096];
        let random_part: Vec<u8> = std::iter::repeat(0u8..=255).flatten().take(2048).collect();
        data[1024..3072].copy_from_slice(&random_part);
        let boundaries = detect_boundaries(&data, 256, 64, 1.5);
        assert!(!boundaries.is_empty(), "no boundaries found with delta >1.5");
        assert!(boundaries.iter().any(|b| (b.offset as i64 - 1024).abs() < 512));
    }

    #[test]
    fn profile_creates_segments() {
        let data: Vec<u8> = std::iter::repeat(0u8..=255).flatten().take(4096).collect();
        let profile = entropy_profile(&data);
        assert!(profile.overall_entropy > 7.0);
        assert!(!profile.segments.is_empty());
    }

    #[test]
    fn empty_data_returns_empty() {
        let data = b"";
        let profile = entropy_profile(data);
        assert_eq!(profile.total_size, 0);
        assert!((profile.overall_entropy - 0.0).abs() < 0.001);
    }
}
