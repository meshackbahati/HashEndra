//! Streaming dictionary cracker for raw hashes.
//!
//! Memory-first: the wordlist is memory-mapped and never loaded into RAM.
//! The main thread slices it into offset windows (a few MB at most); workers
//! hash candidates straight from the mapped bytes. No per-candidate hex,
//! no wordlist Vec, no result accumulation.
//!
//! CPU-only speed tiers (no GPU here): explicit rayon pools. `Eco` sips
//! cores for laptops, `Normal` takes half, `Turbo` takes everything with
//! bigger batches to amortize scheduling.

use crate::core::hasher::{compute_hash, HashAlgorithm};
use std::io;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    Eco,
    Normal,
    Turbo,
}

impl Speed {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "eco" | "low" => Some(Self::Eco),
            "normal" | "balanced" | "medium" => Some(Self::Normal),
            "turbo" | "fast" | "high" => Some(Self::Turbo),
            _ => None,
        }
    }

    /// (worker threads, lines per batch, progress seconds)
    fn plan(&self, cores: usize) -> (usize, usize, u64) {
        match self {
            Self::Eco => ((cores / 4).max(1), 1024, 2),
            Self::Normal => ((cores / 2).max(1), 8192, 1),
            Self::Turbo => (cores.max(1), 65536, 5),
        }
    }
}

pub struct CrackConfig {
    pub jobs: Option<usize>,
    pub speed: Speed,
    pub rules: bool,
    pub max_candidates: Option<u64>,
}

pub struct CrackResult {
    pub found: Option<Vec<u8>>,
    pub attempts: u64,
    pub seconds: f64,
}

/// Identify the algorithm from a hex hash by length. 64 hex chars are
/// ambiguous (SHA-256 vs BLAKE3) — SHA-256 wins by prevalence; pass
/// `--format blake3` to override.
pub fn detect_crack_format(hash: &str) -> Result<HashAlgorithm, String> {
    let clean: String = hash.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("hash is not hex — only raw hex digests are supported".to_string());
    }
    match clean.len() {
        32 => Ok(HashAlgorithm::Md5),
        40 => Ok(HashAlgorithm::Sha1),
        56 => Ok(HashAlgorithm::Sha224),
        64 => Ok(HashAlgorithm::Sha256),
        96 => Ok(HashAlgorithm::Sha384),
        128 => Ok(HashAlgorithm::Sha512),
        n => Err(format!(
            "cannot map {n} hex chars to a supported algorithm (md5, sha1, sha224, sha256, sha384, sha512, blake3)"
        )),
    }
}

pub fn parse_hex_hash(hash: &str) -> Result<Vec<u8>, String> {
    let clean: String = hash.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean.len().is_multiple_of(2) || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("hash must be even-length hex".to_string());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Pure candidate test: hash and compare bytes. No allocation beyond the digest.
pub fn crack_one(target: &[u8], algo: &HashAlgorithm, password: &[u8]) -> bool {
    compute_hash(password, algo) == target
}

/// Candidate mutations for one word. Light set by default; `--rules` adds
/// two-digit appends, year range, and common suffixes. Bounded and explicit.
pub fn mutate_word(word: &[u8], extended: bool, out: &mut Vec<Vec<u8>>) {
    out.clear();
    out.push(word.to_vec());
    out.push(ascii_lower(word));
    out.push(ascii_upper(word));
    out.push(capitalize(word));
    for d in b'0'..=b'9' {
        let mut v = Vec::with_capacity(word.len() + 1);
        v.extend_from_slice(word);
        v.push(d);
        out.push(v);
        let mut v = Vec::with_capacity(word.len() + 1);
        v.push(d);
        v.extend_from_slice(word);
        out.push(v);
    }
    if !extended {
        return;
    }
    for d1 in b'0'..=b'9' {
        for d2 in b'0'..=b'9' {
            let mut v = Vec::with_capacity(word.len() + 2);
            v.extend_from_slice(word);
            v.push(d1);
            v.push(d2);
            out.push(v);
        }
    }
    for year in 1990u16..=2026u16 {
        let mut v = Vec::with_capacity(word.len() + 4);
        v.extend_from_slice(word);
        v.extend_from_slice(year.to_string().as_bytes());
        out.push(v);
    }
    for suffix in ["123", "1234", "12345", "!", "!!", "?", "1!", ".", "01", "007"] {
        let mut v = Vec::with_capacity(word.len() + suffix.len());
        v.extend_from_slice(word);
        v.extend_from_slice(suffix.as_bytes());
        out.push(v);
    }
}

fn ascii_lower(word: &[u8]) -> Vec<u8> {
    word.iter()
        .map(|&b| if b.is_ascii_uppercase() { b + 32 } else { b })
        .collect()
}

fn ascii_upper(word: &[u8]) -> Vec<u8> {
    word.iter()
        .map(|&b| if b.is_ascii_lowercase() { b - 32 } else { b })
        .collect()
}

fn capitalize(word: &[u8]) -> Vec<u8> {
    let mut v = ascii_lower(word);
    if let Some(first) = v.first_mut()
        && first.is_ascii_lowercase() {
            *first -= 32;
        }
    v
}

/// Crack `target` against a wordlist file. Streams offset windows; the file
/// itself is never copied into RAM.
pub fn crack_wordlist(
    target: &[u8],
    algo: &HashAlgorithm,
    path: &Path,
    config: &CrackConfig,
    progress: bool,
) -> io::Result<CrackResult> {
    let file = std::fs::File::open(path)?;
    // SAFETY: read-only mapping, never truncated or written while mapped.
    let map = unsafe { memmap2::Mmap::map(&file)? };
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let (mut workers, batch_lines, report_secs) = config.speed.plan(cores);
    if let Some(jobs) = config.jobs {
        workers = jobs.max(1);
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .map_err(|e| io::Error::other(e.to_string()))?;
    let found = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let answer: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let stop = Arc::new(AtomicBool::new(false));
    let start = Instant::now();

    // Progress reporter on stderr; stdout stays clean for piping.
    // Detached thread, joined via the stop flag + a short grace sleep.
    if progress {
        let attempts_r = Arc::clone(&attempts);
        let found_r = Arc::clone(&found);
        let stop_r = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut last = 0u64;
            let mut last_t = Instant::now();
            while !stop_r.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(report_secs));
                let done = attempts_r.load(Ordering::Relaxed);
                let dt = last_t.elapsed().as_secs_f64().max(0.001);
                eprintln!(
                    "[crack] {} candidates ({:.1} H/s){}",
                    done,
                    (done - last) as f64 / dt,
                    if found_r.load(Ordering::Relaxed) {
                        " — found, finishing batch"
                    } else {
                        ""
                    }
                );
                last = done;
                last_t = Instant::now();
            }
        });
    }

    let max = config.max_candidates.unwrap_or(u64::MAX);
    let extended = config.rules;
    let mut window: Vec<(usize, usize)> = Vec::with_capacity(batch_lines);
    let mut line_start = 0usize;
    let bytes = &map[..];

    // NOTE: stop/attempt accounting uses a helper closure-free loop so the
    // hot path stays branch-light.
    let mut i = 0usize;
    while i <= bytes.len() {
        let end = bytes[i..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| i + p)
            .unwrap_or(bytes.len());
        if end > line_start {
            let mut line_end = end;
            if bytes[line_end - 1] == b'\r' {
                line_end -= 1;
            }
            window.push((line_start, line_end));
        }
        line_start = end + 1;
        i = end + 1;
        if window.len() >= batch_lines || i > bytes.len() {
            if window.is_empty() {
                break;
            }
            pool.install(|| {
                use rayon::prelude::*;
                window.par_iter().for_each(|&(s, e)| {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let word = &bytes[s..e];
                    // Reused scratch per line: one small Vec of candidates.
                    let mut candidates: Vec<Vec<u8>> = Vec::new();
                    mutate_word(word, extended, &mut candidates);
                    for cand in &candidates {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        let n = attempts.fetch_add(1, Ordering::Relaxed) + 1;
                        if n >= max {
                            stop.store(true, Ordering::Relaxed);
                            return;
                        }
                        if crack_one(target, algo, cand) {
                            *answer.lock().unwrap() = Some(cand.clone());
                            found.store(true, Ordering::Relaxed);
                            stop.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                });
            });
            window.clear();
            if stop.load(Ordering::Relaxed) {
                break;
            }
        }
        if i > bytes.len() {
            break;
        }
    }

    stop.store(true, Ordering::Relaxed);
    let seconds = start.elapsed().as_secs_f64();
    Ok(CrackResult {
        found: answer.lock().unwrap().clone(),
        attempts: attempts.load(Ordering::Relaxed),
        seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crack_one_finds_md5_password() {
        // md5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
        let target = parse_hex_hash("5f4dcc3b5aa765d61d8327deb882cf99").unwrap();
        assert!(crack_one(&target, &HashAlgorithm::Md5, b"password"));
        assert!(!crack_one(&target, &HashAlgorithm::Md5, b"passwore"));
    }

    #[test]
    fn detect_format_by_length() {
        assert!(matches!(
            detect_crack_format(&"a".repeat(32)),
            Ok(HashAlgorithm::Md5)
        ));
        assert!(matches!(
            detect_crack_format(&"a".repeat(40)),
            Ok(HashAlgorithm::Sha1)
        ));
        assert!(detect_crack_format(&"a".repeat(33)).is_err());
        assert!(detect_crack_format("not hex at all!!").is_err());
    }

    #[test]
    fn light_mutations_cover_case_and_digits() {
        let mut out = Vec::new();
        mutate_word(b"Pass", false, &mut out);
        let has = |s: &str| out.iter().any(|v| v == s.as_bytes());
        assert!(has("Pass") && has("pass") && has("PASS") && has("Pass0") && has("0Pass"));
        assert_eq!(out.len(), 4 + 20);
    }

    #[test]
    fn extended_mutations_stay_bounded() {
        let mut out = Vec::new();
        mutate_word(b"pw", true, &mut out);
        assert!(out.len() < 220);
    }
}
