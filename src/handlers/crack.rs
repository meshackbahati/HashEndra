use colored::*;
use hashendra::core::crack::{
    crack_wordlist, detect_crack_format, parse_hex_hash, CrackConfig, Speed,
};
use hashendra::core::hasher::HashAlgorithm;
use hashendra::safe_println;
use std::path::Path;

/// Crack one hash against a wordlist file. Streams the file; found passwords
/// print to stdout (or JSON with -j). Returns true only when cracked.
pub(crate) struct CrackArgs<'a> {
    pub(crate) hash: &'a str,
    pub(crate) wordlist: &'a str,
    pub(crate) format: Option<&'a str>,
    pub(crate) rules: bool,
    pub(crate) jobs: Option<usize>,
    pub(crate) speed: &'a str,
    pub(crate) max_candidates: Option<u64>,
    pub(crate) json: bool,
}

pub(crate) fn run_crack(args: CrackArgs<'_>) -> bool {
    let CrackArgs {
        hash,
        wordlist,
        format,
        rules,
        jobs,
        speed,
        max_candidates,
        json,
    } = args;
    let algo: HashAlgorithm = match format {
        Some(name) => match HashAlgorithm::from_name(name) {
            Some(a) => a,
            None => {
                safe_println!(
                    "{} Unknown format '{}'. Use --list-hashes to see supported algorithms.",
                    "[ERROR]".red().bold(),
                    name
                );
                return false;
            }
        },
        None => match detect_crack_format(hash) {
            Ok(a) => a,
            Err(e) => {
                safe_println!("{} {}", "[ERROR]".red().bold(), e);
                return false;
            }
        },
    };
    let target = match parse_hex_hash(hash) {
        Ok(bytes) => bytes,
        Err(e) => {
            safe_println!("{} {}", "[ERROR]".red().bold(), e);
            return false;
        }
    };
    if target.len() != algo.digest_length() {
        safe_println!(
            "{} Hash is {} bytes but {} digests are {} bytes. Pass --format explicitly if auto-detect guessed wrong.",
            "[ERROR]".red().bold(),
            target.len(),
            algo.name(),
            algo.digest_length()
        );
        return false;
    }
    let speed = match Speed::from_name(speed) {
        Some(s) => s,
        None => {
            safe_println!(
                "{} Unknown speed '{}'. Use eco, normal, or turbo.",
                "[ERROR]".red().bold(),
                speed
            );
            return false;
        }
    };
    if !json {
        safe_println!(
            "[CRACK] {} against {} ({} rules, {:?} speed{})",
            algo.name(),
            wordlist,
            if rules { "extended" } else { "light" },
            speed,
            jobs.map(|j| format!(", {} jobs", j)).unwrap_or_default()
        );
    }
    let config = CrackConfig {
        jobs,
        speed,
        rules,
        max_candidates,
    };
    let result = match crack_wordlist(&target, &algo, Path::new(wordlist), &config, !json) {
        Ok(r) => r,
        Err(e) => {
            safe_println!("{} {}", "[ERROR]".red().bold(), e);
            return false;
        }
    };
    let hps = result.attempts as f64 / result.seconds.max(0.001);
    match result.found {
        Some(password) => {
            let text = String::from_utf8_lossy(&password).into_owned();
            if json {
                safe_println!(
                    "{}",
                    serde_json::json!({
                        "hash": hash,
                        "algorithm": algo.name(),
                        "found": true,
                        "password": text,
                        "attempts": result.attempts,
                        "seconds": result.seconds,
                        "hps": hps as u64,
                    })
                );
            } else {
                safe_println!("[OK] Cracked in {:.1}s ({} candidates, {:.0} H/s)", result.seconds, result.attempts, hps);
                safe_println!("  password: {}", text.green().bold());
            }
            true
        }
        None => {
            if json {
                safe_println!(
                    "{}",
                    serde_json::json!({
                        "hash": hash,
                        "algorithm": algo.name(),
                        "found": false,
                        "attempts": result.attempts,
                        "seconds": result.seconds,
                        "hps": hps as u64,
                    })
                );
            } else {
                safe_println!(
                    "[FAIL] Not found after {} candidates in {:.1}s ({:.0} H/s). Try --rules or a bigger wordlist.",
                    result.attempts, result.seconds, hps
                );
            }
            false
        }
    }
}
