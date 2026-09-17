use super::decode::format_jwt_segment;
use colored::*;
use hashendra::core::patterns::{scan_input, ScanningContext, SecurityRating};
use hashendra::core::scanner::{calculate_entropy, decode_url, detect_charset};
use hashendra::safe_println;
use std::io::{self, BufRead};

const VALID_CONTEXTS: &[&str] = &[
    "generic", "network", "filesystem", "shadow", "database", "sql", "memory", "blockchain",
];

pub(crate) fn analyze_single_input(input: &str, json: bool, verbose: bool, context_str: &str) -> bool {
    let context = match context_str.to_lowercase().as_str() {
        "network" => ScanningContext::Network,
        "filesystem" | "shadow" => ScanningContext::Filesystem,
        "database" | "sql" => ScanningContext::Database,
        "memory" => ScanningContext::Memory,
        "blockchain" => ScanningContext::Blockchain,
        other if VALID_CONTEXTS.contains(&other) => ScanningContext::Generic,
        other => {
            if !json {
                safe_println!(
                    "{}",
                    format!("[WARN] Unknown context \"{}\", falling back to Generic", other).yellow()
                );
            }
            ScanningContext::Generic
        }
    };

    let entropy = calculate_entropy(input.as_bytes());
    let charset = detect_charset(input);
    let results = scan_input(input, context.clone());

    if json {
        let output = serde_json::json!({
            "input": input,
            "context": format!("{:?}", context),
            "entropy": entropy,
            "charset": format!("{:?}", charset),
            "results": results
        });
        safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return true;
    }

    safe_println!("\n[INPUT]        : {}", input.white().bold());
    safe_println!("[CONTEXT]      : {:?}", context);
    safe_println!("[LENGTH]       : {} characters", input.len());
    safe_println!("[ENTROPY]      : {:.4} bits/char", entropy);
    safe_println!("[CHARSET]      : {:?}", charset);

    if let Some(top) = results.first() {
        let confidence_bar = "#".repeat((top.confidence * 10.0) as usize)
            + &"-".repeat(10 - (top.confidence * 10.0) as usize);
        safe_println!(
            "[CONFIDENCE]   : [{}] {:.0}%",
            confidence_bar.green(),
            top.confidence * 100.0
        );

        if let Some(rating) = &top.security_rating {
            let rating_str = match rating {
                SecurityRating::Secure => "SECURE",
                SecurityRating::Weak => "WEAK",
                SecurityRating::Broken => "BROKEN",
                SecurityRating::Insecure => "INSECURE",
            };
            safe_println!("[SECURITY]     : {}", rating_str);
        }
    }

    safe_println!("\n+-- DETECTION RESULTS -------------------------------------------+");

    for res in &results {
        let hc = res
            .hashcat_mode
            .map(|m| format!("[hashcat: {}]", m))
            .unwrap_or_default();
        let john = res
            .john_format
            .as_ref()
            .map(|f| format!("[john: {}]", f))
            .unwrap_or_default();

        let status = if res.confidence > 0.8 { "[OK]" } else { "[i]" };
        safe_println!(
            "|  {} {:<18} {:.0}%  {:<12} {:<12} |",
            status,
            res.name,
            res.confidence * 100.0,
            hc,
            john
        );

        if !res.extracted_parameters.is_empty() {
            for (k, v) in &res.extracted_parameters {
                safe_println!("|      -> {}: {} {:<30} |", k.cyan(), v.white(), "");
            }
        }

        if !res.compliance_refs.is_empty() {
            safe_println!(
                "|      -> Compliance: {} {:<30} |",
                res.compliance_refs.join(", ").yellow(),
                ""
            );
        }
    }

    if results.is_empty() {
        safe_println!("|  [FAIL] No matches detected                                     |");
    }

    safe_println!("+----------------------------------------------------------------+");

    if let Some(top) = results.first() {
        safe_println!("\n+-- RECOMMENDATION ----------------------------------------------+");
        safe_println!("   -> Primary : {} ({})", top.name, top.description);
        if results
            .get(1)
            .map(|next| (top.confidence - next.confidence).abs() <= 0.08)
            .unwrap_or(false)
        {
            safe_println!(
                "   -> Note    : Multiple formats share this structure; treat the top hit as a best guess."
            );
        }
        if let Some(hc) = top.hashcat_mode {
            safe_println!("   -> Crack   : hashcat -m {} hash.txt rockyou.txt", hc);
        }
        if !top.compliance_refs.is_empty() {
            safe_println!(
                "   -> Status  : Does not meet {}",
                top.compliance_refs.join(", ")
            );
        }
        safe_println!("+----------------------------------------------------------------+");
    }
    // Show decoded content for JWT and URL encoding
    if let Some(top) = results.first() {
        match top.name.as_str() {
            "JWT" => {
                let parts: Vec<&str> = input.splitn(3, '.').collect();
                if parts.len() == 3 {
                    safe_println!("\n+-- JWT DECODED -------------------------------------------------+");
                    if let Some(header) = format_jwt_segment(parts[0]) {
                        safe_println!("|  header: {}", header.green());
                    }
                    if let Some(payload) = format_jwt_segment(parts[1]) {
                        safe_println!("|  payload: {}", payload.cyan());
                    }
                    safe_println!("+----------------------------------------------------------------+");
                    safe_println!("  JWT (RFC 7519) consists of 3 parts:");
                    safe_println!("  Header    - Base64url-encoded JSON (algorithm & token type)");
                    safe_println!("  Payload   - Base64url-encoded JSON (claims / data)");
                    safe_println!("  Signature - Cryptographic signature (verify with secret key)");
                    safe_println!("  Crack with hashcat -m 16500 <jwt> <wordlist>");
                }
            }
            "URL Encoding" => {
                if let Some(decoded) = decode_url(input) {
                    safe_println!("\n+-- URL DECODED -------------------------------------------------+");
                    safe_println!("|  decoded: {}", decoded.green());
                    safe_println!("+----------------------------------------------------------------+");
                    safe_println!("  URL encoding (RFC 3986) replaces special chars with %xx");
                    safe_println!("  where xx is the hex code of the character. '+' is space.");
                }
            }
            _ => {}
        }
    }

    if verbose {
        safe_println!("\n=================================================================");
        safe_println!("Technical Analysis:");
        safe_println!(
            "  * Byte distribution: {:?}",
            input.as_bytes().iter().take(8).collect::<Vec<_>>()
        );
        safe_println!("=================================================================");
    }
    true
}

pub(crate) fn analyze_file(path: &str, json: bool) -> bool {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            safe_println!("[FAIL] cannot open {}: {}", path, error);
            return false;
        }
    };
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        match line {
            Ok(line) => {
                analyze_single_input(&line, json, false, "generic");
            }
            Err(e) => {
                eprintln!("WARN: skipping line in {}: {}", path, e);
            }
        }
    }
    true
}

pub(crate) fn detect_path_file_type(path: &std::path::Path) -> String {
    hashendra::forensics::filetypes::detect_path_file_type(path)
}

pub(crate) fn print_path_metadata(path: &std::path::Path) {
    match hashendra::forensics::filetypes::read_path_metadata(path) {
        Some(meta) => {
            safe_println!("{}", "[METADATA]".cyan());
            safe_println!("  Path : {}", path.display());
            safe_println!("  Size : {} bytes", meta.size);
            safe_println!(
                "  Type : {}",
                if meta.is_dir { "directory" } else { "file" }
            );
        }
        None => safe_println!("{}", "[FAIL] metadata: could not read path metadata".red()),
    }
}

pub(crate) fn preview_strings_from_path(path: &std::path::Path, min_len: usize, limit: usize) {
    match std::fs::read(path) {
        Ok(data) => {
            let mut flattened = hashendra::forensics::strings::flatten_string_lines(
                hashendra::forensics::strings::extract_printable_strings(&data, min_len),
                min_len.min(4),
                "ascii",
            );
            flattened.extend(hashendra::forensics::strings::flatten_string_lines(
                hashendra::forensics::strings::extract_utf16le_strings(&data, min_len / 2 + 1),
                min_len.min(4),
                "utf16le",
            ));
            safe_println!(
                "{}",
                format!(
                    "[STRINGS] {} candidate strings (min {}, showing {})",
                    flattened.len(),
                    min_len,
                    flattened.len().min(limit)
                )
                .cyan()
            );
            for (offset, encoding, value) in flattened.iter().take(limit) {
                safe_println!("  0x{:08x} [{}] {}", offset, encoding, value);
            }
        }
        Err(e) => safe_println!("{}", format!("[FAIL] string extraction: {}", e).red()),
    }
}
