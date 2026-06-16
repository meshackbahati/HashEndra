use clap::{Parser, Subcommand};
use colored::*;
use hashendra::core::encoder::{encode_to_format, ENCODING_FORMATS};
use hashendra::core::hasher::{compute_hash, hash_to_hex, HashAlgorithm, HASH_ALGORITHMS};
use hashendra::core::patterns::{scan_input, ScanningContext, SecurityRating, EXTERNAL_SIGNATURE_COUNT};
use hashendra::core::recursive_engine::RecursiveEngine;
use hashendra::core::scanner::{calculate_entropy, detect_charset, decode_base64_url, decode_url};
use hashendra::safe_print;
use hashendra::safe_println;
use std::io::{self, BufRead, Write};

// safe_println! and safe_print! are defined in utils/io.rs via #[macro_export]

#[derive(Parser)]
#[command(name = "hashendra")]
#[command(version = "2.0.0")]
#[command(about = "HashEndra - Universal Forensic Decryption & Hashing Engine", long_about = "\
EXAMPLES:
  hashendra \"5d41402abc4b2a76b9719d911017c592\"     Identify a hash
  hashendra --decode \"aGVsbG8=\"                     Decode a single layer
  hashendra --deep-decrypt \"NzI3Ng==\"               Recursively unwrap encodings
  hashendra --rot \"Uryyb Jbeyq\"                     Brute-force ROT cipher
  hashendra --xor \"1b37373331363f78\"                 Crack single-byte XOR
  hashendra --hash sha256 \"hello world\"              Compute a hash
  hashendra --to base64 \"hello\"                      Encode to Base64
  hashendra --to morse \"SOS\"                         Encode to Morse code
  hashendra --encrypt caesar --key 13 \"hello\"         Encrypt with Caesar cipher
  hashendra -f hashes.txt                              Batch process a file
  hashendra -j \"d2Vi\"                                JSON output
  hashendra --context network \"GET /index.html\"       Context-aware detection
  hashendra forensic scan image.jpg                    Extract file metadata
  hashendra forensic carve disk.dd -o carved/          Carve embedded files
  hashendra forensic disk --deleted-only image.dd      Recover deleted files
  hashendra workshop                                   Interactive workshop

MORE INFO:
  See https://github.com/hashendra/hashendra or docs/ directory")]
struct Cli {
    #[arg(help = "The hash or encoded string to analyze")]
    input: Option<String>,

    #[arg(short, long, help = "File to read hashes from")]
    file: Option<String>,

    #[arg(short, long, help = "Output in JSON format")]
    json: bool,

    #[arg(short, long, help = "Verbose mode")]
    verbose: bool,

    #[arg(long, help = "Attempt to decode the input")]
    decode: bool,

    #[arg(long, help = "Run deep recursive decryption (multi-layer)")]
    deep_decrypt: bool,

    #[arg(long, help = "Brute-force ROT cipher")]
    rot: bool,

    #[arg(long, help = "Crack single-byte XOR")]
    xor: bool,

    #[arg(
        long,
        default_value = "generic",
        help = "Context for detection (network, database, filesystem, etc.)"
    )]
    context: String,

    #[arg(
        long,
        help = "Compute a cryptographic hash of the input. Optionally specify algorithm: md5, sha1, sha256, sha512, blake3, etc. Use --list-hashes to see all."
    )]
    hash: Option<Option<String>>,

    #[arg(long, help = "List supported hash algorithms and exit")]
    list_hashes: bool,

    #[arg(
        long,
        help = "Encode input to a format: base64, base64url, base32, base58, hex, url, html, qp, binary, octal, morse, ascii85"
    )]
    to: Option<String>,

    #[arg(long, help = "List supported encoding formats and exit")]
    list_encodings: bool,

    #[arg(
        long,
        help = "Encrypt input using a cipher. Usage: --encrypt <cipher> --key <key>. Ciphers: caesar, vigenere, affine, rail-fence, xor, columnar, atbash"
    )]
    encrypt: Option<String>,

    #[arg(
        long,
        help = "Key for encryption ciphers (shift number for caesar, 'a,b' for affine, string key for others)"
    )]
    key: Option<String>,

    #[arg(
        long,
        help = "Additional cipher parameter (number of rails for rail-fence)"
    )]
    cipher_param: Option<String>,

    #[arg(long, help = "List supported encryption ciphers and exit")]
    list_ciphers: bool,

    #[arg(
        long,
        help = "Load custom detection signatures from a JSON file"
    )]
    custom_signatures: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Update the signature database
    Update,
    /// Forensic workflows: scan files, inspect disks, and carve artifacts
    Forensic {
        #[command(subcommand)]
        command: ForensicCommands,
    },
    /// Backward-compatible alias for `forensic disk`
    #[command(hide = true)]
    Disk {
        path: String,
        #[arg(long, default_value_t = 512, help = "Sector size for partition math")]
        sector_size: usize,
    },
    /// Backward-compatible alias for `forensic disk --ntfs`
    #[command(hide = true)]
    Ntfs {
        path: String,
        #[arg(
            long,
            default_value_t = 0,
            help = "Byte offset to the NTFS volume start"
        )]
        offset: usize,
        #[arg(long, default_value_t = 256, help = "Maximum MFT records to inspect")]
        max_records: usize,
        #[arg(long, help = "Only show deleted entries")]
        deleted_only: bool,
        #[arg(long, help = "Include directory records in the results")]
        include_directories: bool,
        #[arg(
            long = "extract-data",
            alias = "extract-resident",
            help = "Recover deleted file content into this directory (resident and non-resident when rebuildable)"
        )]
        extract_data: Option<String>,
        #[arg(long, help = "Allow overwriting existing recovered files")]
        overwrite: bool,
    },
    /// Backward-compatible alias for `forensic carve`
    #[command(hide = true)]
    Carve {
        #[arg(required_unless_present_any = ["list_types", "input"])]
        path: Option<String>,
        #[arg(short = 'i', long, help = "Input file or directory to carve")]
        input: Option<String>,
        #[arg(short, long, help = "Output directory for carved files")]
        output: Option<String>,
        #[arg(short = 'c', long, help = "Foremost-style carve profile config file")]
        config: Option<String>,
        #[arg(
            short = 't',
            long,
            value_delimiter = ',',
            help = "Only carve matching extensions or type names (comma-separated)"
        )]
        types: Vec<String>,
        #[arg(short = 'a', long, help = "Include signatures at offset 0")]
        include_root: bool,
        #[arg(long, default_value_t = 1, help = "Minimum carved size in bytes")]
        min_size: usize,
        #[arg(long, default_value_t = 0, help = "Start carving at this byte offset")]
        offset: usize,
        #[arg(long, help = "Limit carving to this many bytes from --offset")]
        length: Option<usize>,
        #[arg(
            long,
            help = "Maximum carved size in bytes for formats without a known footer"
        )]
        max_size: Option<usize>,
        #[arg(long, help = "Report sector numbers using this sector size")]
        sector_size: Option<usize>,
        #[arg(
            short = 'Q',
            long,
            help = "Quick mode: first hit per profile per source"
        )]
        quick: bool,
        #[arg(short = 'w', long, help = "Write audit log only; do not extract files")]
        audit_only: bool,
        #[arg(long, help = "Do not recurse when the input is a directory")]
        no_recursive: bool,
        #[arg(long, help = "Allow overwriting existing carved files")]
        overwrite: bool,
        #[arg(long, help = "Report what would be carved without writing files")]
        dry_run: bool,
        #[arg(long, help = "List supported carve types and exit")]
        list_types: bool,
        #[arg(
            short = 'M',
            long,
            help = "Recursively rescan extracted artifacts like binwalk matryoshka mode"
        )]
        matryoshka: bool,
        #[arg(
            long,
            help = "Maximum recursive extraction depth when --matryoshka is enabled"
        )]
        depth: Option<usize>,
    },
    /// Start an interactive decoding workshop
    Workshop { input: Option<String> },
}

#[derive(Subcommand)]
enum ForensicCommands {
    /// Run forensic analysis on a file or directory
    Scan {
        path: String,
        #[arg(long, help = "Do not carve embedded artifacts to disk")]
        no_extract: bool,
    },
    /// Inspect a disk image or volume and optionally focus on a specific filesystem
    Disk {
        path: String,
        #[arg(long, default_value_t = 512, help = "Sector size for partition math")]
        sector_size: usize,
        #[arg(
            long,
            default_value_t = 0,
            help = "Byte offset to the target filesystem volume"
        )]
        offset: usize,
        #[arg(
            long,
            default_value_t = 256,
            help = "Maximum filesystem records to inspect"
        )]
        max_records: usize,
        #[arg(long, help = "Only show deleted filesystem entries")]
        deleted_only: bool,
        #[arg(long, help = "Include directory records in the results")]
        include_directories: bool,
        #[arg(
            long = "extract-data",
            alias = "extract-resident",
            help = "Recover filesystem data streams into this directory"
        )]
        extract_data: Option<String>,
        #[arg(long, help = "Allow overwriting existing recovered files")]
        overwrite: bool,
        #[arg(long, help = "Force NTFS handling instead of auto-detect only")]
        ntfs: bool,
        #[arg(
            long,
            help = "Filesystem to inspect or recover: ntfs, fat, fat12, fat16, fat32, exfat, refs, ext2, ext3, ext4, btrfs, xfs, f2fs, hfs+, apfs, ufs, zfs, jfs, reiserfs, iso9660, udf, nfs, smb, cifs, afs, cephfs"
        )]
        fs: Option<String>,
        #[arg(long, help = "Prefer ext4 handling when available")]
        ext4: bool,
        #[arg(long, help = "Prefer swap handling when available")]
        swap: bool,
        #[arg(long, help = "Prefer Btrfs handling when available")]
        btrfs: bool,
    },
    /// Carve embedded files like a dedicated extractor
    Carve {
        #[arg(required_unless_present_any = ["list_types", "input"])]
        path: Option<String>,
        #[arg(short = 'i', long, help = "Input file or directory to carve")]
        input: Option<String>,
        #[arg(short, long, help = "Output directory for carved files")]
        output: Option<String>,
        #[arg(short = 'c', long, help = "Foremost-style carve profile config file")]
        config: Option<String>,
        #[arg(
            short = 't',
            long,
            value_delimiter = ',',
            help = "Only carve matching extensions or type names (comma-separated)"
        )]
        types: Vec<String>,
        #[arg(short = 'a', long, help = "Include signatures at offset 0")]
        include_root: bool,
        #[arg(long, default_value_t = 1, help = "Minimum carved size in bytes")]
        min_size: usize,
        #[arg(long, default_value_t = 0, help = "Start carving at this byte offset")]
        offset: usize,
        #[arg(long, help = "Limit carving to this many bytes from --offset")]
        length: Option<usize>,
        #[arg(
            long,
            help = "Maximum carved size in bytes for formats without a known footer"
        )]
        max_size: Option<usize>,
        #[arg(long, help = "Report sector numbers using this sector size")]
        sector_size: Option<usize>,
        #[arg(
            short = 'Q',
            long,
            help = "Quick mode: first hit per profile per source"
        )]
        quick: bool,
        #[arg(short = 'w', long, help = "Write audit log only; do not extract files")]
        audit_only: bool,
        #[arg(long, help = "Do not recurse when the input is a directory")]
        no_recursive: bool,
        #[arg(long, help = "Allow overwriting existing carved files")]
        overwrite: bool,
        #[arg(long, help = "Report what would be carved without writing files")]
        dry_run: bool,
        #[arg(long, help = "List supported carve types and exit")]
        list_types: bool,
        #[arg(
            short = 'M',
            long,
            help = "Recursively rescan extracted artifacts like binwalk matryoshka mode"
        )]
        matryoshka: bool,
        #[arg(
            long,
            help = "Maximum recursive extraction depth when --matryoshka is enabled"
        )]
        depth: Option<usize>,
    },
}

fn main() {
    let cli = Cli::parse();
    let context = cli.context.clone();

    // Handle external custom signatures
    if let Some(ref custom_path) = cli.custom_signatures {
        match hashendra::core::patterns::load_external_signatures_from_path(custom_path) {
            Ok(sigs) => {
                let count = sigs.len();
                if count > 0 {
                    safe_println!("[OK] Loaded {} custom signature(s) from {}", count.to_string().green(), custom_path.cyan());
                }
            }
            Err(e) => {
                safe_println!("[FAIL] {}", e.red());
            }
        }
    } else {
        let ext_count = *EXTERNAL_SIGNATURE_COUNT;
        if ext_count > 0 {
            safe_println!("[OK] Loaded {} custom signature(s) from ~/.hashendra/signatures.json", ext_count.to_string().green());
        }
    }

    // List-only flags (no input needed)
    if cli.list_hashes {
        print_hash_algorithms();
        return;
    }
    if cli.list_encodings {
        print_encoding_formats();
        return;
    }
    if cli.list_ciphers {
        print_encryption_ciphers();
        return;
    }

    // Operations that require input
    if let Some(ref input) = cli.input {
        if let Some(algo) = cli.hash {
            handle_hash(input, algo.as_deref());
        } else if let Some(ref cipher) = cli.encrypt {
            handle_encrypt(input, cipher, &cli.key, &cli.cipher_param);
        } else if let Some(ref format) = cli.to {
            handle_encode(input, format);
        } else if cli.deep_decrypt {
            handle_deep_decrypt(input);
        } else if cli.decode {
            handle_decode(input, &context);
        } else if cli.rot {
            handle_rot(input);
        } else if cli.xor {
            handle_xor(input);
        } else {
            analyze_single_input(input, cli.json, cli.verbose, &context);
        }
    } else if let Some(ref file_path) = cli.file {
        analyze_file(file_path, cli.json);
    } else if let Some(command) = cli.command {
        match command {
            Commands::Update => {
                safe_println!("{}", "Checking for signature updates...".blue());
                safe_println!(
                    "{}",
                    "No updates available. You are running the latest version (v0.1.0).".green()
                );
            }
            Commands::Forensic { command } => match command {
                ForensicCommands::Scan { path, no_extract } => {
                    run_forensic_scan(std::path::Path::new(&path), cli.json, !no_extract);
                }
                ForensicCommands::Disk {
                    path,
                    sector_size,
                    offset,
                    max_records,
                    deleted_only,
                    include_directories,
                    extract_data,
                    overwrite,
                    ntfs,
                    fs,
                    ext4,
                    swap,
                    btrfs,
                } => {
                    run_forensic_disk(
                        std::path::Path::new(&path),
                        cli.json,
                        sector_size,
                        offset,
                        max_records,
                        deleted_only,
                        include_directories,
                        extract_data.as_deref(),
                        overwrite,
                        ntfs,
                        fs.as_deref(),
                        ext4,
                        swap,
                        btrfs,
                    );
                }
                ForensicCommands::Carve {
                    path,
                    input,
                    output,
                    config,
                    types,
                    include_root,
                    min_size,
                    offset,
                    length,
                    max_size,
                    sector_size,
                    quick,
                    audit_only,
                    no_recursive,
                    overwrite,
                    dry_run,
                    list_types,
                    matryoshka,
                    depth,
                } => {
                    run_carve(
                        path.as_deref(),
                        input.as_deref(),
                        cli.json,
                        output.as_deref(),
                        config.as_deref(),
                        &types,
                        include_root,
                        min_size,
                        offset,
                        length,
                        max_size,
                        sector_size,
                        quick,
                        audit_only,
                        !no_recursive,
                        overwrite,
                        dry_run,
                        list_types,
                        matryoshka,
                        depth,
                    );
                }
            },
            Commands::Disk { path, sector_size } => {
                run_forensic_disk(
                    std::path::Path::new(&path),
                    cli.json,
                    sector_size,
                    0,
                    256,
                    false,
                    false,
                    None,
                    false,
                    false,
                    None,
                    false,
                    false,
                    false,
                );
            }
            Commands::Ntfs {
                path,
                offset,
                max_records,
                deleted_only,
                include_directories,
                extract_data,
                overwrite,
            } => {
                run_forensic_disk(
                    std::path::Path::new(&path),
                    cli.json,
                    512,
                    offset,
                    max_records,
                    deleted_only,
                    include_directories,
                    extract_data.as_deref(),
                    overwrite,
                    true,
                    None,
                    false,
                    false,
                    false,
                );
            }
            Commands::Carve {
                path,
                input,
                output,
                config,
                types,
                include_root,
                min_size,
                offset,
                length,
                max_size,
                sector_size,
                quick,
                audit_only,
                no_recursive,
                overwrite,
                dry_run,
                list_types,
                matryoshka,
                depth,
            } => {
                run_carve(
                    path.as_deref(),
                    input.as_deref(),
                    cli.json,
                    output.as_deref(),
                    config.as_deref(),
                    &types,
                    include_root,
                    min_size,
                    offset,
                    length,
                    max_size,
                    sector_size,
                    quick,
                    audit_only,
                    !no_recursive,
                    overwrite,
                    dry_run,
                    list_types,
                    matryoshka,
                    depth,
                );
            }
            Commands::Workshop { input } => {
                print_banner();
                run_workshop(input);
            }
        }
    } else {
        // Read from stdin — stream line by line for real-time processing
        let stdin = io::stdin();
        print_banner();
        let mut first = true;
        for line in stdin.lock().lines() {
            match line {
                Ok(input) => {
                    let trimmed = input.trim().to_string();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if first {
                        first = false;
                    } else if !cli.json {
                        // Print separator between inputs
                        safe_println!("{}", "---".cyan());
                    }
                    analyze_single_input(&trimmed, cli.json, cli.verbose, &context);
                }
                Err(e) => {
                    safe_println!("{}", format!("[FAIL] read error: {}", e).red());
                    break;
                }
            }
        }
        if first {
            safe_println!("{}", "No input provided. Use --help for usage.".yellow());
        }
    }
}

fn print_banner() {
    let eagle = r#"
   / \
  / _ \
 | (_) |
  \___/   HashEndra v2.0
"#;

    safe_println!("{}", eagle.cyan());
    safe_println!(
        "{}",
        "------------------------------------------------------------------".cyan()
    );
    safe_println!(
        "{}",
        "          Universal Forensic Decryption & Hashing Engine          ".cyan()
    );
    safe_println!(
        "{}",
        "------------------------------------------------------------------".cyan()
    );
}
fn handle_deep_decrypt(input: &str) {
    let engine = RecursiveEngine::new(10);
    safe_println!(
        "[SCAN] Starting deep recursive unwrapping for: {}",
        input.white().bold()
    );

    let result = engine.explore_paths(input);

    for step in result.steps {
        safe_println!(
            "  [LAYER {}] Detected: {} -> {}",
            step.layer + 1,
            step.decoder.yellow(),
            step.result.green()
        );
    }

    if result.layers_unwrapped > 0 {
        safe_println!(
            "\n[OK] Fully decrypted in {} layers",
            result.layers_unwrapped
        );
        safe_println!(
            "[FINISH] Final Payload: {}",
            result.final_result.cyan().bold()
        );
    } else {
        safe_println!("\n[FAIL] No layers could be automatically unwrapped.");
    }
}

fn handle_decode(input: &str, _context_str: &str) {
    // Delegate to RecursiveEngine for consistency with --deep-decrypt
    let engine = RecursiveEngine::new(10);
    let result = engine.explore_paths(input);

    for step in &result.steps {
        safe_println!(
            "  Layer {}: Decoded {} -> {}",
            step.layer + 1,
            step.decoder.yellow(),
            step.result.green()
        );
    }

    if result.layers_unwrapped > 0 {
        safe_println!(
            "[OK] Decoded {} layers to: {}",
            result.layers_unwrapped,
            result.final_result.cyan().bold()
        );
    } else {
        safe_println!("[FAIL] No automatic decoding layers found.");
    }
}

fn handle_rot(input: &str) {
    use hashendra::core::cryptanalysis::chi_squared_score;
    use hashendra::core::scanner::rot_brute_force;
    safe_println!("[ROT] Brute-forcing ROT for: {}", input);
    let results = rot_brute_force(input);
    let mut scored: Vec<(u8, String, f32)> = results
        .into_iter()
        .map(|(shift, decoded)| (shift, decoded.clone(), chi_squared_score(&decoded)))
        .collect();
    scored.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap());
    for (shift, decoded, chi) in &scored {
        let marker = if *chi < 150.0 { "* " } else { "  " };
        safe_println!("  {}{:02}: {} (chi2={:.1})", marker, shift, decoded, chi);
    }
}

fn handle_xor(input: &str) {
    use hashendra::core::scanner::{decode_hex, xor_crack};
    safe_println!("[XOR] Attempting single-byte XOR crack...");

    // Try as raw ASCII bytes first (the most common use case)
    let raw_results = xor_crack(input.as_bytes());
    if !raw_results.is_empty() {
        safe_println!("  [as raw ASCII bytes]:");
        for (key, decoded, score) in raw_results.iter().take(3) {
            safe_println!("    Key 0x{:02x} (Score {:.2}): {}", key, score, decoded);
        }
        return;
    }

    // Fall back to hex-decoded if input looks like hex and raw didn't work
    if input.len() % 2 == 0 && input.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Some(bytes) = decode_hex(input) {
            let hex_results = xor_crack(&bytes);
            if !hex_results.is_empty() {
                safe_println!("  [as hex-decoded bytes]:");
                for (key, decoded, score) in hex_results.iter().take(3) {
                    safe_println!("    Key 0x{:02x} (Score {:.2}): {}", key, score, decoded);
                }
                return;
            }
        }
    }

    safe_println!("[FAIL] No plaintext found with XOR crack.");
}

const VALID_CONTEXTS: &[&str] = &[
    "generic", "network", "filesystem", "shadow", "database", "sql", "memory", "blockchain",
];

fn analyze_single_input(input: &str, json: bool, verbose: bool, context_str: &str) {
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
        return;
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
                    if let Some(decoded) = decode_base64_url(parts[0]) {
                        if let Ok(text) = String::from_utf8(decoded) {
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                safe_println!("|  header: {}", serde_json::to_string_pretty(&json).unwrap().green());
                            } else {
                                safe_println!("|  header: {} (raw)", text.white());
                            }
                        }
                    }
                    if let Some(decoded) = decode_base64_url(parts[1]) {
                        if let Ok(text) = String::from_utf8(decoded) {
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                safe_println!("|  payload: {}", serde_json::to_string_pretty(&json).unwrap().cyan());
                            } else {
                                safe_println!("|  payload: {} (raw)", text.white());
                            }
                        }
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
}

fn analyze_file(path: &str, json: bool) {
    let file = std::fs::File::open(path).expect("Could not open file");
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
}

fn detect_path_file_type(path: &std::path::Path) -> String {
    hashendra::forensics::filetypes::detect_path_file_type(path)
}

fn print_path_metadata(path: &std::path::Path) {
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

fn preview_strings_from_path(path: &std::path::Path, min_len: usize, limit: usize) {
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

fn run_forensic_scan(path: &std::path::Path, json: bool, extract_artifacts: bool) {
    // Reject non-regular files that would block or cause issues
    if !path.is_dir() {
        match path.metadata() {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    // Resolve symlink before checking
                    match path.canonicalize() {
                        Ok(real) => return run_forensic_scan(&real, json, extract_artifacts),
                        Err(_) => {}
                    }
                }
                if !meta.file_type().is_file() {
                    let msg = format!("not a regular file: {}", path.display());
                    if json {
                        safe_println!("{}", serde_json::json!({"path": path.display().to_string(), "error": msg}).to_string());
                    } else {
                        safe_println!("{}", format!("[FAIL] forensic scan: {}", msg).red());
                    }
                    return;
                }
            }
            Err(e) => {
                let msg = format!("cannot access {}: {}", path.display(), e);
                if json {
                    safe_println!("{}", serde_json::json!({"path": path.display().to_string(), "error": msg}).to_string());
                } else {
                    safe_println!("{}", format!("[FAIL] forensic scan: {}", msg).red());
                }
                return;
            }
        }
    }

    if path.is_dir() {
        if json {
            let report = hashendra::forensics::directory::scan_directory(path, extract_artifacts);
            safe_println!("{}", serde_json::to_string_pretty(&report).unwrap());
            return;
        }

        safe_println!(
            "{}",
            format!(
                "Running recursive forensic scan on directory: {}...",
                path.display()
            )
            .cyan()
        );

        let mut files_scanned = 0usize;
        let mut files_analyzed = 0usize;
        let mut suspicious_files = 0usize;
        let mut total_hits = 0usize;
        let mut total_artifacts = 0usize;
        let mut type_counts = std::collections::BTreeMap::new();
        let walker = walkdir::WalkDir::new(path).into_iter();

        for entry in walker.filter_map(|e| e.ok()) {
            let file_path = entry.path();
            if file_path.is_file() {
                files_scanned += 1;
                let file_type = detect_path_file_type(file_path);
                *type_counts.entry(file_type.clone()).or_insert(0usize) += 1;
                safe_println!(
                    "{}",
                    format!("[FILE] {} | {}", file_path.display(), file_type).blue()
                );

                let mut manager = hashendra::utils::io_manager::FileManager::new();
                if manager
                    .map_file(file_path.to_str().unwrap_or_default())
                    .is_ok()
                {
                    if let Some(report) = manager.build_report(extract_artifacts) {
                        total_hits += report.hits.len();
                        total_artifacts += report.artifacts.len();
                        if !report.hits.is_empty() || !report.artifacts.is_empty() {
                            suspicious_files += 1;
                        }
                    }
                    files_analyzed += 1;
                    manager.scan_binary(extract_artifacts);
                }
            }
        }

        safe_println!(
            "{}",
            format!(
                "[SUMMARY] scanned {} files, analyzed {} readable files, suspicious {}",
                files_scanned, files_analyzed, suspicious_files
            )
            .cyan()
        );
        if !type_counts.is_empty() {
            safe_println!("{}", "[TYPES]".cyan());
            for (kind, count) in type_counts {
                safe_println!("  {} -> {}", kind, count);
            }
        }
        safe_println!("{}", "[EVIDENCE]".cyan());
        safe_println!("  Hits      -> {}", total_hits);
        safe_println!("  Embedded  -> {}", total_artifacts);
    } else {
        let metadata = hashendra::forensics::filetypes::read_path_metadata(path);
        let file_type = detect_path_file_type(path);
        if !json {
            safe_println!(
                "{}",
                format!("Running forensic scan on {}...", path.display()).cyan()
            );
        }

        let mut manager = hashendra::utils::io_manager::FileManager::new();
        if let Err(e) = manager.map_file(path.to_str().unwrap_or_default()) {
            if json {
                let output = serde_json::json!({
                    "path": path.display().to_string(),
                    "error": e.to_string(),
                });
                safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                safe_println!("{}", format!("Error mapping file: {}", e).red());
            }
        } else {
            if json {
                if let Some(report) = manager.build_report(extract_artifacts) {
                    let output = serde_json::json!({
                        "path": path.display().to_string(),
                        "metadata": metadata,
                        "file_type": file_type,
                        "extract_artifacts": extract_artifacts,
                        "report": report,
                    });
                    safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
                }
                return;
            }

            print_path_metadata(path);
            safe_println!("{}", format!("[FILETYPE] {}", file_type).blue());
            manager.scan_binary(extract_artifacts);
            preview_strings_from_path(path, 8, 8);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ForensicFilesystemHint {
    Auto,
    Ntfs,
    Fat32,
    Exfat,
    Refs,
    Ext,
    Ext4,
    Swap,
    Btrfs,
    Xfs,
    F2fs,
    HfsPlus,
    Apfs,
    Ufs,
    Zfs,
    Jfs,
    Reiserfs,
    Iso9660,
    Udf,
    Nfs,
    Smb,
    Cifs,
    Afs,
    Cephfs,
}

fn select_forensic_filesystem_hint(
    ntfs: bool,
    fs: Option<&str>,
    ext4: bool,
    swap: bool,
    btrfs: bool,
) -> Result<ForensicFilesystemHint, &'static str> {
    let mut requested = [
        (ntfs, ForensicFilesystemHint::Ntfs),
        (ext4, ForensicFilesystemHint::Ext4),
        (swap, ForensicFilesystemHint::Swap),
        (btrfs, ForensicFilesystemHint::Btrfs),
    ]
    .into_iter()
    .filter_map(|(enabled, hint)| enabled.then_some(hint))
    .collect::<Vec<_>>();

    if let Some(fs) = fs {
        requested.push(match fs.trim().to_ascii_lowercase().as_str() {
            "ntfs" => ForensicFilesystemHint::Ntfs,
            "fat" | "fat12" | "fat16" | "fat32" => ForensicFilesystemHint::Fat32,
            "exfat" => ForensicFilesystemHint::Exfat,
            "refs" => ForensicFilesystemHint::Refs,
            "ext" | "ext2" | "ext3" => ForensicFilesystemHint::Ext,
            "ext4" => ForensicFilesystemHint::Ext4,
            "swap" => ForensicFilesystemHint::Swap,
            "btrfs" => ForensicFilesystemHint::Btrfs,
            "xfs" => ForensicFilesystemHint::Xfs,
            "f2fs" => ForensicFilesystemHint::F2fs,
            "hfs+" | "hfsplus" => ForensicFilesystemHint::HfsPlus,
            "apfs" => ForensicFilesystemHint::Apfs,
            "ufs" => ForensicFilesystemHint::Ufs,
            "zfs" => ForensicFilesystemHint::Zfs,
            "jfs" => ForensicFilesystemHint::Jfs,
            "reiserfs" => ForensicFilesystemHint::Reiserfs,
            "iso9660" | "iso" => ForensicFilesystemHint::Iso9660,
            "udf" => ForensicFilesystemHint::Udf,
            "nfs" => ForensicFilesystemHint::Nfs,
            "smb" => ForensicFilesystemHint::Smb,
            "cifs" => ForensicFilesystemHint::Cifs,
            "afs" => ForensicFilesystemHint::Afs,
            "cephfs" => ForensicFilesystemHint::Cephfs,
            _ => return Err("unknown filesystem name"),
        });
    }

    match requested.as_slice() {
        [] => Ok(ForensicFilesystemHint::Auto),
        [hint] => Ok(*hint),
        _ => Err("pick only one filesystem hint at a time"),
    }
}

fn detect_disk_partition_offset(
    path: &std::path::Path,
    sector_size: usize,
    target_kind: &str,
) -> Result<Option<usize>, String> {
    let report = hashendra::forensics::disk::inspect_disk_image(path, sector_size)
        .map_err(|error| error.to_string())?;
    if report
        .standalone_filesystem
        .as_ref()
        .is_some_and(|fs| fs.kind.eq_ignore_ascii_case(target_kind))
    {
        return Ok(Some(0));
    }

    let matches = report
        .partitions
        .iter()
        .filter(|partition| {
            partition
                .filesystem
                .as_ref()
                .is_some_and(|fs| fs.kind.eq_ignore_ascii_case(target_kind))
        })
        .map(|partition| partition.start_offset)
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] => Ok(None),
        [offset] => Ok(usize::try_from(*offset).ok()),
        _ => Err(format!(
            "multiple {} partitions were detected; specify --offset explicitly",
            target_kind
        )),
    }
}

fn detect_disk_partition_offset_any(
    path: &std::path::Path,
    sector_size: usize,
    target_kinds: &[&str],
) -> Result<Option<usize>, String> {
    let report = hashendra::forensics::disk::inspect_disk_image(path, sector_size)
        .map_err(|error| error.to_string())?;
    if report.standalone_filesystem.as_ref().is_some_and(|fs| {
        target_kinds
            .iter()
            .any(|target| fs.kind.eq_ignore_ascii_case(target))
    }) {
        return Ok(Some(0));
    }

    let matches = report
        .partitions
        .iter()
        .filter(|partition| {
            partition.filesystem.as_ref().is_some_and(|fs| {
                target_kinds
                    .iter()
                    .any(|target| fs.kind.eq_ignore_ascii_case(target))
            })
        })
        .map(|partition| partition.start_offset)
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] => Ok(None),
        [offset] => Ok(usize::try_from(*offset).ok()),
        _ => Err(format!(
            "multiple matching partitions were detected for {}; specify --offset explicitly",
            target_kinds.join("/")
        )),
    }
}

fn filesystem_hint_name(hint: ForensicFilesystemHint) -> &'static str {
    match hint {
        ForensicFilesystemHint::Auto => "auto",
        ForensicFilesystemHint::Ntfs => "ntfs",
        ForensicFilesystemHint::Fat32 => "fat",
        ForensicFilesystemHint::Exfat => "exfat",
        ForensicFilesystemHint::Refs => "refs",
        ForensicFilesystemHint::Ext => "ext",
        ForensicFilesystemHint::Ext4 => "ext4",
        ForensicFilesystemHint::Swap => "swap",
        ForensicFilesystemHint::Btrfs => "btrfs",
        ForensicFilesystemHint::Xfs => "xfs",
        ForensicFilesystemHint::F2fs => "f2fs",
        ForensicFilesystemHint::HfsPlus => "hfs+",
        ForensicFilesystemHint::Apfs => "apfs",
        ForensicFilesystemHint::Ufs => "ufs",
        ForensicFilesystemHint::Zfs => "zfs",
        ForensicFilesystemHint::Jfs => "jfs",
        ForensicFilesystemHint::Reiserfs => "reiserfs",
        ForensicFilesystemHint::Iso9660 => "iso9660",
        ForensicFilesystemHint::Udf => "udf",
        ForensicFilesystemHint::Nfs => "nfs",
        ForensicFilesystemHint::Smb => "smb",
        ForensicFilesystemHint::Cifs => "cifs",
        ForensicFilesystemHint::Afs => "afs",
        ForensicFilesystemHint::Cephfs => "cephfs",
    }
}

fn filesystem_hint_target_kinds(hint: ForensicFilesystemHint) -> &'static [&'static str] {
    match hint {
        ForensicFilesystemHint::Ntfs => &["NTFS"],
        ForensicFilesystemHint::Fat32 => &["FAT32", "FAT16", "FAT12"],
        ForensicFilesystemHint::Exfat => &["exFAT"],
        ForensicFilesystemHint::Refs => &["ReFS"],
        ForensicFilesystemHint::Ext | ForensicFilesystemHint::Ext4 => &["ext4", "ext3", "ext2"],
        ForensicFilesystemHint::Swap => &["swap"],
        ForensicFilesystemHint::Btrfs => &["Btrfs"],
        ForensicFilesystemHint::Xfs => &["XFS"],
        ForensicFilesystemHint::F2fs => &["F2FS"],
        ForensicFilesystemHint::HfsPlus => &["HFS+"],
        ForensicFilesystemHint::Apfs => &["APFS"],
        ForensicFilesystemHint::Ufs => &["UFS"],
        ForensicFilesystemHint::Zfs => &["ZFS"],
        ForensicFilesystemHint::Jfs => &["JFS"],
        ForensicFilesystemHint::Reiserfs => &["ReiserFS"],
        ForensicFilesystemHint::Iso9660 => &["ISO9660"],
        ForensicFilesystemHint::Udf => &["UDF"],
        _ => &[],
    }
}

fn is_network_filesystem_hint(hint: ForensicFilesystemHint) -> bool {
    matches!(
        hint,
        ForensicFilesystemHint::Nfs
            | ForensicFilesystemHint::Smb
            | ForensicFilesystemHint::Cifs
            | ForensicFilesystemHint::Afs
            | ForensicFilesystemHint::Cephfs
    )
}

fn run_forensic_disk(
    path: &std::path::Path,
    json: bool,
    sector_size: usize,
    offset: usize,
    max_records: usize,
    deleted_only: bool,
    include_directories: bool,
    extract_data: Option<&str>,
    overwrite: bool,
    ntfs: bool,
    fs: Option<&str>,
    ext4: bool,
    swap: bool,
    btrfs: bool,
) {
    let hint = match select_forensic_filesystem_hint(ntfs, fs, ext4, swap, btrfs) {
        Ok(hint) => hint,
        Err(error) => {
            if json {
                let output = serde_json::json!({
                    "path": path.display().to_string(),
                    "error": error,
                });
                safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                safe_println!("{}", format!("[FAIL] forensic disk: {}", error).red());
            }
            return;
        }
    };

    match hint {
        ForensicFilesystemHint::Auto => run_disk_inspect(path, json, sector_size),
        ForensicFilesystemHint::Ntfs => {
            let selected_offset = if offset != 0 {
                offset
            } else {
                match detect_disk_partition_offset(path, sector_size, "NTFS") {
                    Ok(Some(detected)) => detected,
                    Ok(None) => 0,
                    Err(error) => {
                        if json {
                            let output = serde_json::json!({
                                "path": path.display().to_string(),
                                "error": error,
                            });
                            safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
                        } else {
                            safe_println!("{}", format!("[FAIL] forensic disk: {}", error).red());
                            run_disk_inspect(path, false, sector_size);
                        }
                        return;
                    }
                }
            };
            run_ntfs_inspect(
                path,
                json,
                selected_offset,
                max_records,
                deleted_only,
                include_directories,
                extract_data,
                overwrite,
            );
        }
        ForensicFilesystemHint::Fat32 => {
            let selected_offset = if offset != 0 {
                offset
            } else {
                match detect_disk_partition_offset_any(
                    path,
                    sector_size,
                    &["FAT32", "FAT16", "FAT12"],
                ) {
                    Ok(Some(detected)) => detected,
                    Ok(None) => 0,
                    Err(error) => {
                        if json {
                            let output = serde_json::json!({
                                "path": path.display().to_string(),
                                "error": error,
                            });
                            safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
                        } else {
                            safe_println!("{}", format!("[FAIL] forensic disk: {}", error).red());
                            run_disk_inspect(path, false, sector_size);
                        }
                        return;
                    }
                }
            };
            run_fat_inspect(
                path,
                json,
                selected_offset,
                max_records,
                deleted_only,
                include_directories,
                extract_data,
                overwrite,
            );
        }
        ForensicFilesystemHint::Ext | ForensicFilesystemHint::Ext4 => {
            let selected_offset = if offset != 0 {
                offset
            } else {
                match detect_disk_partition_offset_any(path, sector_size, &["ext4", "ext3", "ext2"])
                {
                    Ok(Some(detected)) => detected,
                    Ok(None) => 0,
                    Err(error) => {
                        if json {
                            let output = serde_json::json!({
                                "path": path.display().to_string(),
                                "error": error,
                            });
                            safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
                        } else {
                            safe_println!("{}", format!("[FAIL] forensic disk: {}", error).red());
                            run_disk_inspect(path, false, sector_size);
                        }
                        return;
                    }
                }
            };
            run_ext_inspect(
                path,
                json,
                selected_offset,
                max_records,
                deleted_only,
                include_directories,
                extract_data,
                overwrite,
            );
        }
        other => {
            let hint_name = filesystem_hint_name(other);
            if is_network_filesystem_hint(other) {
                let note = format!(
                    "{} is a network or distributed filesystem, not a raw disk-image format; inspect share metadata, configs, mounts, or captures instead of `forensic disk`",
                    hint_name
                );
                if json {
                    let output = serde_json::json!({
                        "path": path.display().to_string(),
                        "filesystem_hint": hint_name,
                        "note": note,
                    });
                    safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    safe_println!("{}", format!("[NOTE] {}", note).yellow());
                }
                return;
            }

            let target_kinds = filesystem_hint_target_kinds(other);
            let selected_offset = if offset != 0 {
                offset
            } else if target_kinds.is_empty() {
                0
            } else {
                match detect_disk_partition_offset_any(path, sector_size, target_kinds) {
                    Ok(Some(detected)) => detected,
                    Ok(None) => 0,
                    Err(error) => {
                        if json {
                            let output = serde_json::json!({
                                "path": path.display().to_string(),
                                "error": error,
                            });
                            safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
                        } else {
                            safe_println!("{}", format!("[FAIL] forensic disk: {}", error).red());
                            run_disk_inspect(path, false, sector_size);
                        }
                        return;
                    }
                }
            };

            match hashendra::forensics::disk::inspect_filesystem_image(
                path,
                selected_offset,
                sector_size,
            ) {
                Ok(Some(filesystem)) => {
                    if json {
                        let output = serde_json::json!({
                            "path": path.display().to_string(),
                            "mode": "forensic disk",
                            "filesystem_hint": hint_name,
                            "offset": selected_offset,
                            "filesystem": filesystem,
                            "note": format!("deep {} recovery is not implemented yet; returning structured filesystem inspection", hint_name),
                        });
                        safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    } else {
                        safe_println!(
                            "{}",
                            format!("[DISK] {} | offset 0x{:X}", path.display(), selected_offset)
                                .cyan()
                        );
                        hashendra::forensics::disk::print_filesystem(&filesystem, "  ");
                        safe_println!(
                            "{}",
                            format!(
                                "[NOTE] deep {} recovery is not implemented yet; showing structured filesystem inspection",
                                hint_name
                            )
                            .yellow()
                        );
                    }
                }
                Ok(None) => {
                    if json {
                        let output = serde_json::json!({
                            "path": path.display().to_string(),
                            "filesystem_hint": hint_name,
                            "offset": selected_offset,
                            "error": "requested filesystem signature was not found at the selected offset",
                        });
                        safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    } else {
                        safe_println!(
                            "{}",
                            format!(
                                "[FAIL] forensic disk: {} signature was not found at offset 0x{:X}",
                                hint_name, selected_offset
                            )
                            .red()
                        );
                    }
                }
                Err(error) => {
                    if json {
                        let output = serde_json::json!({
                            "path": path.display().to_string(),
                            "filesystem_hint": hint_name,
                            "offset": selected_offset,
                            "error": error.to_string(),
                        });
                        safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    } else {
                        safe_println!("{}", format!("[FAIL] forensic disk: {}", error).red());
                    }
                }
            }
        }
    }
}

fn run_disk_inspect(path: &std::path::Path, json: bool, sector_size: usize) {
    match hashendra::forensics::disk::inspect_disk_image(path, sector_size) {
        Ok(report) => {
            if json {
                safe_println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                hashendra::forensics::disk::print_disk_layout(&report);
            }
        }
        Err(error) => {
            if json {
                let output = serde_json::json!({
                    "path": path.display().to_string(),
                    "error": error.to_string(),
                });
                safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                safe_println!("{}", format!("[FAIL] disk: {}", error).red());
            }
        }
    }
}

fn run_ntfs_inspect(
    path: &std::path::Path,
    json: bool,
    offset: usize,
    max_records: usize,
    deleted_only: bool,
    include_directories: bool,
    extract_data: Option<&str>,
    overwrite: bool,
) {
    let options = hashendra::forensics::ntfs::NtfsOptions {
        volume_offset: offset,
        max_records,
        deleted_only,
        include_directories,
        extract_data_to: extract_data.map(std::path::PathBuf::from),
        overwrite,
    };

    match hashendra::forensics::ntfs::inspect_ntfs_image(path, &options) {
        Ok(report) => {
            if json {
                safe_println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                hashendra::forensics::ntfs::print_ntfs_report(&report);
            }
        }
        Err(error) => {
            if json {
                let output = serde_json::json!({
                    "path": path.display().to_string(),
                    "offset": offset,
                    "error": error.to_string(),
                });
                safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                safe_println!("{}", format!("[FAIL] ntfs: {}", error).red());
            }
        }
    }
}

fn run_ext_inspect(
    path: &std::path::Path,
    json: bool,
    offset: usize,
    max_inodes: usize,
    deleted_only: bool,
    include_directories: bool,
    extract_data: Option<&str>,
    overwrite: bool,
) {
    let options = hashendra::forensics::ext::ExtOptions {
        volume_offset: offset,
        max_inodes,
        deleted_only,
        include_directories,
        extract_data_to: extract_data.map(std::path::PathBuf::from),
        overwrite,
    };

    match hashendra::forensics::ext::inspect_ext_image(path, &options) {
        Ok(report) => {
            if json {
                safe_println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                hashendra::forensics::ext::print_ext_report(&report);
            }
        }
        Err(error) => {
            if json {
                let output = serde_json::json!({
                    "path": path.display().to_string(),
                    "offset": offset,
                    "error": error.to_string(),
                });
                safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                safe_println!("{}", format!("[FAIL] ext: {}", error).red());
            }
        }
    }
}

fn run_fat_inspect(
    path: &std::path::Path,
    json: bool,
    offset: usize,
    max_entries: usize,
    deleted_only: bool,
    include_directories: bool,
    extract_data: Option<&str>,
    overwrite: bool,
) {
    let options = hashendra::forensics::fat::FatOptions {
        volume_offset: offset,
        max_entries,
        deleted_only,
        include_directories,
        extract_data_to: extract_data.map(std::path::PathBuf::from),
        overwrite,
    };

    match hashendra::forensics::fat::inspect_fat_image(path, &options) {
        Ok(report) => {
            if json {
                safe_println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                hashendra::forensics::fat::print_fat_report(&report);
            }
        }
        Err(error) => {
            if json {
                let output = serde_json::json!({
                    "path": path.display().to_string(),
                    "offset": offset,
                    "error": error.to_string(),
                });
                safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                safe_println!("{}", format!("[FAIL] fat: {}", error).red());
            }
        }
    }
}

fn run_carve(
    path: Option<&str>,
    input: Option<&str>,
    json: bool,
    output: Option<&str>,
    config: Option<&str>,
    types: &[String],
    include_root: bool,
    min_size: usize,
    offset: usize,
    length: Option<usize>,
    max_size: Option<usize>,
    sector_size: Option<usize>,
    quick: bool,
    audit_only: bool,
    recursive: bool,
    overwrite: bool,
    dry_run: bool,
    list_types: bool,
    matryoshka: bool,
    depth: Option<usize>,
) {
    let config_profiles = config
        .map(std::path::Path::new)
        .map(hashendra::forensics::carve::load_profiles_from_config)
        .transpose();

    let config_profiles = match config_profiles {
        Ok(profiles) => profiles.unwrap_or_default(),
        Err(error) => {
            if json {
                let output = serde_json::json!({
                    "config": config,
                    "error": error.to_string(),
                });
                safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                safe_println!("{}", format!("[FAIL] config: {}", error).red());
            }
            return;
        }
    };

    if list_types {
        let supported =
            hashendra::forensics::carve::supported_carve_types_with_profiles(&config_profiles);
        if json {
            safe_println!("{}", serde_json::to_string_pretty(&supported).unwrap());
        } else {
            safe_println!("{}", "[CARVE TYPES]".cyan());
            for entry in supported {
                safe_println!(
                    "  {:<8} {:<10} {}",
                    entry.extension,
                    entry.source,
                    entry.names.join(", ")
                );
            }
        }
        return;
    }

    let path = input.or(path);
    let Some(path) = path else {
        safe_println!(
            "{}",
            "[FAIL] carve requires a path or --input unless --list-types is used".red()
        );
        return;
    };

    let carve_path = std::path::Path::new(path);
    let options = hashendra::forensics::carve::CarveOptions {
        output_dir: output.map(std::path::PathBuf::from),
        include_root,
        type_filters: types
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect(),
        min_size,
        scan_offset: offset,
        scan_length: length,
        max_size,
        sector_size,
        overwrite,
        write_files: !(dry_run || audit_only),
        recursive,
        quick,
        write_audit: audit_only || !dry_run,
        profiles: config_profiles,
        deduplicate: true,
        recursive_extract_depth: if matryoshka { depth.unwrap_or(8) } else { 0 },
        extraction_byte_quota: 1024 * 1024 * 1024, // 1 GB safety limit
    };

    match hashendra::forensics::carve::carve_path(
        carve_path,
        config.map(std::path::Path::new),
        &options,
    ) {
        Ok(report) => {
            if json {
                safe_println!("{}", serde_json::to_string_pretty(&report).unwrap());
                return;
            }

            safe_println!(
                "{}",
                format!(
                    "Carving {} from {}...",
                    if dry_run {
                        "preview"
                    } else if audit_only {
                        "audit"
                    } else {
                        "artifacts"
                    },
                    carve_path.display()
                )
                .cyan()
            );
            if let Some(output_dir) = &report.output_dir {
                safe_println!("  [OUTDIR] {}", output_dir.green());
            }
            if let Some(config_path) = &report.config_path {
                safe_println!("  [CONFIG] {}", config_path.cyan());
            }
            safe_println!("  [OFFSET] {}", report.scan_offset);
            if let Some(scan_length) = report.scan_length {
                safe_println!("  [LENGTH] {}", scan_length);
            }
            if let Some(sector_size) = report.sector_size {
                safe_println!("  [SECTOR] {}", sector_size);
            }
            safe_println!(
                "  [SUMMARY] scanned {} file(s), matched {}, wrote {} artifact(s), {} bytes",
                report.files_scanned,
                report.matched,
                report.written,
                report.bytes_written
            );
            if report.containers_expanded > 0 || report.container_members_written > 0 {
                safe_println!(
                    "  [CONTAINERS] expanded {}, wrote {} member file(s)",
                    report.containers_expanded,
                    report.container_members_written
                );
            }
            if !report.by_type.is_empty() {
                safe_println!("{}", "  [TYPES]".cyan());
                for (extension, count) in &report.by_type {
                    safe_println!("    {} -> {}", extension, count);
                }
            }
            for source in report
                .sources
                .iter()
                .filter(|source| !source.artifacts.is_empty())
            {
                safe_println!("\n[SOURCE] {}", source.source.yellow());
                for artifact in &source.artifacts {
                    let output_path = artifact.extracted_path.as_deref().unwrap_or(if dry_run {
                        "dry-run / not written"
                    } else if audit_only {
                        "audit-only / not written"
                    } else {
                        "not written"
                    });
                    if let Some(sector) = artifact.sector {
                        safe_println!(
                            "  0x{:08x} sector {:<8} {:<7} {:>8} bytes -> {}",
                            artifact.offset,
                            sector,
                            artifact.extension,
                            artifact.length.unwrap_or(0),
                            output_path
                        );
                    } else {
                        safe_println!(
                            "  0x{:08x} {:<7} {:>8} bytes -> {}",
                            artifact.offset,
                            artifact.extension,
                            artifact.length.unwrap_or(0),
                            output_path
                        );
                    }
                }
            }
            if !report.notes.is_empty() {
                safe_println!("\n[NOTES]");
                for note in &report.notes {
                    safe_println!("  {}", note);
                }
            }
            if let Some(audit_path) = &report.audit_path {
                safe_println!("\n[AUDIT] {}", audit_path.cyan());
            }
        }
        Err(error) => {
            if json {
                let output = serde_json::json!({
                    "input": carve_path.display().to_string(),
                    "error": error.to_string(),
                });
                safe_println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                safe_println!("{}", format!("[FAIL] carve: {}", error).red());
            }
        }
    }
}

fn workshop_set_current(
    label: &str,
    next: String,
    current: &mut String,
    history: &mut Vec<String>,
) {
    *current = next;
    history.push(current.clone());
    safe_println!("  [OK] {}: {}", label, current.green());
}

fn workshop_decode_bytes(
    label: &str,
    decoded: Option<Vec<u8>>,
    current: &mut String,
    history: &mut Vec<String>,
) {
    match decoded {
        Some(bytes) => match String::from_utf8(bytes) {
            Ok(text) => workshop_set_current("Decoded", text, current, history),
            Err(_) => safe_println!("  [FAIL] {} result is not valid UTF-8.", label),
        },
        None => safe_println!("  [FAIL] Not valid {}.", label),
    }
}

fn workshop_decode_text(
    label: &str,
    decoded: Option<String>,
    current: &mut String,
    history: &mut Vec<String>,
) {
    match decoded {
        Some(text) => workshop_set_current("Decoded", text, current, history),
        None => safe_println!("  [FAIL] Not valid {}.", label),
    }
}

fn apply_rot(text: &str, shift: u8) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                (((c as u8 - base) + (26 - (shift % 26))) % 26 + base) as char
            } else {
                c
            }
        })
        .collect()
}

fn run_workshop(initial_input: Option<String>) {
    let mut current = initial_input.unwrap_or_default();
    let mut history: Vec<String> = vec![current.clone()];
    let mut context = "generic".to_string();
    let mut current_path: Option<String> = None;

    // Banner already printed by caller
    safe_println!(
        "{}",
        "      Type /help for commands, /exit to quit, or raw text to set.  ".cyan()
    );
    safe_println!(
        "{}",
        "------------------------------------------------------------------".cyan()
    );

    loop {
        safe_print!("{}", "hashendra> ".bright_white().bold());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }
        let input = input.trim();

        if input.is_empty() {
            continue;
        }
        if input == "/exit" || input == "/quit" {
            break;
        }

        if input.starts_with('/') {
            let parts: Vec<&str> = input.split_whitespace().collect();
            match parts[0] {
                "/help" => {
                    safe_println!("  /set <text>      - Set current working text");
                    safe_println!("  /load <path>     - Load a file into the workshop buffer");
                    safe_println!("  /forensic <path> - Run forensic scan on a file or directory");
                    safe_println!(
                        "  /filetype [path] - Identify file type for a path or last loaded file"
                    );
                    safe_println!(
                        "  /meta [path]     - Show metadata for a path or last loaded file"
                    );
                    safe_println!(
                        "  /strings [n]     - Extract printable strings from the loaded file"
                    );
                    safe_println!(
                        "  /context <ctx>   - Set analysis context (generic, filesystem, memory, etc.)"
                    );
                    safe_println!(
                        "  /analyze         - Run detection on current text with the active context"
                    );
                    safe_println!("  /base64          - Decode current as Base64");
                    safe_println!("  /hex             - Decode current as Hex");
                    safe_println!("  /base32          - Decode current as Base32");
                    safe_println!("  /base58          - Decode current as Base58");
                    safe_println!("  /binary          - Decode current as Binary / 0b bytes");
                    safe_println!("  /octal           - Decode current as Octal bytes");
                    safe_println!("  /ascii85         - Decode current as Adobe Ascii85");
                    safe_println!("  /qp              - Decode current as Quoted-Printable");
                    safe_println!("  /html            - Decode current as HTML entities");
                    safe_println!("  /morse           - Decode current as Morse code");
                    safe_println!("  /url             - Decode current as URL");
                    safe_println!("  /rot <n>         - Apply a Caesar/ROT shift");
                    safe_println!("  /rot13           - Apply ROT13 to current");
                    safe_println!("  /xor <key>       - XOR current with key (string)");
                    safe_println!("  /deep            - Run deep auto-unwrapper");
                    safe_println!("  /status          - Show current state");
                    safe_println!("  /history         - Show history stack");
                    safe_println!("  /undo            - Revert to previous state");
                    safe_println!("  /exit            - Exit workshop");
                }
                "/set" => {
                    if parts.len() > 1 {
                        current = parts[1..].join(" ");
                        history.push(current.clone());
                        safe_println!("  [OK] Current text set.");
                    }
                }
                "/load" => {
                    if parts.len() > 1 {
                        let path = std::path::Path::new(parts[1]);
                        match std::fs::read(path) {
                            Ok(bytes) => {
                                let is_binary = !bytes.is_empty()
                                    && bytes.iter().any(|&b| b == 0x00)
                                    && String::from_utf8(bytes.clone()).is_err();
                                current_path = Some(path.display().to_string());
                                if is_binary {
                                    let preview_len = bytes.len().min(64);
                                    let hex_preview: String = bytes[..preview_len]
                                        .iter()
                                        .map(|b| format!("{:02x}", b))
                                        .collect::<Vec<_>>()
                                        .join(" ");
                                    safe_println!(
                                        "  [WARN] Binary file loaded — decode commands may produce garbage"
                                    );
                                    safe_println!("  [HEX]  {}...", hex_preview.cyan());
                                }
                                current = String::from_utf8_lossy(&bytes).to_string();
                                history.push(current.clone());
                                safe_println!(
                                    "  [OK] Loaded {} bytes from {}",
                                    bytes.len(),
                                    path.display()
                                );
                                safe_println!("  [TYPE] {}", detect_path_file_type(path).cyan());
                            }
                            Err(e) => safe_println!("  [FAIL] Could not load file: {}", e),
                        }
                    } else {
                        safe_println!("  [FAIL] Usage: /load <path>");
                    }
                }
                "/forensic" => {
                    if parts.len() > 1 {
                        let path = std::path::Path::new(parts[1]);
                        current_path = Some(path.display().to_string());
                        run_forensic_scan(path, false, true);
                    } else {
                        safe_println!("  [FAIL] Usage: /forensic <path>");
                    }
                }
                "/filetype" => {
                    let target = if parts.len() > 1 {
                        Some(parts[1].to_string())
                    } else {
                        current_path.clone()
                    };

                    if let Some(path) = target {
                        safe_println!(
                            "  [TYPE] {} -> {}",
                            path.yellow(),
                            detect_path_file_type(std::path::Path::new(&path)).cyan()
                        );
                    } else {
                        safe_println!("  [FAIL] Usage: /filetype <path>");
                    }
                }
                "/meta" => {
                    let target = if parts.len() > 1 {
                        Some(parts[1].to_string())
                    } else {
                        current_path.clone()
                    };

                    if let Some(path) = target {
                        print_path_metadata(std::path::Path::new(&path));
                    } else {
                        safe_println!("  [FAIL] Usage: /meta <path>");
                    }
                }
                "/strings" => {
                    let min_len = parts
                        .get(1)
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(8);

                    if let Some(path) = &current_path {
                        preview_strings_from_path(std::path::Path::new(path), min_len, 20);
                    } else {
                        safe_println!("  [FAIL] Load a file first with /load <path>.");
                    }
                }
                "/context" => {
                    if parts.len() > 1 {
                        let next = parts[1].to_lowercase();
                        let valid = [
                            "generic",
                            "network",
                            "filesystem",
                            "database",
                            "memory",
                            "blockchain",
                        ];
                        if valid.contains(&next.as_str()) {
                            context = next;
                            safe_println!("  [OK] Context set to {}", context.green());
                        } else {
                            safe_println!("  [FAIL] Invalid context.");
                        }
                    } else {
                        safe_println!("  [OK] Current context: {}", context.yellow());
                    }
                }
                "/analyze" | "/detect" => {
                    safe_println!(
                        "  [ANALYSIS] scanning [{}]: {}",
                        context.cyan(),
                        current.yellow()
                    );
                    analyze_single_input(&current, false, false, &context);
                }
                "/base64" => {
                    use hashendra::core::scanner::decode_base64;
                    workshop_decode_bytes(
                        "Base64",
                        decode_base64(&current),
                        &mut current,
                        &mut history,
                    );
                }
                "/hex" => {
                    use hashendra::core::scanner::decode_hex;
                    workshop_decode_bytes("Hex", decode_hex(&current), &mut current, &mut history);
                }
                "/base32" => {
                    use hashendra::core::scanner::decode_base32;
                    workshop_decode_bytes(
                        "Base32",
                        decode_base32(&current),
                        &mut current,
                        &mut history,
                    );
                }
                "/base58" => {
                    use hashendra::core::scanner::decode_base58;
                    workshop_decode_bytes(
                        "Base58",
                        decode_base58(&current),
                        &mut current,
                        &mut history,
                    );
                }
                "/binary" => {
                    use hashendra::core::scanner::decode_binary;
                    workshop_decode_bytes(
                        "Binary",
                        decode_binary(&current),
                        &mut current,
                        &mut history,
                    );
                }
                "/octal" => {
                    use hashendra::core::scanner::decode_octal;
                    workshop_decode_bytes(
                        "Octal",
                        decode_octal(&current),
                        &mut current,
                        &mut history,
                    );
                }
                "/ascii85" => {
                    use hashendra::core::scanner::decode_ascii85;
                    workshop_decode_bytes(
                        "Ascii85",
                        decode_ascii85(&current),
                        &mut current,
                        &mut history,
                    );
                }
                "/qp" => {
                    use hashendra::core::scanner::decode_quoted_printable;
                    workshop_decode_bytes(
                        "Quoted-Printable",
                        decode_quoted_printable(&current),
                        &mut current,
                        &mut history,
                    );
                }
                "/html" => {
                    use hashendra::core::scanner::decode_html_entities;
                    workshop_decode_text(
                        "HTML Entities",
                        decode_html_entities(&current),
                        &mut current,
                        &mut history,
                    );
                }
                "/morse" => {
                    use hashendra::core::scanner::decode_morse;
                    workshop_decode_text(
                        "Morse",
                        decode_morse(&current),
                        &mut current,
                        &mut history,
                    );
                }
                "/url" => {
                    use hashendra::core::scanner::decode_url;
                    workshop_decode_text("URL", decode_url(&current), &mut current, &mut history);
                }
                "/rot" => {
                    if parts.len() > 1 {
                        if let Ok(shift) = parts[1].parse::<u8>() {
                            workshop_set_current(
                                "Applied ROT",
                                apply_rot(&current, shift),
                                &mut current,
                                &mut history,
                            );
                        } else {
                            safe_println!("  [FAIL] Usage: /rot <0-25>");
                        }
                    } else {
                        safe_println!("  [FAIL] Usage: /rot <0-25>");
                    }
                }
                "/rot13" => {
                    workshop_set_current(
                        "Applied ROT13",
                        apply_rot(&current, 13),
                        &mut current,
                        &mut history,
                    );
                }
                "/xor" => {
                    if parts.len() > 1 {
                        let key = parts[1].as_bytes();
                        let current_bytes = current.as_bytes();
                        let xored: Vec<u8> = current_bytes
                            .iter()
                            .enumerate()
                            .map(|(i, &b)| b ^ key[i % key.len()])
                            .collect();
                        current = String::from_utf8_lossy(&xored).to_string();
                        history.push(current.clone());
                        safe_println!("  [OK] Applied XOR: {}", current.green());
                    } else {
                        safe_println!("  [FAIL] Usage: /xor <key>");
                    }
                }
                "/deep" => {
                    handle_deep_decrypt(&current);
                }
                "/status" => {
                    safe_println!("  Current: {}", current.yellow());
                    safe_println!("  Context: {}", context.cyan());
                    if let Some(path) = &current_path {
                        safe_println!("  Path: {}", path.green());
                        safe_println!(
                            "  Filetype: {}",
                            detect_path_file_type(std::path::Path::new(path)).cyan()
                        );
                    }
                    safe_println!("  Length: {}", current.len());
                    safe_println!("  History depth: {}", history.len());
                }
                "/history" => {
                    for (i, h) in history.iter().enumerate() {
                        safe_println!("  {}: {}", i, h);
                    }
                }
                "/undo" => {
                    if history.len() > 1 {
                        history.pop();
                        current = history.last().unwrap().clone();
                        safe_println!("  [OK] Undone. Current: {}", current.yellow());
                    } else {
                        safe_println!("  [FAIL] Nothing to undo.");
                    }
                }
                _ => {
                    safe_println!("  [FAIL] Unknown command. Type /help.");
                }
            }
        } else {
            current = input.to_string();
            history.push(current.clone());
            safe_println!("  [OK] Current text set to input.");
        }
    }
}

// ──────────────────────────────────────────
// New operation handlers: hash, encode, encrypt
// ──────────────────────────────────────────

fn print_hash_algorithms() {
    safe_println!("{}", "Supported hash algorithms:".blue().bold());
    for algo in HASH_ALGORITHMS {
        safe_println!("  - {}", algo);
    }
}

fn print_encoding_formats() {
    safe_println!("{}", "Supported encoding formats:".blue().bold());
    for fmt in ENCODING_FORMATS {
        safe_println!("  - {}", fmt);
    }
}

fn print_encryption_ciphers() {
    safe_println!("{}", "Supported encryption ciphers:".blue().bold());
    for cipher in &["caesar", "vigenere", "affine", "rail-fence", "xor", "columnar", "atbash"] {
        safe_println!("  - {}", cipher);
    }
}

fn handle_hash(input: &str, algorithm: Option<&str>) {
    let algos: Vec<HashAlgorithm> = if let Some(name) = algorithm {
        match HashAlgorithm::from_name(name) {
            Some(a) => vec![a],
            None => {
                safe_println!(
                    "{} Unknown hash algorithm '{}'. Use --list-hashes to see supported algorithms.",
                    "[ERROR]".red().bold(),
                    name
                );
                return;
            }
        }
    } else {
        // Run all algorithms
        vec![
            HashAlgorithm::Md5,
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha224,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Blake3,
        ]
    };

    let data = input.as_bytes();
    safe_println!("{}", "\n── Hash Results ──".green().bold());
    for algo in &algos {
        let digest = compute_hash(data, algo);
        let hex = hash_to_hex(&digest);
        safe_println!(
            "  {:<10} {}",
            format!("{}:", algo.name()).cyan(),
            hex
        );
    }
}

fn handle_encode(input: &str, format: &str) {
    let result = encode_to_format(input, format);
    match result {
        Ok(encoded) => {
            safe_println!("{}", "\n── Encoded Output ──".green().bold());
            safe_println!("{}", encoded);
        }
        Err(e) => {
            safe_println!(
                "{} {}",
                "[ERROR]".red().bold(),
                e
            );
        }
    }
}

fn handle_encrypt(input: &str, cipher: &str, key: &Option<String>, _param: &Option<String>) {
    use hashendra::core::scanner::*;

    safe_println!("{}", "\n── Encrypted Output ──".green().bold());
    let result = match cipher {
        "caesar" | "rot" => {
            let shift = key.as_deref().and_then(|k| k.parse::<u8>().ok()).unwrap_or(3);
            Some(caesar_encrypt(input, shift))
        }
        "vigenere" => {
            let k = key.as_deref().unwrap_or("key");
            Some(vigenere_encrypt(input, k))
        }
        "affine" => {
            let parts: Vec<&str> = key.as_deref().unwrap_or("5,8").split(',').collect();
            let a = parts.first().and_then(|s| s.parse::<u8>().ok()).unwrap_or(5);
            let b = parts.get(1).and_then(|s| s.parse::<u8>().ok()).unwrap_or(8);
            affine_encrypt(input, a, b)
        }
        "rail-fence" | "railfence" => {
            let rails = key.as_deref().and_then(|k| k.parse::<usize>().ok()).unwrap_or(3);
            Some(rail_fence_encrypt(input, rails))
        }
        "xor" => {
            let k = key.as_deref().unwrap_or("key").as_bytes().to_vec();
            if k.is_empty() {
                safe_println!("{} Key cannot be empty for XOR cipher.", "[ERROR]".red().bold());
                return;
            }
            let encrypted = xor_encrypt(input.as_bytes(), &k);
            let hex = encrypted.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            Some(hex)
        }
        "columnar" => {
            let k = key.as_deref().unwrap_or("key");
            Some(columnar_encrypt(input, k))
        }
        "atbash" => {
            // Atbash is self-inverse, but provide encrypt as explicit call
            let result: String = input
                .chars()
                .map(|c| match c {
                    'A'..='Z' => (b'Z' - (c as u8 - b'A')) as char,
                    'a'..='z' => (b'z' - (c as u8 - b'a')) as char,
                    _ => c,
                })
                .collect();
            Some(result)
        }
        _ => {
            safe_println!(
                "{} Unknown cipher '{}'. Use --list-ciphers to see supported ciphers.",
                "[ERROR]".red().bold(),
                cipher
            );
            return;
        }
    };

    match result {
        Some(output) => safe_println!("{}", output),
        None => safe_println!(
            "{} Encryption failed. Check parameters.",
            "[ERROR]".red().bold()
        ),
    }
}

// safe_print! is defined in utils/io.rs via #[macro_export]
