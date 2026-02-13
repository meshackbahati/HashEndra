use clap::{Parser, Subcommand};
use colored::*;
use hashendra::core::patterns::{scan_input, ScanningContext, SecurityRating};
use hashendra::core::scanner::{calculate_entropy, detect_charset};
use hashendra::core::recursive_engine::RecursiveEngine;
use rayon::prelude::*;
use std::io::{self, BufRead, Write};

macro_rules! safe_println {
    ($($arg:tt)*) => {
        if let Err(e) = writeln!(io::stdout(), $($arg)*) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                std::process::exit(0);
            }
            panic!("IO error: {}", e);
        }
    }
}

#[derive(Parser)]
#[command(name = "hashendra")]
#[command(about = "HashEndra - Universal Hash & Encoding Detection Engine", long_about = None)]
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

    #[arg(long, default_value = "generic", help = "Context for detection (network, database, filesystem, etc.)")]
    context: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Update the signature database
    Update,
    /// Run forensic analysis on a file or directory
    Forensic {
        path: String,
    },
    /// Start an interactive decoding workshop
    Workshop {
        input: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let context = cli.context.clone();

    print_banner();

    if let Some(input) = cli.input {
        if cli.deep_decrypt {
            handle_deep_decrypt(&input);
        } else if cli.decode {
            handle_decode(&input, &context);
        } else if cli.rot {
            handle_rot(&input);
        } else if cli.xor {
            handle_xor(&input);
        } else {
            analyze_single_input(&input, cli.json, cli.verbose, &context);
        }
    } else if let Some(file_path) = cli.file {
        analyze_file(&file_path, cli.json);
    } else if let Some(command) = cli.command {
        match command {
            Commands::Update => {
                safe_println!("{}", "Checking for signature updates...".blue());
                safe_println!("{}", "No updates available. You are running the latest version (v0.1.0).".green());
            }
            Commands::Forensic { path } => {
                safe_println!("{}", format!("Running forensic scan on {}...", path).cyan());
                let mut manager = hashendra::utils::io_manager::FileManager::new();
                if let Err(e) = manager.map_file(&path) {
                    safe_println!("{}", format!("Error mapping file: {}", e).red());
                } else {
                    manager.scan_binary();
                }
            }
            Commands::Workshop { input } => {
                run_workshop(input);
            }
        }
    } else {
        // Read from stdin
        let stdin = io::stdin();
        let inputs: Vec<String> = stdin.lock().lines().filter_map(|l| l.ok()).collect();
        
        if inputs.is_empty() {
             safe_println!("{}", "No input provided. Use --help for usage.".yellow());
             return;
        }

        inputs.par_iter().for_each(|input| {
            analyze_single_input(input, cli.json, cli.verbose, &context);
        });
    }
}

fn print_banner() {
    let eagle = r#"
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@%%%@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%@@@@@@@%%%%@@@@@%%%%@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%@@@@@@@@%%%@@@@@%%@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@%%%@@@@@@@@@@@@%%@%%%%%@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*+*#%%@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@%@@%@@%@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%####%@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@%%@@%@@%@%@%@%@@@@%@%@%@@@@@@@%@@@@@%%@@@%%@@%@%%%%%%%%@
@@@@@@@@@@@@@@%%@@@@@@@@@@@@@@@@%%%@%@@@@%@@%%%@%@@%@%@%@@%@@@%@%@%@@@%%%%@%#%@%%%%%%%%@@%@%%%%%%@@@
@@@@@@@@@@@@@@#=+*#%%%@@@@@%@@@@%%%@%%%@%%@@%%%%@@@%@#@%@%%%%@%@%%%@@@@@%@@#%@%%%#*+=#%@@@@@@@@@@@@%
@@@@@@@@@@@@@@@#*#*+-=*%%%%%%@%@%%%@%%%%%%@@%%%%%%%%@%%%%%%%%@%@%%%@@@%@%%%%%*=-=*#**@@@@@@@@@@@@@%#
@@@@@@@@@@@@@@%@%+**++*+--*##%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#*#--=*++*++#@%%@@@@@@@@@%##@
@@@@@@@@@@@@@@*******=*++*==-=-=+**##%%%%%%%%%%%%#####%%%%%%%%%%##*+=---==*++*=******+@@@@@@@@%###%@
@@@@@@@@@@@@@@@*#%###**++###==+=--::=*#%%%%%%#:--:...:+##%%%%#*=::--=+=-#*#++**##*%#*@@@@@%%%#*###@@
@@@@@@@@@@@@@@@@%**#%#***#*+=+*+-===-:+#%%%##*--=--.:=:.-*###+:-===-+*=-=*#***###**%@@@@@%%@@%%%#%@@
@@@@@@@@@@@@@@@#+++++*+++*#*#**+++==+=:#%%%%%+==+++++==+=+%%#-=++=++++*#***+++++++++*@@@@@@@@%@@%%@@
@@@@@@@@@@@@@@@@#=#+=+++++=*#**+++*=*+-#%%%%#=+++=#*#*%%%%%%#-+*-*+++*+#*=+++=+=+#=*@@@@@@@@@@@@%%%@
@@@@@@@@@@@@@@@@@@#++++*#+**=+***##+++*-#%%%*+++=**+*=%%%%%#-***+#****+-**+#*++++#@@@@@@@@@@%@@%%%%%
@@@@@@@@@@@@@@@@@@*++++++++++*+#+*#**+***++**=+==++=++*#*++*#*+**#*+#+*++++++++++*@@@@@@@@@%%@%%@@%%
@@@@@@@@@@@@@@@@@@@#+#******#*##=**+###+###+==+#*+++**=++%##+###=**=##*#******#+*@@@@@@@@@@%%%%@@@@@
@@@@@@@@@@@@@@@@@@@@@%#******#++#**####%##%-++*#+**+##*+=###%####**#++#*#****#%@@@@@@@@@@@@@%@@@@@@@
@@@@@@@@@@@@@@@@%@@@@@%+=***###*+*#***####%=***=-::-=***+%%###***#*+*###***=+%@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@#%@%##%*+**#*%#%%%##%+%#+==-=++*#%*%##%%##%*#**+*%##%%%#@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@%@%@@@@**%%@%#+*##**++####%%%+%##+*****#%%*%%%####++**#**+*%@@%#+@@%@@@@@%@@@@@@@@@@@%
@@@@@@@@@@@@@@%@%@@@%-#%%%%#%@@#++*****#*#%####%*##*%###*@#*#*****++#@@@#%####-%@%@@@@@@@%@@@@@@@@@@
@@@@@@@@@@@@@@@@%@@%*=%%##%*@@@@%%%+=+%+*#@###+%###*#+###@#*=%+=+%%%@@@@*##%##=*%@@@%%@@@@@@@@@@@@@@
@@@@@@@@@@@@@@%@%@%%++##%%#*%%@@@@@@@@%@@@+**#%##%###%##*=%@@%@@@@@@@@%@**###*+=%@@@%%@@@%@%@@@@@@@@
@@@@@@@@@@@@@@%@@@@%=**#++**%%%@%@@@%@@@%%=#*####%%#%##*#-%%@@@@@%@%%%%%*+*+*#*-%@@@@%@@@%@@@@@@@@@@
@@@@@@@@@@@@@@%@@@@%=+******%%%%#%%%%%%%+#=+*######%%##*+-#+%%%%%%%%%%%%*+#*##*-%@@@%%@@@%@@@@@@@@@@
@@@@@@@@@@@@@@@@%@@%+=#%%#*+%%#%###%###-*#%+*+%+..--+%+*+%%*-#%%##%%%#%%+*####+=%@@@%%@@@%@@@@@@@@@@
@@@@@@@@@@@@@@#@@@@@#-%#+=*=%%%%%##%#*+#*=++#+*=+-+*+#*#++=**=*##%%#%%%%+*+#%#=*@@@@%%@@@@@@@@@@@@@@
@@@@@@@@@@@@@@%@@@@@%-*#%#*+*%%%####*-..=*###++--=***%#%%##+:.:=**##%#%*+##%##-%@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@%@@@@@@#=%%*+#=%%@%%%##-.*-:----*-:-=--#####++#--##%%%@%%-%###*+*@@@@@@@@@@@@@@@@@@@@@
@%@@@@@%%@@@@@@@@@@@@@*##%##%+%@%%%%%=:%--::-*:+#*#%*=##****%=+%%%%%%%+%*#%%#*@@@@@@@@@@@@@@@@@@@@@@
@%@@@@@@@@%@@@%@@@@@@@%*%#%##%*%@%%@%+:%====+++**=#%*****##*%=+%@@@%%*#%*%#%*%@@@@@@@@@@@@@@@@@@@@@@
@%%%@@@@@@@@@@@@@@@@@@@%+%*%%#%*%@@@@*-#++*+#*++=--=+**##%**#=+%@@@%+%#%@%%+%@@@@@@@@@@@@@@@@@@@@@@@
@%%%@@@@%%#@@@@@@@@@@@@@%*%%@%#%%#%@@#==*+**+-::..---=+*##**=:+%@%##%#%%%%*%@@@@@@@@@@@@@@@@@@@@@@@@
@@%%%%@%@%%@@@@@@@@@@@@@@@##%@%#%%#*%%-:****=:-=+%%*++++##**::#%*#%##%%%##@@@@@@@@@@@@@@@@@@@@@@@@@@
@@%%%%%@@%@@@@@@@%@@@@@@@@@%*%%@@%#%%##++###+==+=##+*+++###+-*%%%##%%%%*#@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@%%%%@@@@@@@@@@@@@@@@@@@@@@##%%%%%%%@#+*#%*++***#*#***###+*@%#####%##@@@@@@@%@@@@@@@@@@@@@@@@@@@@@
@@@@%@@%@@@@@@@@@@@@@@@%@@@@@@@%#%%@%%%@#**%#*++=--++**#%**#@@%%@%#*#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@#%@%@@@@%%%@@@%%@@%%%@@@@@@@@%**%%%@@%#*%%%%#*#%%%%%*#%@@%@%**%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@%#%%%@@@@%%%%%####%%@@@@@@@@@@@@@%##%%@@###%#*+*%%%###@@@%##%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@%%%%%@@@@@@@%%%%@%@@@@@@@@@@%@@@@@@@@@@%%%%#++*##*###%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@%%%%@@@@@@@@@%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#-.+*#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@%%@@@@@@@@@@@%@@@%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@%#**%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@%@@%%#%@@@@@@@@@@@@@@@@@@%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    "#;

    safe_println!("{}", eagle.cyan());
    safe_println!("{}", "------------------------------------------------------------------".cyan());
    safe_println!("{}", "                HashEndra v2.0 - Advanced Cipher Suite            ".cyan());
    safe_println!("{}", "          The Universal Forensic Decryption & Hashing Engine      ".cyan());
    safe_println!("{}", "                 Author: Meshack Bahati                           ".cyan());
    safe_println!("{}", "          GitHub: https://github.com/meshackbahati/HashEndra      ".cyan());
    safe_println!("{}", "------------------------------------------------------------------".cyan());
}
fn handle_deep_decrypt(input: &str) {
    let engine = RecursiveEngine::new(10);
    safe_println!("[SCAN] Starting deep recursive unwrapping for: {}", input.white().bold());
    
    let result = engine.explore_paths(input);
    
    for step in result.steps {
        safe_println!("  [LAYER {}] Detected: {} -> {}", step.layer + 1, step.decoder.yellow(), step.result.green());
    }
    
    if result.layers_unwrapped > 0 {
        safe_println!("\n[OK] Fully decrypted in {} layers", result.layers_unwrapped);
        safe_println!("[FINISH] Final Payload: {}", result.final_result.cyan().bold());
    } else {
        safe_println!("\n[FAIL] No layers could be automatically unwrapped.");
    }
}

fn handle_decode(input: &str, _context_str: &str) {
    use hashendra::core::scanner::{decode_base64, decode_hex, decode_url, decode_base32, decode_base58};
    use hashendra::core::patterns::{scan_input, ScanningContext};
    
    let mut current = input.to_string();
    let mut layer = 0;
    let mut history = vec![current.clone()];
    
    safe_println!("[SCAN] Starting deep decode for: {}", input);
    
    while layer < 10 { // Prevent infinite loops
        let mut decoded_something = false;
        
        // Try HEX
        if let Some(decoded) = decode_hex(&current) {
            if let Ok(s) = String::from_utf8(decoded.clone()) {
                if s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) && !history.contains(&s) && s.len() >= 3 {
                    current = s;
                    layer += 1;
                    history.push(current.clone());
                    safe_println!("  Layer {}: Decoded Hex -> {}", layer, current.green());
                    decoded_something = true;
                }
            }
        }
        
        if !decoded_something {
            if let Some(decoded) = decode_base64(&current) {
                if let Ok(s) = String::from_utf8(decoded.clone()) {
                    if s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) && !history.contains(&s) && s.len() >= 3 {
                        current = s;
                        layer += 1;
                        history.push(current.clone());
                        safe_println!("  Layer {}: Decoded Base64 -> {}", layer, current.green());
                        decoded_something = true;
                    }
                }
            }
        }

        if !decoded_something {
            if let Some(url_s) = decode_url(&current) {
                if !history.contains(&url_s) {
                    current = url_s;
                    layer += 1;
                    history.push(current.clone());
                    safe_println!("  Layer {}: Decoded URL -> {}", layer, current.green());
                    decoded_something = true;
                }
            }
        }

        if !decoded_something {
            if let Some(b32_data) = decode_base32(&current) {
                if let Ok(s) = String::from_utf8(b32_data) {
                    if s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) && !history.contains(&s) && s.len() >= 3 {
                        current = s;
                        layer += 1;
                        history.push(current.clone());
                        safe_println!("  Layer {}: Decoded Base32 -> {}", layer, current.green());
                        decoded_something = true;
                    }
                }
            }
        }

        if !decoded_something {
            if let Some(b58_data) = decode_base58(&current) {
                if let Ok(s) = String::from_utf8(b58_data) {
                    if s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) && !history.contains(&s) && s.len() >= 3 {
                        current = s;
                        layer += 1;
                        history.push(current.clone());
                        safe_println!("  Layer {}: Decoded Base58 -> {}", layer, current.green());
                        decoded_something = true;
                    }
                }
            }
        }

        // Try ROT13
        if !decoded_something {
            use hashendra::core::scanner::rot_brute_force;
            let rot_results = rot_brute_force(&current);
            // We specifically look for ROT13 (shift 13)
            if let Some((_, rot13)) = rot_results.into_iter().find(|(s, _)| *s == 13) {
                if !history.contains(&rot13) && rot13.chars().any(|c| c.is_ascii_alphabetic()) {
                    // Simple heuristic: Does it contain common English vowels/liquids?
                    let lower = rot13.to_lowercase();
                    let common = lower.chars().filter(|c| "aeiou ".contains(*c)).count();
                    if common as f32 / rot13.len() as f32 > 0.2 {
                        current = rot13;
                        layer += 1;
                        history.push(current.clone());
                        safe_println!("  Layer {}: Decoded ROT13 -> {}", layer, current.green());
                        decoded_something = true;
                    }
                }
            }
        }
        
        if !decoded_something {
            break;
        }
        
        // After decoding, check if it's a known hash
        let matches = scan_input(&current, ScanningContext::Generic);
        if !matches.is_empty() {
            safe_println!("[MATCH] Potential Match found at Layer {}:", layer);
            for m in matches {
                safe_println!("  - {} ({:.0}%)", m.name, m.confidence * 100.0);
            }
        }
    }
    
    if layer == 0 {
        safe_println!("[FAIL] No automatic decoding layers found.");
    } else {
        safe_println!("[FINISH] Final Result: {}", current);
    }
}

fn handle_rot(input: &str) {
    use hashendra::core::scanner::rot_brute_force;
    safe_println!("[ROT] Brute-forcing ROT for: {}", input);
    let results = rot_brute_force(input);
    for (shift, decoded) in results {
        safe_println!("  ROT{:02}: {}", shift, decoded);
    }
}

fn handle_xor(input: &str) {
    use hashendra::core::scanner::{xor_crack, decode_hex};
    safe_println!("[XOR] Attempting single-byte XOR crack...");
    
    let bytes = if let Some(h) = decode_hex(input) {
        h
    } else {
        input.as_bytes().to_vec()
    };
    
    let results = xor_crack(&bytes);
    if results.is_empty() {
        safe_println!("[FAIL] No plaintext found with XOR crack.");
    } else {
        for (key, decoded, score) in results.iter().take(5) {
            safe_println!("  Key 0x{:02x} (Score {:.2}): {}", key, score, decoded);
        }
    }
}

fn analyze_single_input(input: &str, json: bool, verbose: bool, context_str: &str) {
    let context = match context_str.to_lowercase().as_str() {
        "network" => ScanningContext::Network,
        "filesystem" | "shadow" => ScanningContext::Filesystem,
        "database" | "sql" => ScanningContext::Database,
        "memory" => ScanningContext::Memory,
        "blockchain" => ScanningContext::Blockchain,
        _ => ScanningContext::Generic,
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
        let confidence_bar = "#".repeat((top.confidence * 10.0) as usize) + &"-".repeat(10 - (top.confidence * 10.0) as usize);
        safe_println!("[CONFIDENCE]   : [{}] {:.0}%", confidence_bar.green(), top.confidence * 100.0);
        
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
        let hc = res.hashcat_mode.map(|m| format!("[hashcat: {}]", m)).unwrap_or_default();
        let john = res.john_format.as_ref().map(|f| format!("[john: {}]", f)).unwrap_or_default();
        
        let status = if res.confidence > 0.8 { "[OK]" } else { "[i]" };
        safe_println!("|  {} {:<18} {:.0}%  {:<12} {:<12} |", status, res.name, res.confidence * 100.0, hc, john);
        
        if !res.extracted_parameters.is_empty() {
             for (k, v) in &res.extracted_parameters {
                 safe_println!("|      -> {}: {} {:<30} |", k.cyan(), v.white(), "");
             }
        }
        
        if !res.compliance_refs.is_empty() {
             safe_println!("|      -> Compliance: {} {:<30} |", res.compliance_refs.join(", ").yellow(), "");
         }
    }

    if results.is_empty() {
        safe_println!("|  [FAIL] No matches detected                                     |");
    }

    safe_println!("+----------------------------------------------------------------+");

    if let Some(top) = results.first() {
        safe_println!("\n+-- RECOMMENDATION ----------------------------------------------+");
        safe_println!("   -> Primary : {} ({})", top.name, top.description);
        if let Some(hc) = top.hashcat_mode {
             safe_println!("   -> Crack   : hashcat -m {} hash.txt rockyou.txt", hc);
        }
        if !top.compliance_refs.is_empty() {
             safe_println!("   -> Status  : Does not meet {}", top.compliance_refs.join(", "));
        }
        safe_println!("+----------------------------------------------------------------+");
    }
    if verbose {
        safe_println!("\n=================================================================");
        safe_println!("Technical Analysis:");
        safe_println!("  * Byte distribution: {:?}", input.as_bytes().iter().take(8).collect::<Vec<_>>());
        safe_println!("=================================================================");
    }
}

fn analyze_file(path: &str, json: bool) {
    let file = std::fs::File::open(path).expect("Could not open file");
    let reader = io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();

    lines.par_iter().for_each(|line| {
        analyze_single_input(line, json, false, "generic");
    });
}

fn run_workshop(initial_input: Option<String>) {
    let mut current = initial_input.unwrap_or_default();
    safe_println!("{}", "------------------------------------------------------------------".cyan());
    safe_println!("{}", "                HashEndra Interactive Workshop v2.0               ".cyan());
    safe_println!("{}", "      Type /help for commands, /exit to quit, or raw text to set.  ".cyan());
    safe_println!("{}", "------------------------------------------------------------------".cyan());

    loop {
        safe_print("hashendra> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() { break; }
        let input = input.trim();

        if input.is_empty() { continue; }
        if input == "/exit" || input == "/quit" { break; }

        if input.starts_with('/') {
            let parts: Vec<&str> = input.split_whitespace().collect();
            match parts[0] {
                "/help" => {
                    safe_println!("  /set <text>      - Set current working text");
                    safe_println!("  /base64          - Decode current as Base64");
                    safe_println!("  /hex             - Decode current as Hex");
                    safe_println!("  /rot13           - Apply ROT13 to current");
                    safe_println!("  /xor <key>       - XOR current with key (string)");
                    safe_println!("  /deep            - Run deep auto-unwrapper");
                    safe_println!("  /status          - Show current state");
                    safe_println!("  /exit            - Exit workshop");
                }
                "/set" => {
                    if parts.len() > 1 {
                        current = parts[1..].join(" ");
                        safe_println!("  [OK] Current text set.");
                    }
                }
                "/base64" => {
                    use hashendra::core::scanner::decode_base64;
                    if let Some(dec) = decode_base64(&current) {
                        if let Ok(s) = String::from_utf8(dec) {
                            current = s;
                            safe_println!("  [OK] Decoded: {}", current.green());
                        } else {
                            safe_println!("  [FAIL] Result is not valid UTF-8.");
                        }
                    } else {
                        safe_println!("  [FAIL] Not valid Base64.");
                    }
                }
                "/hex" => {
                    use hashendra::core::scanner::decode_hex;
                    if let Some(dec) = decode_hex(&current) {
                        if let Ok(s) = String::from_utf8(dec) {
                            current = s;
                            safe_println!("  [OK] Decoded: {}", current.green());
                        } else {
                            safe_println!("  [FAIL] Result is not valid UTF-8.");
                        }
                    } else {
                        safe_println!("  [FAIL] Not valid Hex.");
                    }
                }
                "/rot13" => {
                     current = current.chars().map(|c| {
                        if c.is_ascii_alphabetic() {
                            let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                            (((c as u8 - base) + 13) % 26 + base) as char
                        } else {
                            c
                        }
                    }).collect();
                    safe_println!("  [OK] Applied ROT13: {}", current.green());
                }
                "/xor" => {
                    if parts.len() > 1 {
                        let key = parts[1].as_bytes();
                        let current_bytes = current.as_bytes();
                        let xored: Vec<u8> = current_bytes.iter().enumerate().map(|(i, &b)| b ^ key[i % key.len()]).collect();
                        current = String::from_utf8_lossy(&xored).to_string();
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
                }
                 _ => {
                    safe_println!("  [FAIL] Unknown command. Type /help.");
                }
            }
        } else {
            current = input.to_string();
            safe_println!("  [OK] Current text set to input.");
        }
    }
}

fn safe_print(arg: &str) {
    print!("{}", arg.bright_white().bold());
}
