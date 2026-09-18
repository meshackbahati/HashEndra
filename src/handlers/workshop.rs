use super::analyze::{analyze_single_input, detect_path_file_type, preview_strings_from_path};
use super::analyze::print_path_metadata;
use super::decode::handle_deep_decrypt;
use super::scan::run_forensic_scan;
use super::workshop_ciphers::run_cipher_command;
use colored::*;
use hashendra::safe_print;
use hashendra::safe_println;
use std::io;
use std::io::Write;

pub(crate) fn workshop_set_current(
    label: &str,
    next: String,
    current: &mut String,
    history: &mut Vec<String>,
) {
    *current = next;
    history.push(current.clone());
    safe_println!("  [OK] {}: {}", label, current.green());
}

pub(crate) fn workshop_decode_bytes(
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

pub(crate) fn workshop_decode_text(
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

pub(crate) fn apply_rot(text: &str, shift: u8) -> String {
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

pub(crate) fn run_workshop(initial_input: Option<String>) -> bool {
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
        if io::stdout().flush().is_err() {
            break; // stdout is gone; nothing left to interact with
        }

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
                    safe_println!("  /caesar <shift>  - Caesar decode with shift");
                    safe_println!("  /xor <key>       - XOR current with key (string)");
                    safe_println!("  /vigenere <key>  - Vigenere decode");
                    safe_println!("  /beaufort <key>  - Beaufort decode (reciprocal)");
                    safe_println!("  /autokey <key>   - Autokey decode");
                    safe_println!("  /gronsfeld <digits> - Gronsfeld decode");
                    safe_println!("  /porta <key>     - Porta decode (reciprocal)");
                    safe_println!("  /affine <a> <b>  - Affine decode");
                    safe_println!("  /atbash          - Atbash decode (reciprocal)");
                    safe_println!("  /rail <n>        - Rail Fence decode");
                    safe_println!("  /columnar <key>  - Columnar decode");
                    safe_println!("  /polybius [key]  - Polybius decode");
                    safe_println!("  /tap             - Tap code decode");
                    safe_println!("  /adfgx <sq> <ck> - ADFGX decode");
                    safe_println!("  /adfgvx <sq> <ck> - ADFGVX decode");
                    safe_println!("  /foursquare <k1> <k2> - Four-Square decode");
                    safe_println!("  /twosquare <k1> <k2>  - Two-Square decode");
                    safe_println!("  /trifid <key> [period] - Trifid decode");
                    safe_println!("  /playfair <key>  - Playfair decode");
                    safe_println!("  /bifid <key> [period]  - Bifid decode");
                    safe_println!("  /bacon [AB]      - Baconian decode");
                    safe_println!("  /substitution <KEY26>  - Substitution decode");
                    safe_println!("  /deep            - Run deep auto-unwrapper");
                    safe_println!("  /from <format>  - Decode current as one explicit format");
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
                                    && bytes.contains(&0x00)
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
                "/caesar" => {
                    if parts.len() > 1 {
                        if let Ok(shift) = parts[1].parse::<u8>() {
                            // Same as /rot: left-rotate, which decodes a
                            // Caesar encryption made with this shift.
                            workshop_set_current(
                                "Caesar decoded",
                                apply_rot(&current, shift),
                                &mut current,
                                &mut history,
                            );
                        } else {
                            safe_println!("  [FAIL] Usage: /caesar <shift>");
                        }
                    } else {
                        safe_println!("  [FAIL] Usage: /caesar <shift>");
                    }
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
                "/from" => {
                    if parts.len() > 1 {
                        use super::decode::handle_decode_format;
                        handle_decode_format(&current, parts[1]);
                    } else {
                        safe_println!("  [FAIL] Usage: /from <format> (see --list-encodings)");
                    }
                }
                "/vigenere" | "/beaufort" | "/autokey" | "/gronsfeld" | "/porta"
                | "/affine" | "/atbash" | "/rail" | "/columnar" | "/polybius" | "/tap"
                | "/adfgx" | "/adfgvx" | "/foursquare" | "/twosquare" | "/trifid"
                | "/playfair" | "/bifid" | "/bacon" | "/substitution" => {
                    run_cipher_command(parts[0], &parts, &mut current, &mut history);
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
    true
}
