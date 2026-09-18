mod cli;
mod handlers;

use clap::Parser;
use cli::{CarveOptions, Cli, Commands, DiskOptions, ForensicCommands};
use colored::*;
use handlers::{
    analyze_file, analyze_single_input, handle_decode, handle_deep_decrypt, handle_encode,
    handle_encrypt, handle_hash, handle_rot, handle_xor, print_banner, print_encoding_formats,
    print_encryption_ciphers, print_hash_algorithms, run_carve, run_crack, run_evm_lookup,
    run_forensic_disk, run_forensic_scan, run_tls_lookup, run_workshop, CrackArgs,
};
use hashendra::core::patterns::EXTERNAL_SIGNATURE_COUNT;
use hashendra::safe_println;
use std::io::{self, BufRead};

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let context = cli.context.clone();
    let mut ok = true;

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
        return std::process::ExitCode::SUCCESS;
    }
    if cli.list_encodings {
        print_encoding_formats();
        return std::process::ExitCode::SUCCESS;
    }
    if cli.list_ciphers {
        print_encryption_ciphers();
        return std::process::ExitCode::SUCCESS;
    }

    // Operations that require input
    if let Some(ref input) = cli.input {
        if let Some(algo) = cli.hash {
            ok &= handle_hash(input, algo.as_deref());
        } else if let Some(ref cipher) = cli.encrypt {
            ok &= handle_encrypt(input, cipher, &cli.key, &cli.cipher_param);
        } else if let Some(ref format) = cli.to {
            ok &= handle_encode(input, format);
        } else if cli.deep_decrypt {
            ok &= handle_deep_decrypt(input);
        } else if cli.decode {
            ok &= handle_decode(input, &context);
        } else if cli.rot {
            ok &= handle_rot(input);
        } else if cli.xor {
            ok &= handle_xor(input);
        } else {
            ok &= analyze_single_input(input, cli.json, cli.verbose, &context);
        }
    } else if let Some(ref file_path) = cli.file {
        ok &= analyze_file(file_path, cli.json);
    } else if let Some(command) = cli.command {
        match command {
            Commands::Update => {
                // No remote database exists yet; report the bundled version.
                safe_println!(
                    "{}",
                    format!(
                        "Signatures are bundled with the binary (v{}). Nothing to fetch yet.",
                        env!("CARGO_PKG_VERSION")
                    )
                    .green()
                );
            }
            Commands::Forensic { command } => match command {
                ForensicCommands::Scan { path, no_extract } => {
                    ok &= run_forensic_scan(std::path::Path::new(&path), cli.json, !no_extract);
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
                    ok &= run_forensic_disk(DiskOptions {
                        path: std::path::Path::new(&path),
                        json: cli.json,
                        sector_size,
                        offset,
                        max_records,
                        deleted_only,
                        include_directories,
                        extract_data: extract_data.as_deref(),
                        overwrite,
                        ntfs,
                        fs: fs.as_deref(),
                        ext4,
                        swap,
                        btrfs,
                    });
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
                    ok &= run_carve(CarveOptions {
                        path: path.as_deref(),
                        input: input.as_deref(),
                        json: cli.json,
                        output: output.as_deref(),
                        config: config.as_deref(),
                        types: &types,
                        include_root,
                        min_size,
                        offset,
                        length,
                        max_size,
                        sector_size,
                        quick,
                        audit_only,
                        recursive: !no_recursive,
                        overwrite,
                        dry_run,
                        list_types,
                        matryoshka,
                        depth,
                    });
                }
            },
            Commands::Disk { path, sector_size } => {
                ok &= run_forensic_disk(DiskOptions {
                    path: std::path::Path::new(&path),
                    json: cli.json,
                    sector_size,
                    offset: 0,
                    max_records: 256,
                    deleted_only: false,
                    include_directories: false,
                    extract_data: None,
                    overwrite: false,
                    ntfs: false,
                    fs: None,
                    ext4: false,
                    swap: false,
                    btrfs: false,
                });
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
                ok &= run_forensic_disk(DiskOptions {
                    path: std::path::Path::new(&path),
                    json: cli.json,
                    sector_size: 512,
                    offset,
                    max_records,
                    deleted_only,
                    include_directories,
                    extract_data: extract_data.as_deref(),
                    overwrite,
                    ntfs: true,
                    fs: None,
                    ext4: false,
                    swap: false,
                    btrfs: false,
                });
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
                ok &= run_carve(CarveOptions {
                    path: path.as_deref(),
                    input: input.as_deref(),
                    json: cli.json,
                    output: output.as_deref(),
                    config: config.as_deref(),
                    types: &types,
                    include_root,
                    min_size,
                    offset,
                    length,
                    max_size,
                    sector_size,
                    quick,
                    audit_only,
                    recursive: !no_recursive,
                    overwrite,
                    dry_run,
                    list_types,
                    matryoshka,
                    depth,
                });
            }
            Commands::Workshop { input } => {
                print_banner();
                ok &= run_workshop(input);
            }
            Commands::Crack {
                hash,
                wordlist,
                format,
                rules,
                jobs,
                speed,
                max_candidates,
            } => {
                ok &= run_crack(CrackArgs {
                    hash: &hash,
                    wordlist: &wordlist,
                    format: format.as_deref(),
                    rules,
                    jobs,
                    speed: &speed,
                    max_candidates,
                    json: cli.json,
                });
            }
            Commands::Tls { code } => {
                ok &= run_tls_lookup(&code, cli.json);
            }
            Commands::Evm { selector } => {
                ok &= run_evm_lookup(&selector, cli.json);
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
                    ok = false;
                    break;
                }
            }
        }
        if first {
            safe_println!("{}", "No input provided. Use --help for usage.".yellow());
        }
    }

    if ok {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
