use crate::cli::CarveOptions;
use colored::*;
use hashendra::safe_println;

pub(crate) fn run_carve(opts: CarveOptions<'_>) -> bool {
    let CarveOptions {
        path,
        input,
        json,
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
        recursive,
        overwrite,
        dry_run,
        list_types,
        matryoshka,
        depth,
    } = opts;
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
            return false;
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
        return true;
    }

    let path = input.or(path);
    let Some(path) = path else {
        safe_println!(
            "{}",
            "[FAIL] carve requires a path or --input unless --list-types is used".red()
        );
        return false;
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
                return true;
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
            true
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
            false
        }
    }
}
