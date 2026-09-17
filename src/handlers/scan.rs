use super::analyze::{detect_path_file_type, preview_strings_from_path, print_path_metadata};
use colored::*;
use hashendra::safe_println;

pub(crate) fn run_forensic_scan(path: &std::path::Path, json: bool, extract_artifacts: bool) -> bool {
    // Reject non-regular files that would block or cause issues
    if !path.is_dir() {
        match path.metadata() {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    // Resolve symlink before checking
                    if let Ok(real) = path.canonicalize() {
                        return run_forensic_scan(&real, json, extract_artifacts);
                    }
                }
                if !meta.file_type().is_file() {
                    let msg = format!("not a regular file: {}", path.display());
                    if json {
                        safe_println!("{}", serde_json::json!({"path": path.display().to_string(), "error": msg}).to_string());
                    } else {
                        safe_println!("{}", format!("[FAIL] forensic scan: {}", msg).red());
                    }
                    return false;
                }
            }
            Err(e) => {
                let msg = format!("cannot access {}: {}", path.display(), e);
                if json {
                    safe_println!("{}", serde_json::json!({"path": path.display().to_string(), "error": msg}).to_string());
                } else {
                    safe_println!("{}", format!("[FAIL] forensic scan: {}", msg).red());
                }
                return false;
            }
        }
    }

    if path.is_dir() {
        if json {
            let report = hashendra::forensics::directory::scan_directory(path, extract_artifacts);
            safe_println!("{}", serde_json::to_string_pretty(&report).unwrap());
            return true;
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
                safe_println!("{}", format!("[FAIL] cannot map file: {}", e).red());
            }
            return false;
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
                return true;
            }

            print_path_metadata(path);
            safe_println!("{}", format!("[FILETYPE] {}", file_type).blue());
            manager.scan_binary(extract_artifacts);
            preview_strings_from_path(path, 8, 8);
        }
    }
    true
}
