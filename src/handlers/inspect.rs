use crate::cli::InspectOptions;
use colored::*;
use hashendra::safe_println;

pub(crate) fn run_disk_inspect(path: &std::path::Path, json: bool, sector_size: usize) -> bool {
    match hashendra::forensics::disk::inspect_disk_image(path, sector_size) {
        Ok(report) => {
            if json {
                safe_println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                hashendra::forensics::disk::print_disk_layout(&report);
            }
            true
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
            false
        }
    }
}

pub(crate) fn run_ntfs_inspect(opts: InspectOptions<'_>) -> bool {
    let InspectOptions {
        path,
        json,
        offset,
        max_entries: max_records,
        deleted_only,
        include_directories,
        extract_data,
        overwrite,
    } = opts;
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
            true
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
            false
        }
    }
}

pub(crate) fn run_ext_inspect(opts: InspectOptions<'_>) -> bool {
    let InspectOptions {
        path,
        json,
        offset,
        max_entries: max_inodes,
        deleted_only,
        include_directories,
        extract_data,
        overwrite,
    } = opts;
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
            true
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
            false
        }
    }
}

pub(crate) fn run_fat_inspect(opts: InspectOptions<'_>) -> bool {
    let InspectOptions {
        path,
        json,
        offset,
        max_entries,
        deleted_only,
        include_directories,
        extract_data,
        overwrite,
    } = opts;
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
            true
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
            false
        }
    }
}
