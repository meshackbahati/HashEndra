use super::inspect::{run_disk_inspect, run_ext_inspect, run_fat_inspect, run_ntfs_inspect};
use crate::cli::{DiskOptions, InspectOptions};
use colored::*;
use hashendra::safe_println;

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

pub(crate) fn run_forensic_disk(opts: DiskOptions<'_>) -> bool {
    let DiskOptions {
        path,
        json,
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
    } = opts;
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
            return false;
        }
    };

    match hint {
            ForensicFilesystemHint::Auto => {
                return run_disk_inspect(path, json, sector_size);
            }
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
                        return false;
                    }
                }
            };
            return run_ntfs_inspect(InspectOptions {
                path,
                json,
                offset: selected_offset,
                max_entries: max_records,
                deleted_only,
                include_directories,
                extract_data,
                overwrite,
            })
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
                        return false;
                    }
                }
            };
            return run_fat_inspect(InspectOptions {
                path,
                json,
                offset: selected_offset,
                max_entries: max_records,
                deleted_only,
                include_directories,
                extract_data,
                overwrite,
            });
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
                        return false;
                    }
                }
            };
            return run_ext_inspect(InspectOptions {
                path,
                json,
                offset: selected_offset,
                max_entries: max_records,
                deleted_only,
                include_directories,
                extract_data,
                overwrite,
            })
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
                return true;
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
                        return false;
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
                    return false;
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
                    return false;
                }
            }
        }
    }
    true
}
