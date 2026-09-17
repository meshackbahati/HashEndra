use super::NtfsReport;
use colored::*;
use crate::safe_println;

pub fn print_ntfs_report(report: &NtfsReport) {
    safe_println!(
        "{}",
        format!(
            "[NTFS] {} | volume 0x{:X} | MFT 0x{:X}",
            report.path, report.boot.volume_offset, report.boot.mft_offset
        )
        .cyan()
    );
    safe_println!(
        "{}",
        format!(
            "[BOOT] sector {} | cluster {} | record {} | serial {}",
            report.boot.bytes_per_sector,
            report.boot.cluster_size,
            report.boot.record_size,
            report.boot.serial
        )
        .blue()
    );
    safe_println!(
        "{}",
        format!(
            "[SUMMARY] scanned {} record(s), returned {}, deleted {}, resident recovered {}, non-resident recovered {}, bytes {}",
            report.scanned_records,
            report.returned_entries,
            report.deleted_entries,
            report.resident_recovered,
            report.non_resident_recovered,
            report.recovered_bytes
        )
        .cyan()
    );

    if !report.entries.is_empty() {
        safe_println!("{}", "[ENTRIES]".cyan());
        for entry in &report.entries {
            let state = if entry.deleted { "deleted" } else { "live" };
            let kind = if entry.directory { "dir" } else { "file" };
            safe_println!(
                "  [{}] {} {} {}",
                entry.record_number,
                state.red(),
                kind.yellow(),
                entry.name.as_deref().unwrap_or("<unnamed>").white()
            );
            safe_println!(
                "      parent={} seq={} size={} resident={} nonresident={} runs={}{}",
                entry
                    .parent_reference
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                entry.sequence_number,
                entry
                    .real_size
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                entry
                    .resident_data_size
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "0".to_string()),
                entry
                    .non_resident_data_size
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "0".to_string()),
                entry
                    .data_runs
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "0".to_string()),
                entry
                    .extracted_path
                    .as_ref()
                    .map(|path| format!(" | extracted {}", path))
                    .unwrap_or_default()
            );
            if let Some(note) = &entry.recovery_note {
                safe_println!("      note={}", note.yellow());
            }
            for ads in &entry.alternate_data_streams {
                safe_println!(
                    "      ads={} resident={} compressed={} encrypted={} sparse={} size={} runs={}{}",
                    ads.name.cyan(),
                    ads.resident,
                    ads.compressed,
                    ads.encrypted,
                    ads.sparse,
                    ads.size
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    ads.data_runs
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "0".to_string()),
                    ads.extracted_path
                        .as_ref()
                        .map(|path| format!(" | extracted {}", path))
                        .unwrap_or_default()
                );
                if let Some(note) = &ads.recovery_note {
                    safe_println!("          note={}", note.yellow());
                }
            }
        }
    }

    if let Some(bitmap) = &report.system_artifacts.bitmap {
        safe_println!(
            "{}",
            format!(
                "[BITMAP] tracked {} | allocated {} | free {}",
                bitmap.tracked_clusters, bitmap.allocated_clusters, bitmap.free_clusters
            )
            .cyan()
        );
    }
    if let Some(logfile) = &report.system_artifacts.logfile {
        safe_println!(
            "{}",
            format!(
                "[LOGFILE] bytes {} | restart pages {} | record pages {}{}",
                logfile.bytes,
                logfile.restart_pages,
                logfile.record_pages,
                logfile
                    .first_magic
                    .as_ref()
                    .map(|value| format!(" | first {}", value))
                    .unwrap_or_default()
            )
            .cyan()
        );
    }
    if let Some(usn) = &report.system_artifacts.usn_journal {
        safe_println!(
            "{}",
            format!(
                "[USN] stream {} | bytes {} | records {}",
                usn.stream_name, usn.bytes, usn.records
            )
            .cyan()
        );
        for name in &usn.sample_names {
            safe_println!("  {}", name);
        }
    }

    if !report.notes.is_empty() {
        safe_println!("{}", "[NOTES]".cyan());
        for note in &report.notes {
            safe_println!("  {}", note);
        }
    }
}
