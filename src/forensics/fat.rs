use crate::safe_println;
use colored::*;
use memmap2::Mmap;
use serde::Serialize;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

// safe_println! is defined in utils/io.rs via #[macro_export]

#[derive(Debug, Clone)]
pub struct FatOptions {
    pub volume_offset: usize,
    pub max_entries: usize,
    pub deleted_only: bool,
    pub include_directories: bool,
    pub extract_data_to: Option<PathBuf>,
    pub overwrite: bool,
}

impl Default for FatOptions {
    fn default() -> Self {
        Self {
            volume_offset: 0,
            max_entries: 256,
            deleted_only: false,
            include_directories: false,
            extract_data_to: None,
            overwrite: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FatBootInfo {
    pub volume_offset: u64,
    pub kind: String,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub cluster_size: u64,
    pub reserved_sectors: u16,
    pub fat_count: u8,
    pub sectors_per_fat: u32,
    pub total_sectors: u32,
    pub total_clusters: u32,
    pub root_cluster: Option<u32>,
    pub root_entry_count: u16,
    pub data_offset: u64,
    pub fat_offset: u64,
    pub volume_label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FatEntry {
    pub deleted: bool,
    pub directory: bool,
    pub short_name: String,
    pub path: Option<String>,
    pub first_cluster: u32,
    pub size: u32,
    pub extracted_path: Option<String>,
    pub recovery_note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FatReport {
    pub path: String,
    pub boot: FatBootInfo,
    pub scanned_entries: usize,
    pub returned_entries: usize,
    pub deleted_entries: usize,
    pub recovered_files: usize,
    pub recovered_bytes: u64,
    pub entries: Vec<FatEntry>,
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

#[derive(Clone)]
pub(crate) struct BootSector {
    pub(crate) kind: FatType,
    pub(crate) volume_offset: usize,
    pub(crate) bytes_per_sector: u16,
    pub(crate) sectors_per_cluster: u8,
    pub(crate) cluster_size: usize,
    pub(crate) reserved_sectors: u16,
    pub(crate) fat_count: u8,
    pub(crate) sectors_per_fat: u32,
    pub(crate) total_sectors: u32,
    pub(crate) total_clusters: u32,
    pub(crate) root_cluster: Option<u32>,
    pub(crate) root_entry_count: u16,
    pub(crate) root_dir_offset: usize,
    pub(crate) root_dir_bytes: usize,
    pub(crate) data_offset: usize,
    pub(crate) fat_offset: usize,
    pub(crate) volume_label: Option<String>,
}

#[derive(Clone)]
pub(crate) struct ParsedEntry {
    pub(crate) deleted: bool,
    pub(crate) directory: bool,
    pub(crate) short_name: String,
    pub(crate) path: String,
    pub(crate) first_cluster: u32,
    pub(crate) size: u32,
}

#[derive(Clone)]
pub(crate) enum DirSource {
    Root,
    Cluster(u32),
}
pub fn inspect_fat_image(path: &Path, options: &FatOptions) -> io::Result<FatReport> {
    let file = File::open(path)?;
    // SAFETY: the file is opened read-only and never truncated or
    // written while mapped; the mapping is only read.
    let mmap = unsafe { Mmap::map(&file)? };
    inspect_fat_bytes(&mmap[..], path.display().to_string(), options)
}

pub fn inspect_fat_bytes(data: &[u8], path: String, options: &FatOptions) -> io::Result<FatReport> {
    let boot = parse_boot_sector(data, options.volume_offset).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no FAT boot sector found at the requested offset",
        )
    })?;

    if let Some(dir) = &options.extract_data_to {
        std::fs::create_dir_all(dir)?;
    }

    let (scanned_entries, deleted_entries, parsed_entries, mut notes) =
        collect_entries(data, &boot, options.max_entries)?;

    let mut recovered_files = 0usize;
    let mut recovered_bytes = 0u64;
    let mut entries = Vec::new();

    for parsed in parsed_entries {
        if options.deleted_only && !parsed.deleted {
            continue;
        }
        if !options.include_directories && parsed.directory {
            continue;
        }

        let mut entry = FatEntry {
            deleted: parsed.deleted,
            directory: parsed.directory,
            short_name: parsed.short_name.clone(),
            path: Some(parsed.path.clone()),
            first_cluster: parsed.first_cluster,
            size: parsed.size,
            extracted_path: None,
            recovery_note: None,
        };

        if let Some(dir) = &options.extract_data_to
            && !parsed.directory && parsed.size > 0 && parsed.first_cluster >= 2 {
                let (bytes, note) = recover_file_bytes(
                    data,
                    &boot,
                    parsed.first_cluster,
                    parsed.size,
                    parsed.deleted,
                )?;
                let written = write_recovered_file(dir, &entry, &bytes, options.overwrite)?;
                entry.extracted_path = Some(written.display().to_string());
                entry.recovery_note = note;
                recovered_files += 1;
                recovered_bytes = recovered_bytes.saturating_add(bytes.len() as u64);
            }

        entries.push(entry);
    }

    notes.push(
        "FAT deleted-file recovery is strongest for contiguous cluster chains. Cleared FAT chains rebuild only through contiguous free clusters."
            .to_string(),
    );
    notes.push(
        "Short 8.3 names are preserved. Long filename reconstruction for deleted FAT entries is not rebuilt yet."
            .to_string(),
    );

    Ok(FatReport {
        path,
        boot: FatBootInfo {
            volume_offset: boot.volume_offset as u64,
            kind: boot.kind.name().to_string(),
            bytes_per_sector: boot.bytes_per_sector,
            sectors_per_cluster: boot.sectors_per_cluster,
            cluster_size: boot.cluster_size as u64,
            reserved_sectors: boot.reserved_sectors,
            fat_count: boot.fat_count,
            sectors_per_fat: boot.sectors_per_fat,
            total_sectors: boot.total_sectors,
            total_clusters: boot.total_clusters,
            root_cluster: boot.root_cluster,
            root_entry_count: boot.root_entry_count,
            data_offset: boot.data_offset as u64,
            fat_offset: boot.fat_offset as u64,
            volume_label: boot.volume_label.clone(),
        },
        scanned_entries,
        returned_entries: entries.len(),
        deleted_entries,
        recovered_files,
        recovered_bytes,
        entries,
        notes,
    })
}
pub fn print_fat_report(report: &FatReport) {
    safe_println!(
        "{}",
        format!(
            "[FAT] {} | volume 0x{:X} | {}",
            report.path, report.boot.volume_offset, report.boot.kind
        )
        .cyan()
    );
    safe_println!(
        "{}",
        format!(
            "[BOOT] sector {} | cluster {} | fats {} | sectors {}{}",
            report.boot.bytes_per_sector,
            report.boot.cluster_size,
            report.boot.fat_count,
            report.boot.total_sectors,
            report
                .boot
                .volume_label
                .as_ref()
                .map(|value| format!(" | label {}", value))
                .unwrap_or_default()
        )
        .blue()
    );
    safe_println!(
        "{}",
        format!(
            "[SUMMARY] scanned {} entrie(s), returned {}, deleted {}, recovered {}, bytes {}",
            report.scanned_entries,
            report.returned_entries,
            report.deleted_entries,
            report.recovered_files,
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
                entry.first_cluster,
                state.red(),
                kind.yellow(),
                entry.path.as_deref().unwrap_or(&entry.short_name).white()
            );
            safe_println!(
                "      size={} short={}{}",
                entry.size,
                entry.short_name,
                entry
                    .extracted_path
                    .as_ref()
                    .map(|path| format!(" | extracted {}", path))
                    .unwrap_or_default()
            );
            if let Some(note) = &entry.recovery_note {
                safe_println!("      note={}", note.yellow());
            }
        }
    }

    if !report.notes.is_empty() {
        safe_println!("{}", "[NOTES]".cyan());
        for note in &report.notes {
            safe_println!("  {}", note);
        }
    }
}
fn write_recovered_file(
    output_dir: &Path,
    entry: &FatEntry,
    bytes: &[u8],
    overwrite: bool,
) -> io::Result<PathBuf> {
    let label = entry
        .path
        .as_deref()
        .map(sanitize_relative_path)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from(&entry.short_name));
    let mut candidate = output_dir.join(label);

    if let Some(parent) = candidate.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if !overwrite {
        let stem = candidate
            .file_stem()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| entry.short_name.clone());
        let ext = candidate
            .extension()
            .map(|value| value.to_string_lossy().to_string());
        let parent = candidate
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| output_dir.to_path_buf());
        let mut suffix = 1usize;
        while candidate.exists() {
            let file_name = match &ext {
                Some(ext) => format!("{}_{}.{}", stem, suffix, ext),
                None => format!("{}_{}", stem, suffix),
            };
            candidate = parent.join(file_name);
            suffix += 1;
        }
    }

    std::fs::write(&candidate, bytes)?;
    Ok(candidate)
}

fn sanitize_relative_path(value: &str) -> PathBuf {
    let mut path = PathBuf::new();
    for component in value.split('/') {
        let component = sanitize_component(component);
        if !component.is_empty() {
            path.push(component);
        }
    }
    path
}

fn sanitize_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn div_ceil(value: usize, divisor: usize) -> usize {
    if divisor == 0 {
        0
    } else {
        value.div_ceil(divisor)
    }
}

fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

impl FatType {
    fn name(self) -> &'static str {
        match self {
            FatType::Fat12 => "FAT12",
            FatType::Fat16 => "FAT16",
            FatType::Fat32 => "FAT32",
        }
    }
}

impl BootSector {
    fn valid_cluster(&self, cluster: u32) -> bool {
        cluster >= 2 && cluster < self.total_clusters.saturating_add(2)
    }

    fn cluster_offset(&self, cluster: u32) -> Option<usize> {
        if !self.valid_cluster(cluster) {
            return None;
        }
        let cluster_index = cluster.checked_sub(2)? as usize;
        self.data_offset
            .checked_add(cluster_index.checked_mul(self.cluster_size)?)
    }

    fn is_end_of_chain(&self, value: u32) -> bool {
        match self.kind {
            FatType::Fat12 => value >= 0x0FF8,
            FatType::Fat16 => value >= 0xFFF8,
            FatType::Fat32 => value >= 0x0FFF_FFF8,
        }
    }

    fn is_bad_cluster(&self, value: u32) -> bool {
        match self.kind {
            FatType::Fat12 => value == 0x0FF7,
            FatType::Fat16 => value == 0xFFF7,
            FatType::Fat32 => value == 0x0FFF_FFF7,
        }
    }
}

mod parse;
mod recover;

pub(crate) use parse::*;
pub(crate) use recover::*;

#[cfg(test)]
#[path = "fat/fat_tests.rs"]
mod fat_tests;
