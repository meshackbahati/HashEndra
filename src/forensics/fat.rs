use crate::safe_println;
use colored::*;
use memmap2::Mmap;
use serde::Serialize;
use std::collections::{BTreeSet, VecDeque};
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
enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

#[derive(Clone)]
struct BootSector {
    kind: FatType,
    volume_offset: usize,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    cluster_size: usize,
    reserved_sectors: u16,
    fat_count: u8,
    sectors_per_fat: u32,
    total_sectors: u32,
    total_clusters: u32,
    root_cluster: Option<u32>,
    root_entry_count: u16,
    root_dir_offset: usize,
    root_dir_bytes: usize,
    data_offset: usize,
    fat_offset: usize,
    volume_label: Option<String>,
}

#[derive(Clone)]
struct ParsedEntry {
    deleted: bool,
    directory: bool,
    short_name: String,
    path: String,
    first_cluster: u32,
    size: u32,
}

#[derive(Clone)]
enum DirSource {
    Root,
    Cluster(u32),
}

pub fn inspect_fat_image(path: &Path, options: &FatOptions) -> io::Result<FatReport> {
    let file = File::open(path)?;
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

        if let Some(dir) = &options.extract_data_to {
            if !parsed.directory && parsed.size > 0 && parsed.first_cluster >= 2 {
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

fn parse_boot_sector(data: &[u8], volume_offset: usize) -> Option<BootSector> {
    let boot = data.get(volume_offset..volume_offset + 512)?;
    if boot.get(3..11) == Some(b"EXFAT   ") || boot.get(510..512) != Some(&[0x55, 0xAA]) {
        return None;
    }

    let bytes_per_sector = le_u16(boot, 11)?;
    let sectors_per_cluster = *boot.get(13)?;
    let reserved_sectors = le_u16(boot, 14)?;
    let fat_count = *boot.get(16)?;
    let root_entry_count = le_u16(boot, 17)?;
    let total_sectors = {
        let short = le_u16(boot, 19)?;
        if short == 0 {
            le_u32(boot, 32)?
        } else {
            short as u32
        }
    };
    let sectors_per_fat = {
        let short = le_u16(boot, 22)? as u32;
        if short == 0 { le_u32(boot, 36)? } else { short }
    };

    if bytes_per_sector == 0
        || !bytes_per_sector.is_power_of_two()
        || sectors_per_cluster == 0
        || !sectors_per_cluster.is_power_of_two()
        || fat_count == 0
        || total_sectors == 0
        || sectors_per_fat == 0
    {
        return None;
    }

    let root_dir_sectors =
        ((root_entry_count as u32 * 32) + (bytes_per_sector as u32 - 1)) / bytes_per_sector as u32;
    let data_sectors = total_sectors.checked_sub(
        reserved_sectors as u32 + fat_count as u32 * sectors_per_fat + root_dir_sectors,
    )?;
    let total_clusters = data_sectors / sectors_per_cluster as u32;
    let kind = if total_clusters < 4085 {
        FatType::Fat12
    } else if total_clusters < 65525 {
        FatType::Fat16
    } else {
        FatType::Fat32
    };

    let cluster_size = bytes_per_sector as usize * sectors_per_cluster as usize;
    let fat_offset =
        volume_offset.checked_add(bytes_per_sector as usize * reserved_sectors as usize)?;
    let root_dir_offset = volume_offset.checked_add(
        bytes_per_sector as usize
            * (reserved_sectors as usize + fat_count as usize * sectors_per_fat as usize),
    )?;
    let root_dir_bytes = root_dir_sectors as usize * bytes_per_sector as usize;
    let data_offset = volume_offset.checked_add(
        bytes_per_sector as usize
            * (reserved_sectors as usize
                + fat_count as usize * sectors_per_fat as usize
                + root_dir_sectors as usize),
    )?;
    let root_cluster = (kind == FatType::Fat32).then(|| le_u32(boot, 44)).flatten();

    Some(BootSector {
        kind,
        volume_offset,
        bytes_per_sector,
        sectors_per_cluster,
        cluster_size,
        reserved_sectors,
        fat_count,
        sectors_per_fat,
        total_sectors,
        total_clusters,
        root_cluster,
        root_entry_count,
        root_dir_offset,
        root_dir_bytes,
        data_offset,
        fat_offset,
        volume_label: boot_volume_label(boot, kind),
    })
}

fn collect_entries(
    data: &[u8],
    boot: &BootSector,
    max_entries: usize,
) -> io::Result<(usize, usize, Vec<ParsedEntry>, Vec<String>)> {
    let mut scanned_entries = 0usize;
    let mut deleted_entries = 0usize;
    let mut entries = Vec::new();
    let mut notes = Vec::new();
    let mut queue = VecDeque::from([(String::new(), DirSource::Root)]);
    let mut visited_dirs = BTreeSet::new();

    while let Some((parent, source)) = queue.pop_front() {
        let bytes = match source {
            DirSource::Root => read_root_directory_bytes(data, boot)?,
            DirSource::Cluster(cluster) => {
                if !visited_dirs.insert(cluster) {
                    continue;
                }
                read_directory_chain(data, boot, cluster)?
            }
        };

        for record in bytes.chunks_exact(32) {
            if scanned_entries >= max_entries {
                notes.push(format!(
                    "entry limit reached at {}; increase --max-records to inspect more FAT directory entries",
                    max_entries
                ));
                return Ok((scanned_entries, deleted_entries, entries, notes));
            }
            if record[0] == 0x00 {
                break;
            }
            if record[11] == 0x0F {
                continue;
            }

            scanned_entries += 1;
            let deleted = record[0] == 0xE5;
            if deleted {
                deleted_entries += 1;
            }

            let attr = record[11];
            if attr & 0x08 != 0 {
                continue;
            }

            let short_name = decode_short_name(record, deleted);
            if short_name.is_empty() {
                continue;
            }

            let directory = attr & 0x10 != 0;
            let first_cluster = cluster_from_entry(record);
            let path = if parent.is_empty() {
                short_name.clone()
            } else {
                format!("{}/{}", parent, short_name)
            };

            if !deleted
                && directory
                && short_name != "."
                && short_name != ".."
                && first_cluster >= 2
            {
                queue.push_back((path.clone(), DirSource::Cluster(first_cluster)));
            }

            entries.push(ParsedEntry {
                deleted,
                directory,
                short_name,
                path,
                first_cluster,
                size: le_u32(record, 28).unwrap_or(0),
            });
        }
    }

    Ok((scanned_entries, deleted_entries, entries, notes))
}

fn read_root_directory_bytes(data: &[u8], boot: &BootSector) -> io::Result<Vec<u8>> {
    if let Some(root_cluster) = boot.root_cluster {
        read_directory_chain(data, boot, root_cluster)
    } else {
        let slice = data
            .get(boot.root_dir_offset..boot.root_dir_offset + boot.root_dir_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "root directory fell outside the image",
                )
            })?;
        Ok(slice.to_vec())
    }
}

fn read_directory_chain(data: &[u8], boot: &BootSector, first_cluster: u32) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut current = first_cluster;
    let mut visited = BTreeSet::new();

    while boot.valid_cluster(current) {
        if !visited.insert(current) {
            break;
        }
        bytes.extend_from_slice(read_cluster(data, boot, current)?);
        let next = read_fat_entry(data, boot, current).unwrap_or(0);
        if next == 0 || boot.is_end_of_chain(next) || boot.is_bad_cluster(next) {
            break;
        }
        current = next;
    }

    Ok(bytes)
}

fn recover_file_bytes(
    data: &[u8],
    boot: &BootSector,
    first_cluster: u32,
    size: u32,
    deleted: bool,
) -> io::Result<(Vec<u8>, Option<String>)> {
    let target_size = size as usize;
    let clusters_needed = div_ceil(target_size, boot.cluster_size).max(1);
    let mut bytes = Vec::with_capacity(target_size.min(1024 * 1024));
    let mut visited = BTreeSet::new();
    let mut note = None;
    let mut current = first_cluster;
    let mut clusters_read = 0usize;

    while boot.valid_cluster(current) && clusters_read < clusters_needed {
        if !visited.insert(current) {
            note = Some("cluster chain loop detected during recovery".to_string());
            break;
        }

        bytes.extend_from_slice(read_cluster(data, boot, current)?);
        clusters_read += 1;
        if clusters_read >= clusters_needed {
            break;
        }

        let next = read_fat_entry(data, boot, current).unwrap_or(0);
        if next == 0 {
            if deleted {
                let (_extended, extension_note) = extend_contiguous_deleted_recovery(
                    data,
                    boot,
                    current + 1,
                    clusters_needed - clusters_read,
                    &mut bytes,
                )?;
                note = extension_note;
            } else {
                note = Some("FAT chain terminated early".to_string());
            }
            break;
        }
        if boot.is_bad_cluster(next) {
            note = Some("encountered a bad cluster while rebuilding the FAT chain".to_string());
            break;
        }
        if boot.is_end_of_chain(next) {
            break;
        }
        current = next;
    }

    bytes.truncate(target_size);
    Ok((bytes, note))
}

fn extend_contiguous_deleted_recovery(
    data: &[u8],
    boot: &BootSector,
    mut next_cluster: u32,
    mut needed_clusters: usize,
    bytes: &mut Vec<u8>,
) -> io::Result<(usize, Option<String>)> {
    let mut recovered = 0usize;
    while needed_clusters > 0
        && boot.valid_cluster(next_cluster)
        && cluster_is_free(data, boot, next_cluster)
    {
        bytes.extend_from_slice(read_cluster(data, boot, next_cluster)?);
        next_cluster += 1;
        needed_clusters -= 1;
        recovered += 1;
    }

    let note = if recovered == 0 {
        Some(
            "deleted FAT chain was cleared; no contiguous free-cluster extension was available"
                .to_string(),
        )
    } else if needed_clusters == 0 {
        Some("deleted FAT chain was cleared; rebuilt from contiguous free clusters".to_string())
    } else {
        Some(
            "deleted FAT chain was cleared; partially rebuilt from contiguous free clusters"
                .to_string(),
        )
    };

    Ok((recovered, note))
}

fn read_cluster<'a>(data: &'a [u8], boot: &BootSector, cluster: u32) -> io::Result<&'a [u8]> {
    let offset = boot.cluster_offset(cluster).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cluster offset overflowed or fell outside the volume",
        )
    })?;
    data.get(offset..offset + boot.cluster_size).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "cluster fell outside the image",
        )
    })
}

fn read_fat_entry(data: &[u8], boot: &BootSector, cluster: u32) -> Option<u32> {
    match boot.kind {
        FatType::Fat12 => {
            let fat_entry_offset = cluster as usize + cluster as usize / 2;
            let value = le_u16(data, boot.fat_offset + fat_entry_offset)?;
            if cluster & 1 == 0 {
                Some((value & 0x0FFF) as u32)
            } else {
                Some((value >> 4) as u32)
            }
        }
        FatType::Fat16 => Some(le_u16(data, boot.fat_offset + cluster as usize * 2)? as u32),
        FatType::Fat32 => Some(le_u32(data, boot.fat_offset + cluster as usize * 4)? & 0x0FFF_FFFF),
    }
}

fn cluster_is_free(data: &[u8], boot: &BootSector, cluster: u32) -> bool {
    read_fat_entry(data, boot, cluster) == Some(0)
}

fn cluster_from_entry(record: &[u8]) -> u32 {
    let high = le_u16(record, 20).unwrap_or(0) as u32;
    let low = le_u16(record, 26).unwrap_or(0) as u32;
    (high << 16) | low
}

fn decode_short_name(record: &[u8], deleted: bool) -> String {
    let mut base = record[..8].to_vec();
    let ext = &record[8..11];

    if deleted {
        base[0] = b'_';
    } else if base[0] == 0x05 {
        base[0] = 0xE5;
    }

    let base = decode_dos_component(&base);
    let ext = decode_dos_component(ext);
    if base.is_empty() {
        String::new()
    } else if ext.is_empty() {
        base
    } else {
        format!("{}.{}", base, ext)
    }
}

fn decode_dos_component(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .filter(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'$' | b'~' | b' ')
        })
        .collect::<Vec<_>>()
        .split(|byte| *byte == b' ')
        .next()
        .map(|chunk| String::from_utf8_lossy(chunk).trim().to_string())
        .unwrap_or_default()
}

fn boot_volume_label(boot: &[u8], kind: FatType) -> Option<String> {
    let label = match kind {
        FatType::Fat32 => boot.get(71..82),
        FatType::Fat12 | FatType::Fat16 => boot.get(43..54),
    }?;
    let label = decode_ascii(label);
    (!label.is_empty()).then_some(label)
}

fn decode_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .filter(|byte| byte.is_ascii_graphic() || *byte == b' ')
        .map(char::from)
        .collect::<String>()
        .trim()
        .to_string()
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
        value.saturating_add(divisor - 1) / divisor
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

#[cfg(test)]
mod tests {
    use super::{FatOptions, inspect_fat_bytes};

    #[test]
    fn enumerates_and_recovers_deleted_fat32_entries() {
        let image = build_test_image();
        let output_dir = std::env::temp_dir().join(format!("hashendra-fat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&output_dir);

        let report = inspect_fat_bytes(
            &image,
            "fat.img".to_string(),
            &FatOptions {
                max_entries: 32,
                include_directories: true,
                extract_data_to: Some(output_dir.clone()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(report.boot.kind, "FAT32");
        assert_eq!(report.deleted_entries, 1);
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.path.as_deref() == Some("DOCS"))
        );
        let deleted = report
            .entries
            .iter()
            .find(|entry| entry.deleted && entry.short_name == "_ELTXT.TXT")
            .unwrap();
        assert!(
            deleted
                .recovery_note
                .as_deref()
                .unwrap_or_default()
                .contains("contiguous")
        );
        let deleted_path = deleted.extracted_path.as_ref().unwrap();
        assert_eq!(
            std::fs::read(deleted_path).unwrap(),
            build_deleted_payload()
        );

        let live_nested = report
            .entries
            .iter()
            .find(|entry| entry.path.as_deref() == Some("DOCS/INNER.BIN"))
            .unwrap();
        assert_eq!(
            std::fs::read(live_nested.extracted_path.as_ref().unwrap()).unwrap(),
            b"ABCD"
        );

        let _ = std::fs::remove_dir_all(output_dir);
    }

    fn build_test_image() -> Vec<u8> {
        let sector_size = 512usize;
        let total_sectors = 70_000usize;
        let mut image = vec![0u8; sector_size * total_sectors];

        image[11..13].copy_from_slice(&(sector_size as u16).to_le_bytes());
        image[13] = 1;
        image[14..16].copy_from_slice(&1u16.to_le_bytes());
        image[16] = 1;
        image[17..19].copy_from_slice(&0u16.to_le_bytes());
        image[19..21].copy_from_slice(&0u16.to_le_bytes());
        image[21] = 0xF8;
        image[32..36].copy_from_slice(&(total_sectors as u32).to_le_bytes());
        image[36..40].copy_from_slice(&1u32.to_le_bytes());
        image[44..48].copy_from_slice(&2u32.to_le_bytes());
        image[71..82].copy_from_slice(b"EVIDENCE   ");
        image[82..90].copy_from_slice(b"FAT32   ");
        image[510] = 0x55;
        image[511] = 0xAA;

        let fat_offset = sector_size;
        write_fat32_entry(&mut image, fat_offset, 0, 0x0FFF_FFF8);
        write_fat32_entry(&mut image, fat_offset, 1, 0xFFFF_FFFF);
        write_fat32_entry(&mut image, fat_offset, 2, 0x0FFF_FFFF);
        write_fat32_entry(&mut image, fat_offset, 3, 0x0FFF_FFFF);
        write_fat32_entry(&mut image, fat_offset, 4, 0x0FFF_FFFF);
        write_fat32_entry(&mut image, fat_offset, 5, 0);
        write_fat32_entry(&mut image, fat_offset, 6, 0);
        write_fat32_entry(&mut image, fat_offset, 7, 0x0FFF_FFFF);

        let root = 2 * sector_size;
        write_dir_entry(
            &mut image[root..root + 32],
            b"DOCS    ",
            b"   ",
            0x10,
            3,
            0,
            false,
        );
        write_dir_entry(
            &mut image[root + 32..root + 64],
            b"DELTXT  ",
            b"TXT",
            0x20,
            5,
            build_deleted_payload().len() as u32,
            true,
        );
        write_dir_entry(
            &mut image[root + 64..root + 96],
            b"LIVE    ",
            b"TXT",
            0x20,
            4,
            10,
            false,
        );
        image[root + 96] = 0;

        let docs = 3 * sector_size;
        write_dir_entry(
            &mut image[docs..docs + 32],
            b".       ",
            b"   ",
            0x10,
            3,
            0,
            false,
        );
        write_dir_entry(
            &mut image[docs + 32..docs + 64],
            b"..      ",
            b"   ",
            0x10,
            2,
            0,
            false,
        );
        write_dir_entry(
            &mut image[docs + 64..docs + 96],
            b"INNER   ",
            b"BIN",
            0x20,
            7,
            4,
            false,
        );
        image[docs + 96] = 0;

        let live = 4 * sector_size;
        image[live..live + 10].copy_from_slice(b"live-data\n");

        let deleted_payload = build_deleted_payload();
        let deleted_a = 5 * sector_size;
        let deleted_b = 6 * sector_size;
        image[deleted_a..deleted_a + sector_size].copy_from_slice(&deleted_payload[..sector_size]);
        image[deleted_b..deleted_b + deleted_payload.len() - sector_size]
            .copy_from_slice(&deleted_payload[sector_size..]);

        let inner = 7 * sector_size;
        image[inner..inner + 4].copy_from_slice(b"ABCD");

        image
    }

    fn build_deleted_payload() -> Vec<u8> {
        let mut payload = vec![b'R'; 700];
        payload[0..15].copy_from_slice(b"recovered-data!");
        payload
    }

    fn write_fat32_entry(image: &mut [u8], fat_offset: usize, cluster: usize, value: u32) {
        let offset = fat_offset + cluster * 4;
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_dir_entry(
        entry: &mut [u8],
        base: &[u8; 8],
        ext: &[u8; 3],
        attr: u8,
        cluster: u32,
        size: u32,
        deleted: bool,
    ) {
        entry[..8].copy_from_slice(base);
        entry[8..11].copy_from_slice(ext);
        entry[11] = attr;
        if deleted {
            entry[0] = 0xE5;
        }
        entry[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
        entry[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
        entry[28..32].copy_from_slice(&size.to_le_bytes());
    }
}
