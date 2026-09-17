use crate::safe_println;
use colored::*;
use memmap2::Mmap;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::Path;

// safe_println! is defined in utils/io.rs via #[macro_export]

#[derive(Debug, Clone, Serialize)]
pub struct FilesystemVolume {
    pub kind: String,
    pub summary: String,
    pub details: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PartitionRecord {
    pub index: usize,
    pub bootable: bool,
    pub partition_type: String,
    pub type_code: Option<String>,
    pub guid_type: Option<String>,
    pub name: Option<String>,
    pub start_lba: u64,
    pub sectors: u64,
    pub start_offset: u64,
    pub length_bytes: u64,
    pub filesystem: Option<FilesystemVolume>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskLayoutReport {
    pub path: String,
    pub size: u64,
    pub sector_size: usize,
    pub scheme: Option<String>,
    pub standalone_filesystem: Option<FilesystemVolume>,
    pub partitions: Vec<PartitionRecord>,
    pub notes: Vec<String>,
}

pub fn inspect_disk_image(path: &Path, sector_size: usize) -> io::Result<DiskLayoutReport> {
    let file = File::open(path)?;
    // SAFETY: the file is opened read-only and never truncated or
    // written while mapped; the mapping is only read.
    let mmap = unsafe { Mmap::map(&file)? };
    Ok(inspect_disk_bytes(
        &mmap[..],
        path.display().to_string(),
        sector_size,
    ))
}

pub fn inspect_filesystem_image(
    path: &Path,
    offset: usize,
    sector_size: usize,
) -> io::Result<Option<FilesystemVolume>> {
    let file = File::open(path)?;
    // SAFETY: the file is opened read-only and never truncated or
    // written while mapped; the mapping is only read.
    let mmap = unsafe { Mmap::map(&file)? };
    Ok(inspect_filesystem_bytes(&mmap[..], offset, sector_size))
}

pub fn inspect_disk_bytes(data: &[u8], path: String, sector_size: usize) -> DiskLayoutReport {
    let sector_size = sector_size.max(1);
    let mut report = DiskLayoutReport {
        path,
        size: data.len() as u64,
        sector_size,
        scheme: None,
        standalone_filesystem: None,
        partitions: Vec::new(),
        notes: Vec::new(),
    };

    if let Some(mbr) = parse_mbr(data, sector_size) {
        if mbr.protective_gpt {
            if let Some(gpt_partitions) = parse_gpt(data, sector_size) {
                report.scheme = Some("GPT".to_string());
                report.partitions = gpt_partitions;
            } else {
                report.scheme = Some("Protective MBR".to_string());
                report.notes.push(
                    "Protective MBR was present but the GPT header or entries could not be parsed."
                        .to_string(),
                );
            }
        } else if !mbr.partitions.is_empty() {
            report.scheme = Some("MBR".to_string());
            report.partitions = mbr.partitions;
        } else {
            report.scheme = Some("MBR Boot Sector".to_string());
        }
    }

    if report.partitions.is_empty() {
        report.standalone_filesystem = inspect_filesystem_at(data, 0, sector_size);
    }

    report
}

pub fn inspect_filesystem_bytes(
    data: &[u8],
    offset: usize,
    sector_size: usize,
) -> Option<FilesystemVolume> {
    inspect_filesystem_at(data, offset, sector_size)
}

pub fn print_disk_layout(report: &DiskLayoutReport) {
    safe_println!(
        "{}",
        format!(
            "[DISK] {} | {} bytes | sector {}",
            report.path, report.size, report.sector_size
        )
        .cyan()
    );

    if let Some(scheme) = &report.scheme {
        safe_println!("{}", format!("[LAYOUT] {}", scheme).blue());
    } else {
        safe_println!("{}", "[LAYOUT] no partition table detected".blue());
    }

    if let Some(filesystem) = &report.standalone_filesystem {
        safe_println!("{}", "[VOLUME]".cyan());
        print_filesystem(filesystem, "  ");
    }

    if !report.partitions.is_empty() {
        safe_println!("{}", "[PARTITIONS]".cyan());
        for partition in &report.partitions {
            safe_println!(
                "  [{}] {} | start LBA {} | {} bytes | {}",
                partition.index,
                partition.partition_type.yellow(),
                partition.start_lba,
                partition.length_bytes,
                partition.name.as_deref().unwrap_or("-")
            );
            safe_println!(
                "      offset 0x{:X} | sectors {}{}{}",
                partition.start_offset,
                partition.sectors,
                partition
                    .type_code
                    .as_ref()
                    .map(|value| format!(" | type {}", value))
                    .unwrap_or_default(),
                partition
                    .guid_type
                    .as_ref()
                    .map(|value| format!(" | guid {}", value))
                    .unwrap_or_default()
            );
            if let Some(filesystem) = &partition.filesystem {
                print_filesystem(filesystem, "      ");
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

pub fn print_filesystem(filesystem: &FilesystemVolume, indent: &str) {
    safe_println!(
        "{}[FS] {} -> {}",
        indent,
        filesystem.kind.green(),
        filesystem.summary.white()
    );
    for (key, value) in &filesystem.details {
        safe_println!("{}  {}: {}", indent, key.yellow(), value);
    }
}

pub(crate) fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn le_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

pub(crate) fn be_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn be_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn be_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

pub(crate) fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return "invalid".to_string();
    }

    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

pub(crate) fn decode_gpt_name(bytes: &[u8]) -> Option<String> {
    let mut values = Vec::new();
    for chunk in bytes.as_chunks::<2>().0 {
        let value = u16::from_le_bytes([chunk[0], chunk[1]]);
        if value == 0 {
            break;
        }
        values.push(value);
    }
    String::from_utf16(&values)
        .ok()
        .filter(|value| !value.is_empty())
}

pub(crate) fn decode_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .filter(|byte| byte.is_ascii_graphic() || *byte == b' ')
        .map(char::from)
        .collect()
}

pub(crate) fn mbr_partition_type_name(value: u8) -> &'static str {
    match value {
        0x01 => "FAT12",
        0x04 | 0x06 | 0x0E => "FAT16",
        0x07 => "NTFS/exFAT/HPFS",
        0x0B | 0x0C => "FAT32",
        0x82 => "Linux swap",
        0x83 => "Linux filesystem",
        0x8E => "Linux LVM",
        0xAF => "Apple HFS/HFS+",
        0xEE => "GPT Protective",
        0xEF => "EFI System Partition",
        _ => "Unknown partition",
    }
}

pub(crate) fn gpt_partition_type_name(guid: &str) -> &'static str {
    match guid {
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI System Partition",
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft Reserved",
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Microsoft Basic Data",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux Filesystem",
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux Swap",
        "21686148-6449-6E6F-744E-656564454649" => "BIOS Boot Partition",
        "48465300-0000-11AA-AA11-00306543ECAC" => "Apple HFS+",
        "7C3457EF-0000-11AA-AA11-00306543ECAC" => "Apple APFS",
        _ => "GPT Partition",
    }
}

mod fingerprint;
mod layout;

pub(crate) use fingerprint::*;
pub(crate) use layout::*;

#[cfg(test)]
#[path = "disk/disk_tests.rs"]
mod disk_tests;
