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

struct MbrLayout {
    partitions: Vec<PartitionRecord>,
    protective_gpt: bool,
}

fn parse_mbr(data: &[u8], sector_size: usize) -> Option<MbrLayout> {
    if data.len() < 512 || data.get(510..512) != Some(&[0x55, 0xAA]) {
        return None;
    }

    let mut partitions = Vec::new();
    let mut protective_gpt = false;

    for index in 0..4 {
        let entry_offset = 446 + index * 16;
        let entry = data.get(entry_offset..entry_offset + 16)?;
        let type_code = entry[4];
        let start_lba = le_u32(entry, 8)? as u64;
        let sectors = le_u32(entry, 12)? as u64;

        if type_code == 0 || sectors == 0 {
            continue;
        }

        if type_code == 0xEE {
            protective_gpt = true;
            continue;
        }

        let start_offset = start_lba.saturating_mul(sector_size as u64);
        let filesystem = inspect_filesystem_at(data, start_offset as usize, sector_size);
        partitions.push(PartitionRecord {
            index: index + 1,
            bootable: entry[0] == 0x80,
            partition_type: mbr_partition_type_name(type_code).to_string(),
            type_code: Some(format!("0x{:02X}", type_code)),
            guid_type: None,
            name: None,
            start_lba,
            sectors,
            start_offset,
            length_bytes: sectors.saturating_mul(sector_size as u64),
            filesystem,
        });
    }

    Some(MbrLayout {
        partitions,
        protective_gpt,
    })
}

fn parse_gpt(data: &[u8], sector_size: usize) -> Option<Vec<PartitionRecord>> {
    let header_offset = sector_size;
    let header = data.get(header_offset..header_offset + 92)?;
    if &header[..8] != b"EFI PART" {
        return None;
    }

    let entry_start_lba = le_u64(header, 72)?;
    let entry_count = le_u32(header, 80)? as usize;
    let entry_size = le_u32(header, 84)? as usize;
    if entry_size < 128 {
        return None;
    }

    let entry_start = entry_start_lba.checked_mul(sector_size as u64)? as usize;
    let mut partitions = Vec::new();
    let max_entries = entry_count.min(128);

    for index in 0..max_entries {
        let offset = entry_start.checked_add(index.checked_mul(entry_size)?)?;
        let entry = data.get(offset..offset + entry_size)?;
        if entry[..16].iter().all(|byte| *byte == 0) {
            continue;
        }

        let type_guid = format_guid(&entry[..16]);
        let start_lba = le_u64(entry, 32)?;
        let end_lba = le_u64(entry, 40)?;
        if end_lba < start_lba {
            continue;
        }
        let sectors = end_lba - start_lba + 1;
        let start_offset = start_lba.saturating_mul(sector_size as u64);
        let filesystem = inspect_filesystem_at(data, start_offset as usize, sector_size);
        partitions.push(PartitionRecord {
            index: partitions.len() + 1,
            bootable: false,
            partition_type: gpt_partition_type_name(&type_guid).to_string(),
            type_code: None,
            guid_type: Some(type_guid),
            name: decode_gpt_name(&entry[56..128]),
            start_lba,
            sectors,
            start_offset,
            length_bytes: sectors.saturating_mul(sector_size as u64),
            filesystem,
        });
    }

    Some(partitions)
}

fn inspect_filesystem_at(
    data: &[u8],
    base_offset: usize,
    sector_size: usize,
) -> Option<FilesystemVolume> {
    inspect_ntfs(data, base_offset)
        .or_else(|| inspect_refs(data, base_offset))
        .or_else(|| inspect_btrfs(data, base_offset))
        .or_else(|| inspect_exfat(data, base_offset))
        .or_else(|| inspect_fat(data, base_offset))
        .or_else(|| inspect_xfs(data, base_offset))
        .or_else(|| inspect_f2fs(data, base_offset))
        .or_else(|| inspect_hfs_plus(data, base_offset))
        .or_else(|| inspect_apfs(data, base_offset))
        .or_else(|| inspect_jfs(data, base_offset))
        .or_else(|| inspect_reiserfs(data, base_offset))
        .or_else(|| inspect_iso9660(data, base_offset))
        .or_else(|| inspect_udf(data, base_offset))
        .or_else(|| inspect_swap(data, base_offset))
        .or_else(|| inspect_ext(data, base_offset, sector_size))
}

fn inspect_ntfs(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let boot = data.get(base..base + 512)?;
    if boot.get(3..11)? != b"NTFS    " {
        return None;
    }

    let bytes_per_sector = le_u16(boot, 11)? as u64;
    let sectors_per_cluster = boot[13] as u64;
    let total_sectors = le_u64(boot, 40)?;
    let mft_cluster = le_u64(boot, 48)?;
    let serial = le_u64(boot, 72)?;

    let mut details = BTreeMap::new();
    details.insert("bytes_per_sector".to_string(), bytes_per_sector.to_string());
    details.insert(
        "sectors_per_cluster".to_string(),
        sectors_per_cluster.to_string(),
    );
    details.insert("total_sectors".to_string(), total_sectors.to_string());
    details.insert("mft_cluster".to_string(), mft_cluster.to_string());
    details.insert("serial".to_string(), format!("0x{:016X}", serial));

    Some(FilesystemVolume {
        kind: "NTFS".to_string(),
        summary: format!(
            "NTFS volume with {}-byte sectors and {} sectors",
            bytes_per_sector, total_sectors
        ),
        details,
    })
}

fn inspect_exfat(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let boot = data.get(base..base + 512)?;
    if boot.get(3..11)? != b"EXFAT   " {
        return None;
    }

    let partition_offset = le_u64(boot, 64)?;
    let volume_length = le_u64(boot, 72)?;
    let fat_offset = le_u32(boot, 80)?;
    let cluster_count = le_u32(boot, 92)?;
    let root_cluster = le_u32(boot, 96)?;
    let serial = le_u32(boot, 100)?;
    let bytes_per_sector = 1u64 << boot[108];
    let sectors_per_cluster = 1u64 << boot[109];

    let mut details = BTreeMap::new();
    details.insert("partition_offset".to_string(), partition_offset.to_string());
    details.insert("volume_length".to_string(), volume_length.to_string());
    details.insert("bytes_per_sector".to_string(), bytes_per_sector.to_string());
    details.insert(
        "sectors_per_cluster".to_string(),
        sectors_per_cluster.to_string(),
    );
    details.insert("fat_offset".to_string(), fat_offset.to_string());
    details.insert("cluster_count".to_string(), cluster_count.to_string());
    details.insert("root_cluster".to_string(), root_cluster.to_string());
    details.insert("serial".to_string(), format!("0x{:08X}", serial));

    Some(FilesystemVolume {
        kind: "exFAT".to_string(),
        summary: format!(
            "exFAT volume with {} clusters and {}-byte sectors",
            cluster_count, bytes_per_sector
        ),
        details,
    })
}

fn inspect_refs(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let boot = data.get(base..base + 512)?;
    if boot.get(3..7)? != b"ReFS" {
        return None;
    }

    let mut details = BTreeMap::new();
    details.insert("signature".to_string(), "ReFS".to_string());
    if let Some(serial) = le_u64(boot, 56) {
        details.insert("serial".to_string(), format!("0x{:016X}", serial));
    }

    Some(FilesystemVolume {
        kind: "ReFS".to_string(),
        summary: "Resilient File System volume".to_string(),
        details,
    })
}

fn inspect_btrfs(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let super_offset = base.checked_add(0x10000)?;
    let superblock = data.get(super_offset..super_offset + 0x200)?;
    if superblock.get(0x40..0x48)? != b"_BHRfS_M" {
        return None;
    }

    let bytenr = le_u64(superblock, 0x30)?;
    let total_bytes = le_u64(superblock, 0x70)?;
    let fsid = superblock
        .get(0x20..0x30)?
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();

    let mut details = BTreeMap::new();
    details.insert("superblock_offset".to_string(), super_offset.to_string());
    details.insert("bytenr".to_string(), bytenr.to_string());
    details.insert("total_bytes".to_string(), total_bytes.to_string());
    details.insert("fsid".to_string(), fsid);

    Some(FilesystemVolume {
        kind: "Btrfs".to_string(),
        summary: format!(
            "Btrfs filesystem with primary superblock at 0x{:X}",
            super_offset
        ),
        details,
    })
}

fn inspect_xfs(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let superblock = data.get(base..base + 512)?;
    if superblock.get(..4)? != b"XFSB" {
        return None;
    }

    let block_size = be_u32(superblock, 4)?;
    let data_blocks = be_u64(superblock, 8)?;
    let mut details = BTreeMap::new();
    details.insert("block_size".to_string(), block_size.to_string());
    details.insert("data_blocks".to_string(), data_blocks.to_string());
    let label = decode_ascii(superblock.get(108..120)?);
    if !label.is_empty() {
        details.insert("label".to_string(), label.clone());
    }

    Some(FilesystemVolume {
        kind: "XFS".to_string(),
        summary: format!(
            "XFS filesystem with {}-byte blocks and {} data blocks",
            block_size, data_blocks
        ),
        details,
    })
}

fn inspect_f2fs(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let super_offset = base.checked_add(1024)?;
    let superblock = data.get(super_offset..super_offset + 512)?;
    if le_u32(superblock, 0)? != 0xF2F52010 {
        return None;
    }

    let log_block_size = le_u32(superblock, 24).unwrap_or(12);
    let block_size = 1u64 << log_block_size;
    let segment_count = le_u32(superblock, 104).unwrap_or(0);
    let mut details = BTreeMap::new();
    details.insert("superblock_offset".to_string(), super_offset.to_string());
    details.insert("block_size".to_string(), block_size.to_string());
    details.insert("segment_count".to_string(), segment_count.to_string());

    Some(FilesystemVolume {
        kind: "F2FS".to_string(),
        summary: format!(
            "F2FS filesystem with {}-byte blocks and {} segments",
            block_size, segment_count
        ),
        details,
    })
}

fn inspect_fat(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let boot = data.get(base..base + 512)?;
    let fat_hint = if boot.get(82..90) == Some(b"FAT32   ") {
        Some("FAT32")
    } else if boot.get(54..62) == Some(b"FAT16   ") {
        Some("FAT16")
    } else if boot.get(54..62) == Some(b"FAT12   ") {
        Some("FAT12")
    } else {
        None
    }?;

    let bytes_per_sector = le_u16(boot, 11)? as u64;
    let sectors_per_cluster = boot[13] as u64;
    let reserved = le_u16(boot, 14)? as u64;
    let fats = boot[16] as u64;
    let total_sectors = {
        let short = le_u16(boot, 19)? as u64;
        if short == 0 {
            le_u32(boot, 32)? as u64
        } else {
            short
        }
    };
    let sectors_per_fat = if fat_hint == "FAT32" {
        le_u32(boot, 36)? as u64
    } else {
        le_u16(boot, 22)? as u64
    };

    let mut details = BTreeMap::new();
    details.insert("bytes_per_sector".to_string(), bytes_per_sector.to_string());
    details.insert(
        "sectors_per_cluster".to_string(),
        sectors_per_cluster.to_string(),
    );
    details.insert("reserved_sectors".to_string(), reserved.to_string());
    details.insert("fat_count".to_string(), fats.to_string());
    details.insert("total_sectors".to_string(), total_sectors.to_string());
    details.insert("sectors_per_fat".to_string(), sectors_per_fat.to_string());
    if fat_hint == "FAT32" {
        details.insert("root_cluster".to_string(), le_u32(boot, 44)?.to_string());
    }

    Some(FilesystemVolume {
        kind: fat_hint.to_string(),
        summary: format!(
            "{} volume with {} sectors and {}-byte sectors",
            fat_hint, total_sectors, bytes_per_sector
        ),
        details,
    })
}

fn inspect_ext(data: &[u8], base: usize, sector_size: usize) -> Option<FilesystemVolume> {
    let super_offset = base.checked_add(1024)?;
    let superblock = data.get(super_offset..super_offset + 0x100)?;
    if le_u16(superblock, 56)? != 0xEF53 {
        return None;
    }

    let blocks_count = le_u32(superblock, 4)? as u64;
    let log_block_size = le_u32(superblock, 24)?;
    let block_size = 1024u64.checked_shl(log_block_size)?;
    let blocks_per_group = le_u32(superblock, 32)? as u64;
    let inodes_per_group = le_u32(superblock, 40)? as u64;
    let features_compat = le_u32(superblock, 92)?;
    let features_incompat = le_u32(superblock, 96)?;
    let volume_name = decode_ascii(superblock.get(120..136)?);

    let kind = if features_incompat & 0x40 != 0 {
        "ext4"
    } else if features_compat & 0x4 != 0 {
        "ext3"
    } else {
        "ext2"
    };

    let mut details = BTreeMap::new();
    details.insert("block_size".to_string(), block_size.to_string());
    details.insert("blocks".to_string(), blocks_count.to_string());
    details.insert("blocks_per_group".to_string(), blocks_per_group.to_string());
    details.insert("inodes_per_group".to_string(), inodes_per_group.to_string());
    details.insert("superblock_offset".to_string(), super_offset.to_string());
    details.insert("sector_size".to_string(), sector_size.to_string());
    if !volume_name.is_empty() {
        details.insert("volume_name".to_string(), volume_name.clone());
    }

    Some(FilesystemVolume {
        kind: kind.to_string(),
        summary: format!(
            "{} filesystem with {}-byte blocks and {} blocks",
            kind, block_size, blocks_count
        ),
        details,
    })
}

fn inspect_hfs_plus(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let header_offset = base.checked_add(1024)?;
    let header = data.get(header_offset..header_offset + 512)?;
    let signature = be_u16(header, 0)?;
    if signature != 0x482B && signature != 0x4858 {
        return None;
    }

    let block_size = be_u32(header, 40)?;
    let total_blocks = be_u32(header, 44)?;
    let mut details = BTreeMap::new();
    details.insert("header_offset".to_string(), header_offset.to_string());
    details.insert("block_size".to_string(), block_size.to_string());
    details.insert("total_blocks".to_string(), total_blocks.to_string());

    Some(FilesystemVolume {
        kind: "HFS+".to_string(),
        summary: format!(
            "HFS+ volume with {}-byte blocks and {} blocks",
            block_size, total_blocks
        ),
        details,
    })
}

fn inspect_apfs(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let superblock = data.get(base..base + 512)?;
    if superblock.get(32..36)? != b"NXSB" {
        return None;
    }

    let block_size = le_u32(superblock, 36)?;
    let block_count = le_u64(superblock, 40)?;
    let mut details = BTreeMap::new();
    details.insert("block_size".to_string(), block_size.to_string());
    details.insert("block_count".to_string(), block_count.to_string());

    Some(FilesystemVolume {
        kind: "APFS".to_string(),
        summary: format!(
            "APFS container with {}-byte blocks and {} blocks",
            block_size, block_count
        ),
        details,
    })
}

fn inspect_jfs(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let super_offset = base.checked_add(32768)?;
    let superblock = data.get(super_offset..super_offset + 4096)?;
    if superblock.get(..4)? != b"JFS1" {
        return None;
    }

    let block_size = le_u32(superblock, 24).unwrap_or(0);
    let mut details = BTreeMap::new();
    details.insert("superblock_offset".to_string(), super_offset.to_string());
    if block_size != 0 {
        details.insert("block_size".to_string(), block_size.to_string());
    }

    Some(FilesystemVolume {
        kind: "JFS".to_string(),
        summary: "JFS filesystem".to_string(),
        details,
    })
}

fn inspect_reiserfs(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    for candidate in [base.checked_add(65536)?, base.checked_add(8192)?] {
        let superblock = data.get(candidate..candidate + 128)?;
        let magic = superblock.get(52..64)?;
        if magic.starts_with(b"ReIsEr") {
            let block_size = le_u32(superblock, 44).unwrap_or(0);
            let mut details = BTreeMap::new();
            details.insert("superblock_offset".to_string(), candidate.to_string());
            if block_size != 0 {
                details.insert("block_size".to_string(), block_size.to_string());
            }
            return Some(FilesystemVolume {
                kind: "ReiserFS".to_string(),
                summary: "ReiserFS filesystem".to_string(),
                details,
            });
        }
    }
    None
}

fn inspect_iso9660(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let vd_offset = base.checked_add(16 * 2048)?;
    let descriptor = data.get(vd_offset..vd_offset + 2048)?;
    if descriptor.get(1..6)? != b"CD001" {
        return None;
    }

    let system_id = decode_ascii(descriptor.get(8..40)?);
    let volume_id = decode_ascii(descriptor.get(40..72)?);
    let mut details = BTreeMap::new();
    if !system_id.is_empty() {
        details.insert("system_id".to_string(), system_id);
    }
    if !volume_id.is_empty() {
        details.insert("volume_id".to_string(), volume_id.clone());
    }

    Some(FilesystemVolume {
        kind: "ISO9660".to_string(),
        summary: format!(
            "ISO 9660 optical image{}",
            if volume_id.is_empty() {
                "".to_string()
            } else {
                format!(" ({})", volume_id)
            }
        ),
        details,
    })
}

fn inspect_udf(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let start = base.checked_add(16 * 2048)?;
    let end = base
        .checked_add(512 * 2048)
        .unwrap_or(data.len())
        .min(data.len());

    for offset in (start..end).step_by(2048) {
        let descriptor = data.get(offset..offset + 2048)?;
        let ident = descriptor.get(1..6)?;
        if ident == b"NSR02" || ident == b"NSR03" {
            let mut details = BTreeMap::new();
            details.insert("descriptor_offset".to_string(), offset.to_string());
            details.insert(
                "revision".to_string(),
                String::from_utf8_lossy(ident).to_string(),
            );
            return Some(FilesystemVolume {
                kind: "UDF".to_string(),
                summary: "Universal Disk Format image".to_string(),
                details,
            });
        }
    }

    None
}

fn inspect_swap(data: &[u8], base: usize) -> Option<FilesystemVolume> {
    let header = data.get(base..base + 4096)?;
    let signature = header.get(4086..4096)?;
    let signature = if signature == b"SWAPSPACE2" {
        "SWAPSPACE2"
    } else if signature == b"SWAP-SPACE" {
        "SWAP-SPACE"
    } else {
        return None;
    };

    let mut details = BTreeMap::new();
    details.insert("header_page_size".to_string(), "4096".to_string());
    details.insert("signature".to_string(), signature.to_string());

    Some(FilesystemVolume {
        kind: "swap".to_string(),
        summary: "Linux swap area".to_string(),
        details,
    })
}

fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn be_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn be_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn be_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn format_guid(bytes: &[u8]) -> String {
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

fn decode_gpt_name(bytes: &[u8]) -> Option<String> {
    let mut values = Vec::new();
    for chunk in bytes.chunks_exact(2) {
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

fn decode_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .filter(|byte| byte.is_ascii_graphic() || *byte == b' ')
        .map(char::from)
        .collect()
}

fn mbr_partition_type_name(value: u8) -> &'static str {
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

fn gpt_partition_type_name(guid: &str) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::{inspect_disk_bytes, inspect_filesystem_bytes};

    #[test]
    fn parses_mbr_with_fat32_partition() {
        let mut data = vec![0u8; 4096];
        data[510] = 0x55;
        data[511] = 0xAA;
        data[446] = 0x80;
        data[450] = 0x0C;
        data[454..458].copy_from_slice(&1u32.to_le_bytes());
        data[458..462].copy_from_slice(&100u32.to_le_bytes());

        let boot = 512usize;
        data[boot + 11..boot + 13].copy_from_slice(&512u16.to_le_bytes());
        data[boot + 13] = 8;
        data[boot + 14..boot + 16].copy_from_slice(&32u16.to_le_bytes());
        data[boot + 16] = 2;
        data[boot + 32..boot + 36].copy_from_slice(&100u32.to_le_bytes());
        data[boot + 36..boot + 40].copy_from_slice(&16u32.to_le_bytes());
        data[boot + 44..boot + 48].copy_from_slice(&2u32.to_le_bytes());
        data[boot + 82..boot + 90].copy_from_slice(b"FAT32   ");

        let report = inspect_disk_bytes(&data, "mbr.img".to_string(), 512);
        assert_eq!(report.scheme.as_deref(), Some("MBR"));
        assert_eq!(report.partitions.len(), 1);
        assert_eq!(
            report.partitions[0].filesystem.as_ref().unwrap().kind,
            "FAT32"
        );
    }

    #[test]
    fn parses_gpt_with_ntfs_partition() {
        let mut data = vec![0u8; 40 * 512 + 512];
        data[510] = 0x55;
        data[511] = 0xAA;
        data[450] = 0xEE;
        data[454..458].copy_from_slice(&1u32.to_le_bytes());
        data[458..462].copy_from_slice(&400u32.to_le_bytes());

        let header = 512usize;
        data[header..header + 8].copy_from_slice(b"EFI PART");
        data[header + 72..header + 80].copy_from_slice(&2u64.to_le_bytes());
        data[header + 80..header + 84].copy_from_slice(&1u32.to_le_bytes());
        data[header + 84..header + 88].copy_from_slice(&128u32.to_le_bytes());

        let entry = 1024usize;
        data[entry..entry + 16].copy_from_slice(&[
            0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26,
            0x99, 0xC7,
        ]);
        data[entry + 32..entry + 40].copy_from_slice(&40u64.to_le_bytes());
        data[entry + 40..entry + 48].copy_from_slice(&80u64.to_le_bytes());
        let name: Vec<u8> = "DATA"
            .encode_utf16()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        data[entry + 56..entry + 56 + name.len()].copy_from_slice(&name);

        let boot = 40 * 512;
        data[boot + 3..boot + 11].copy_from_slice(b"NTFS    ");
        data[boot + 11..boot + 13].copy_from_slice(&512u16.to_le_bytes());
        data[boot + 13] = 8;
        data[boot + 40..boot + 48].copy_from_slice(&2048u64.to_le_bytes());
        data[boot + 48..boot + 56].copy_from_slice(&4u64.to_le_bytes());
        data[boot + 72..boot + 80].copy_from_slice(&0x12345678ABCDEF00u64.to_le_bytes());

        let report = inspect_disk_bytes(&data, "gpt.img".to_string(), 512);
        assert_eq!(report.scheme.as_deref(), Some("GPT"));
        assert_eq!(report.partitions.len(), 1);
        assert_eq!(report.partitions[0].name.as_deref(), Some("DATA"));
        assert_eq!(
            report.partitions[0].filesystem.as_ref().unwrap().kind,
            "NTFS"
        );
    }

    #[test]
    fn detects_standalone_ext_volume() {
        let mut data = vec![0u8; 4096];
        let super_offset = 1024usize;
        data[super_offset + 4..super_offset + 8].copy_from_slice(&8192u32.to_le_bytes());
        data[super_offset + 24..super_offset + 28].copy_from_slice(&2u32.to_le_bytes());
        data[super_offset + 32..super_offset + 36].copy_from_slice(&32768u32.to_le_bytes());
        data[super_offset + 40..super_offset + 44].copy_from_slice(&8192u32.to_le_bytes());
        data[super_offset + 56..super_offset + 58].copy_from_slice(&0xEF53u16.to_le_bytes());
        data[super_offset + 96..super_offset + 100].copy_from_slice(&0x40u32.to_le_bytes());
        data[super_offset + 120..super_offset + 128].copy_from_slice(b"evidence");

        let report = inspect_disk_bytes(&data, "ext.img".to_string(), 512);
        assert!(report.partitions.is_empty());
        assert_eq!(report.standalone_filesystem.as_ref().unwrap().kind, "ext4");
    }

    #[test]
    fn detects_standalone_btrfs_volume() {
        let mut data = vec![0u8; 0x12000];
        let super_offset = 0x10000usize;
        data[super_offset + 0x20..super_offset + 0x30].copy_from_slice(&[0x11; 16]);
        data[super_offset + 0x30..super_offset + 0x38].copy_from_slice(&(0x10000u64).to_le_bytes());
        data[super_offset + 0x40..super_offset + 0x48].copy_from_slice(b"_BHRfS_M");
        data[super_offset + 0x70..super_offset + 0x78]
            .copy_from_slice(&(8 * 1024 * 1024u64).to_le_bytes());

        let report = inspect_disk_bytes(&data, "btrfs.img".to_string(), 512);
        assert!(report.partitions.is_empty());
        assert_eq!(report.standalone_filesystem.as_ref().unwrap().kind, "Btrfs");
    }

    #[test]
    fn detects_standalone_swap_area() {
        let mut data = vec![0u8; 8192];
        data[4086..4096].copy_from_slice(b"SWAPSPACE2");

        let report = inspect_disk_bytes(&data, "swap.img".to_string(), 512);
        assert!(report.partitions.is_empty());
        assert_eq!(report.standalone_filesystem.as_ref().unwrap().kind, "swap");
    }

    #[test]
    fn detects_refs_signature() {
        let mut data = vec![0u8; 4096];
        data[3..7].copy_from_slice(b"ReFS");
        data[56..64].copy_from_slice(&0x1234_5678_90AB_CDEFu64.to_le_bytes());

        let filesystem = inspect_filesystem_bytes(&data, 0, 512).unwrap();
        assert_eq!(filesystem.kind, "ReFS");
    }

    #[test]
    fn detects_xfs_signature() {
        let mut data = vec![0u8; 4096];
        data[..4].copy_from_slice(b"XFSB");
        data[4..8].copy_from_slice(&4096u32.to_be_bytes());
        data[8..16].copy_from_slice(&1024u64.to_be_bytes());
        data[108..113].copy_from_slice(b"DATA ");

        let filesystem = inspect_filesystem_bytes(&data, 0, 512).unwrap();
        assert_eq!(filesystem.kind, "XFS");
    }

    #[test]
    fn detects_f2fs_signature() {
        let mut data = vec![0u8; 4096];
        let super_offset = 1024usize;
        data[super_offset..super_offset + 4].copy_from_slice(&0xF2F52010u32.to_le_bytes());
        data[super_offset + 24..super_offset + 28].copy_from_slice(&12u32.to_le_bytes());
        data[super_offset + 104..super_offset + 108].copy_from_slice(&64u32.to_le_bytes());

        let filesystem = inspect_filesystem_bytes(&data, 0, 512).unwrap();
        assert_eq!(filesystem.kind, "F2FS");
    }

    #[test]
    fn detects_hfs_plus_signature() {
        let mut data = vec![0u8; 4096];
        let header_offset = 1024usize;
        data[header_offset..header_offset + 2].copy_from_slice(&0x482Bu16.to_be_bytes());
        data[header_offset + 40..header_offset + 44].copy_from_slice(&4096u32.to_be_bytes());
        data[header_offset + 44..header_offset + 48].copy_from_slice(&2048u32.to_be_bytes());

        let filesystem = inspect_filesystem_bytes(&data, 0, 512).unwrap();
        assert_eq!(filesystem.kind, "HFS+");
    }

    #[test]
    fn detects_apfs_signature() {
        let mut data = vec![0u8; 4096];
        data[32..36].copy_from_slice(b"NXSB");
        data[36..40].copy_from_slice(&4096u32.to_le_bytes());
        data[40..48].copy_from_slice(&8192u64.to_le_bytes());

        let filesystem = inspect_filesystem_bytes(&data, 0, 512).unwrap();
        assert_eq!(filesystem.kind, "APFS");
    }

    #[test]
    fn detects_optical_filesystem_signatures() {
        let mut iso = vec![0u8; 18 * 2048];
        let vd = 16 * 2048;
        iso[vd + 1..vd + 6].copy_from_slice(b"CD001");
        iso[vd + 40..vd + 46].copy_from_slice(b"DISC01");
        assert_eq!(
            inspect_filesystem_bytes(&iso, 0, 512).unwrap().kind,
            "ISO9660"
        );

        let mut udf = vec![0u8; 24 * 2048];
        let descriptor = 20 * 2048;
        udf[descriptor + 1..descriptor + 6].copy_from_slice(b"NSR02");
        assert_eq!(inspect_filesystem_bytes(&udf, 0, 512).unwrap().kind, "UDF");
    }
}
