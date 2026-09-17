use super::{
    be_u16, be_u32, be_u64, decode_ascii, le_u16, le_u32, le_u64, FilesystemVolume,
};
use std::collections::BTreeMap;

pub(crate) fn inspect_filesystem_at(
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
