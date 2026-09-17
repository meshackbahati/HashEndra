use super::recover::{
    boot_volume_label, cluster_from_entry, decode_short_name, read_cluster, read_fat_entry,
};
use super::{le_u16, le_u32, BootSector, DirSource, FatType, ParsedEntry};
use std::collections::{BTreeSet, VecDeque};
use std::io;

pub(crate) fn parse_boot_sector(data: &[u8], volume_offset: usize) -> Option<BootSector> {
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
        (root_entry_count as u32 * 32).div_ceil(bytes_per_sector as u32);
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

pub(crate) fn collect_entries(
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

        for record in bytes.as_chunks::<32>().0 {
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

pub(crate) fn read_root_directory_bytes(data: &[u8], boot: &BootSector) -> io::Result<Vec<u8>> {
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

pub(crate) fn read_directory_chain(data: &[u8], boot: &BootSector, first_cluster: u32) -> io::Result<Vec<u8>> {
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
