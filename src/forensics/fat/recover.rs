use super::{div_ceil, le_u16, le_u32, BootSector, FatType};
use std::collections::BTreeSet;
use std::io;

pub(crate) fn recover_file_bytes(
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

pub(crate) fn extend_contiguous_deleted_recovery(
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

pub(crate) fn read_cluster<'a>(data: &'a [u8], boot: &BootSector, cluster: u32) -> io::Result<&'a [u8]> {
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

pub(crate) fn read_fat_entry(data: &[u8], boot: &BootSector, cluster: u32) -> Option<u32> {
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

pub(crate) fn cluster_is_free(data: &[u8], boot: &BootSector, cluster: u32) -> bool {
    read_fat_entry(data, boot, cluster) == Some(0)
}

pub(crate) fn cluster_from_entry(record: &[u8]) -> u32 {
    let high = le_u16(record, 20).unwrap_or(0) as u32;
    let low = le_u16(record, 26).unwrap_or(0) as u32;
    (high << 16) | low
}

pub(crate) fn decode_short_name(record: &[u8], deleted: bool) -> String {
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

pub(crate) fn decode_dos_component(bytes: &[u8]) -> String {
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

pub(crate) fn boot_volume_label(boot: &[u8], kind: FatType) -> Option<String> {
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
