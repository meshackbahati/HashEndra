use super::{
    decode_gpt_name, format_guid, gpt_partition_type_name, le_u32, le_u64, mbr_partition_type_name,
    PartitionRecord,
};
use super::fingerprint::inspect_filesystem_at;

pub(crate) struct MbrLayout {
    pub(crate) partitions: Vec<PartitionRecord>,
    pub(crate) protective_gpt: bool,
}

pub(crate) fn parse_mbr(data: &[u8], sector_size: usize) -> Option<MbrLayout> {
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

pub(crate) fn parse_gpt(data: &[u8], sector_size: usize) -> Option<Vec<PartitionRecord>> {
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
