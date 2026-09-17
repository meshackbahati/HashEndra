use super::{ExtJournalSummary, GroupDesc, InodeRecord, Superblock};
use super::{be_u32, decode_ascii, le_u16, le_u32};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;

pub(crate) fn parse_superblock(data: &[u8], volume_offset: usize) -> Option<Superblock> {
    let super_offset = volume_offset.checked_add(1024)?;
    let sb = data.get(super_offset..super_offset + 1024)?;
    if le_u16(sb, 0x38)? != 0xEF53 {
        return None;
    }

    let blocks_count_lo = le_u32(sb, 0x04)? as u64;
    let first_data_block = le_u32(sb, 0x14)?;
    let log_block_size = le_u32(sb, 0x18)?;
    let block_size = 1024u64.checked_shl(log_block_size)?;
    let blocks_count_hi = le_u32(sb, 0x150).unwrap_or(0) as u64;
    let blocks_count = blocks_count_lo | (blocks_count_hi << 32);
    let inodes_count = le_u32(sb, 0x00)?;
    let blocks_per_group = le_u32(sb, 0x20)?;
    let inodes_per_group = le_u32(sb, 0x28)?;
    let inode_size = le_u16(sb, 0x58).unwrap_or(128);
    let feature_compat = le_u32(sb, 0x5C).unwrap_or(0);
    let feature_incompat = le_u32(sb, 0x60).unwrap_or(0);
    let desc_size = if feature_incompat & 0x80 != 0 {
        le_u16(sb, 0xFE).unwrap_or(64).max(32)
    } else {
        32
    };
    let volume_name = decode_ascii(sb.get(0x78..0x88)?);
    let kind = if feature_incompat & 0x40 != 0 {
        "ext4"
    } else if feature_compat & 0x4 != 0 {
        "ext3"
    } else {
        "ext2"
    };
    let journal_inode = (feature_compat & 0x4 != 0).then_some(le_u32(sb, 0xE0).unwrap_or(8));

    Some(Superblock {
        kind: kind.to_string(),
        block_size,
        blocks_count,
        inodes_count,
        blocks_per_group,
        inodes_per_group,
        inode_size,
        descriptor_size: desc_size,
        first_data_block,
        journal_inode,
        volume_name: (!volume_name.is_empty()).then_some(volume_name),
    })
}

pub(crate) fn parse_group_descriptors(
    data: &[u8],
    volume_offset: usize,
    superblock: &Superblock,
) -> Option<Vec<GroupDesc>> {
    let groups = superblock
        .blocks_count
        .div_ceil(superblock.blocks_per_group as u64)
        .max(1) as usize;
    let table_block = if superblock.block_size == 1024 { 2 } else { 1 };
    let table_offset = volume_offset.checked_add(table_block * superblock.block_size as usize)?;

    let mut descriptors = Vec::with_capacity(groups);
    for index in 0..groups {
        let entry_offset = table_offset.checked_add(index * superblock.descriptor_size as usize)?;
        let entry = data.get(entry_offset..entry_offset + superblock.descriptor_size as usize)?;
        let low = le_u32(entry, 0x08)? as u64;
        let high = if superblock.descriptor_size >= 64 {
            le_u32(entry, 0x28).unwrap_or(0) as u64
        } else {
            0
        };
        descriptors.push(GroupDesc {
            inode_table_block: low | (high << 32),
        });
    }

    Some(descriptors)
}

pub(crate) fn read_inode_record(
    data: &[u8],
    volume_offset: usize,
    superblock: &Superblock,
    groups: &[GroupDesc],
    inode: u32,
) -> Option<InodeRecord> {
    if inode == 0 {
        return None;
    }
    let index = inode - 1;
    let group_index = (index / superblock.inodes_per_group) as usize;
    let inode_index = index % superblock.inodes_per_group;
    let group = groups.get(group_index)?;
    let table_offset =
        volume_offset.checked_add((group.inode_table_block * superblock.block_size) as usize)?;
    let inode_offset =
        table_offset.checked_add(inode_index as usize * superblock.inode_size as usize)?;
    let raw = data.get(inode_offset..inode_offset + superblock.inode_size as usize)?;

    let mode = le_u16(raw, 0x00)?;
    if mode == 0 {
        return None;
    }
    let size_lo = le_u32(raw, 0x04)? as u64;
    let size_high = le_u32(raw, 0x6C).unwrap_or(0) as u64;
    let size = size_lo | (size_high << 32);
    let dtime = le_u32(raw, 0x14).unwrap_or(0);
    let links_count = le_u16(raw, 0x1A).unwrap_or(0);
    let flags = le_u32(raw, 0x20).unwrap_or(0);
    let i_block = raw.get(0x28..0x64)?;
    let directory = mode & 0xF000 == 0x4000;
    let regular = mode & 0xF000 == 0x8000;
    let (blocks, storage, recovery_note) = if regular || directory {
        if flags & 0x80000 != 0 {
            match parse_extent_bytes(data, volume_offset, superblock.block_size, i_block, 0) {
                Ok(blocks) => (blocks, "extents".to_string(), None),
                Err(error) => (Vec::new(), "extents".to_string(), Some(error)),
            }
        } else {
            let blocks = parse_block_map(data, volume_offset, superblock.block_size, i_block);
            (blocks, "block-map".to_string(), None)
        }
    } else {
        (Vec::new(), "inode".to_string(), None)
    };

    Some(InodeRecord {
        inode,
        mode,
        size,
        links_count,
        dtime,
        blocks,
        storage,
        directory,
        regular,
        recovery_note,
    })
}

fn parse_extent_bytes(
    data: &[u8],
    volume_offset: usize,
    block_size: u64,
    node: &[u8],
    depth_hint: u16,
) -> Result<Vec<u64>, String> {
    if node.len() < 12 {
        return Err("extent header is truncated".to_string());
    }
    let magic = le_u16(node, 0).ok_or_else(|| "extent header missing magic".to_string())?;
    if magic != 0xF30A {
        return Err("extent magic was not present".to_string());
    }
    let entries = le_u16(node, 2).unwrap_or(0) as usize;
    let depth = if depth_hint == 0 {
        le_u16(node, 6).unwrap_or(0)
    } else {
        depth_hint
    };
    let mut blocks = Vec::new();

    if depth == 0 {
        for index in 0..entries {
            let offset = 12 + index * 12;
            let entry = node
                .get(offset..offset + 12)
                .ok_or_else(|| "extent entry was truncated".to_string())?;
            let len = le_u16(entry, 4).unwrap_or(0);
            let initialized_len = (len & 0x7FFF) as u64;
            let start =
                (le_u16(entry, 6).unwrap_or(0) as u64) << 32 | le_u32(entry, 8).unwrap_or(0) as u64;
            for block in 0..initialized_len {
                blocks.push(start.saturating_add(block));
            }
        }
        return Ok(blocks);
    }

    for index in 0..entries {
        let offset = 12 + index * 12;
        let entry = node
            .get(offset..offset + 12)
            .ok_or_else(|| "extent index entry was truncated".to_string())?;
        let leaf_block =
            (le_u16(entry, 8).unwrap_or(0) as u64) << 32 | le_u32(entry, 4).unwrap_or(0) as u64;
        let child_offset = volume_offset
            .checked_add((leaf_block * block_size) as usize)
            .ok_or_else(|| "extent child offset overflowed".to_string())?;
        let child = data
            .get(child_offset..child_offset + block_size as usize)
            .ok_or_else(|| "extent child block fell outside the image".to_string())?;
        blocks.extend(parse_extent_bytes(
            data,
            volume_offset,
            block_size,
            child,
            depth - 1,
        )?);
    }

    Ok(blocks)
}

fn parse_block_map(data: &[u8], volume_offset: usize, block_size: u64, i_block: &[u8]) -> Vec<u64> {
    let mut blocks = Vec::new();
    for slot in 0..12 {
        let pointer = le_u32(i_block, slot * 4).unwrap_or(0) as u64;
        if pointer != 0 {
            blocks.push(pointer);
        }
    }
    for (level, slot) in [(1usize, 12usize), (2, 13), (3, 14)] {
        let pointer = le_u32(i_block, slot * 4).unwrap_or(0) as u64;
        if pointer != 0 {
            gather_indirect_blocks(data, volume_offset, block_size, pointer, level, &mut blocks);
        }
    }
    blocks
}

fn gather_indirect_blocks(
    data: &[u8],
    volume_offset: usize,
    block_size: u64,
    block: u64,
    level: usize,
    out: &mut Vec<u64>,
) {
    let Some(offset) = volume_offset.checked_add((block * block_size) as usize) else {
        return;
    };
    let Some(bytes) = data.get(offset..offset + block_size as usize) else {
        return;
    };
    for slot in 0..(block_size as usize / 4) {
        let pointer = le_u32(bytes, slot * 4).unwrap_or(0) as u64;
        if pointer == 0 {
            continue;
        }
        if level == 1 {
            out.push(pointer);
        } else {
            gather_indirect_blocks(data, volume_offset, block_size, pointer, level - 1, out);
        }
    }
}

pub(crate) fn build_live_path_map(
    data: &[u8],
    volume_offset: usize,
    superblock: &Superblock,
    records: &BTreeMap<u32, InodeRecord>,
) -> BTreeMap<u32, String> {
    let mut paths = BTreeMap::new();
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    queue.push_back((2u32, String::new()));
    visited.insert(2u32);

    while let Some((inode, parent_path)) = queue.pop_front() {
        let Some(record) = records.get(&inode) else {
            continue;
        };
        if !record.directory || record.blocks.is_empty() {
            continue;
        }

        let Ok(bytes) = recover_inode_bytes(data, volume_offset, superblock, record) else {
            continue;
        };
        let mut offset = 0usize;
        while offset + 8 <= bytes.len() {
            let child_inode = le_u32(&bytes, offset).unwrap_or(0);
            let rec_len = le_u16(&bytes, offset + 4).unwrap_or(0) as usize;
            let name_len = *bytes.get(offset + 6).unwrap_or(&0) as usize;
            let file_type = *bytes.get(offset + 7).unwrap_or(&0);
            if rec_len == 0 {
                break;
            }
            if child_inode != 0 && name_len > 0 && offset + rec_len <= bytes.len() {
                let name_bytes =
                    &bytes[offset + 8..offset + 8 + name_len.min(rec_len.saturating_sub(8))];
                let name = String::from_utf8_lossy(name_bytes).to_string();
                if name != "." && name != ".." {
                    let path = if parent_path.is_empty() {
                        name.clone()
                    } else {
                        format!("{}/{}", parent_path, name)
                    };
                    paths.entry(child_inode).or_insert_with(|| path.clone());
                    if file_type == 2 && visited.insert(child_inode) {
                        queue.push_back((child_inode, path));
                    }
                }
            }
            offset += rec_len;
        }
    }

    paths
}

pub(crate) fn summarize_journal(
    data: &[u8],
    volume_offset: usize,
    superblock: &Superblock,
    records: &BTreeMap<u32, InodeRecord>,
) -> Option<ExtJournalSummary> {
    let journal_inode = superblock.journal_inode?;
    let record = records.get(&journal_inode)?;
    let bytes = recover_inode_bytes(data, volume_offset, superblock, record).ok()?;
    let header = bytes.get(..24)?;
    let magic = be_u32(header, 0)?;
    Some(ExtJournalSummary {
        inode: journal_inode,
        bytes: bytes.len() as u64,
        magic: Some(format!("0x{:08X}", magic)),
        block_type: be_u32(header, 4),
        block_size: be_u32(header, 12),
        maxlen: be_u32(header, 16),
        first: be_u32(header, 20),
    })
}

pub(crate) fn recover_inode_bytes(
    data: &[u8],
    volume_offset: usize,
    superblock: &Superblock,
    record: &InodeRecord,
) -> Result<Vec<u8>, io::Error> {
    let size = usize::try_from(record.size).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "inode size exceeds address space",
        )
    })?;
    let mut bytes = Vec::with_capacity(size.min(1024 * 1024));

    for block in &record.blocks {
        if bytes.len() >= size {
            break;
        }
        let offset = volume_offset
            .checked_add((*block * superblock.block_size) as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "block offset overflow"))?;
        let to_copy = (superblock.block_size as usize).min(size - bytes.len());
        let slice = data.get(offset..offset + to_copy).ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "block fell outside the image")
        })?;
        bytes.extend_from_slice(slice);
    }

    bytes.truncate(size);
    Ok(bytes)
}
