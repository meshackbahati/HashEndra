use crate::safe_println;
use colored::*;
use memmap2::Mmap;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

// safe_println! is defined in utils/io.rs via #[macro_export]

#[derive(Debug, Clone)]
pub struct ExtOptions {
    pub volume_offset: usize,
    pub max_inodes: usize,
    pub deleted_only: bool,
    pub include_directories: bool,
    pub extract_data_to: Option<PathBuf>,
    pub overwrite: bool,
}

impl Default for ExtOptions {
    fn default() -> Self {
        Self {
            volume_offset: 0,
            max_inodes: 256,
            deleted_only: false,
            include_directories: false,
            extract_data_to: None,
            overwrite: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtSuperInfo {
    pub volume_offset: u64,
    pub kind: String,
    pub block_size: u64,
    pub blocks_count: u64,
    pub inodes_count: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub descriptor_size: u16,
    pub first_data_block: u32,
    pub volume_name: Option<String>,
    pub journal_inode: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtEntry {
    pub inode: u32,
    pub deleted: bool,
    pub directory: bool,
    pub file_type: String,
    pub path: Option<String>,
    pub links_count: u16,
    pub dtime: Option<u32>,
    pub size: u64,
    pub storage: String,
    pub block_count: usize,
    pub extracted_path: Option<String>,
    pub recovery_note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtJournalSummary {
    pub inode: u32,
    pub bytes: u64,
    pub magic: Option<String>,
    pub block_type: Option<u32>,
    pub block_size: Option<u32>,
    pub maxlen: Option<u32>,
    pub first: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtReport {
    pub path: String,
    pub superblock: ExtSuperInfo,
    pub scanned_inodes: usize,
    pub returned_entries: usize,
    pub deleted_entries: usize,
    pub recovered_files: usize,
    pub recovered_bytes: u64,
    pub journal: Option<ExtJournalSummary>,
    pub entries: Vec<ExtEntry>,
    pub notes: Vec<String>,
}

#[derive(Clone)]
struct Superblock {
    kind: String,
    block_size: u64,
    blocks_count: u64,
    inodes_count: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    descriptor_size: u16,
    first_data_block: u32,
    journal_inode: Option<u32>,
    volume_name: Option<String>,
}

#[derive(Clone, Copy)]
struct GroupDesc {
    inode_table_block: u64,
}

#[derive(Clone)]
struct InodeRecord {
    inode: u32,
    mode: u16,
    size: u64,
    links_count: u16,
    dtime: u32,
    blocks: Vec<u64>,
    storage: String,
    directory: bool,
    regular: bool,
    recovery_note: Option<String>,
}

pub fn inspect_ext_image(path: &Path, options: &ExtOptions) -> io::Result<ExtReport> {
    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    inspect_ext_bytes(&mmap[..], path.display().to_string(), options)
}

pub fn inspect_ext_bytes(data: &[u8], path: String, options: &ExtOptions) -> io::Result<ExtReport> {
    let superblock = parse_superblock(data, options.volume_offset).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no ext superblock found at the requested offset",
        )
    })?;

    let groups =
        parse_group_descriptors(data, options.volume_offset, &superblock).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "could not parse ext group descriptors",
            )
        })?;

    let mut records = BTreeMap::new();
    let inode_limit = options.max_inodes.min(superblock.inodes_count as usize);
    let mut scanned_inodes = 0usize;
    let mut deleted_entries = 0usize;

    for inode in 1..=inode_limit as u32 {
        let Some(record) =
            read_inode_record(data, options.volume_offset, &superblock, &groups, inode)
        else {
            continue;
        };
        scanned_inodes += 1;
        if record.deleted() {
            deleted_entries += 1;
        }
        records.insert(inode, record);
    }

    let path_map = build_live_path_map(data, options.volume_offset, &superblock, &records);
    let journal = summarize_journal(data, options.volume_offset, &superblock, &records);

    if let Some(dir) = &options.extract_data_to {
        std::fs::create_dir_all(dir)?;
    }

    let mut entries = Vec::new();
    let mut recovered_files = 0usize;
    let mut recovered_bytes = 0u64;

    for record in records.values() {
        if options.deleted_only && !record.deleted() {
            continue;
        }
        if !options.include_directories && record.directory {
            continue;
        }

        let file_type = inode_type_name(record.mode).to_string();
        let mut entry = ExtEntry {
            inode: record.inode,
            deleted: record.deleted(),
            directory: record.directory,
            file_type,
            path: path_map.get(&record.inode).cloned(),
            links_count: record.links_count,
            dtime: (record.dtime != 0).then_some(record.dtime),
            size: record.size,
            storage: record.storage.clone(),
            block_count: record.blocks.len(),
            extracted_path: None,
            recovery_note: record.recovery_note.clone(),
        };

        if let Some(dir) = &options.extract_data_to {
            if record.regular && !record.blocks.is_empty() {
                let bytes = recover_inode_bytes(data, options.volume_offset, &superblock, record)?;
                let written = write_recovered_file(dir, &entry, &bytes, options.overwrite)?;
                entry.extracted_path = Some(written.display().to_string());
                recovered_files += 1;
                recovered_bytes = recovered_bytes.saturating_add(bytes.len() as u64);
            }
        }

        entries.push(entry);
    }

    let mut notes = Vec::new();
    notes.push(
        "Deleted ext-family recovery enumerates inodes directly; deleted names are only shown when they still have live directory references."
            .to_string(),
    );
    notes.push(
        "Regular files recover via extents and direct/indirect block pointers. Inline symlinks and journal replay are not rebuilt yet."
            .to_string(),
    );

    Ok(ExtReport {
        path,
        superblock: ExtSuperInfo {
            volume_offset: options.volume_offset as u64,
            kind: superblock.kind.clone(),
            block_size: superblock.block_size,
            blocks_count: superblock.blocks_count,
            inodes_count: superblock.inodes_count,
            blocks_per_group: superblock.blocks_per_group,
            inodes_per_group: superblock.inodes_per_group,
            inode_size: superblock.inode_size,
            descriptor_size: superblock.descriptor_size,
            first_data_block: superblock.first_data_block,
            volume_name: superblock.volume_name.clone(),
            journal_inode: superblock.journal_inode,
        },
        scanned_inodes,
        returned_entries: entries.len(),
        deleted_entries,
        recovered_files,
        recovered_bytes,
        journal,
        entries,
        notes,
    })
}

pub fn print_ext_report(report: &ExtReport) {
    safe_println!(
        "{}",
        format!(
            "[EXT] {} | volume 0x{:X} | {}",
            report.path, report.superblock.volume_offset, report.superblock.kind
        )
        .cyan()
    );
    safe_println!(
        "{}",
        format!(
            "[SUPER] block {} | blocks {} | inodes {} | inode size {}{}",
            report.superblock.block_size,
            report.superblock.blocks_count,
            report.superblock.inodes_count,
            report.superblock.inode_size,
            report
                .superblock
                .volume_name
                .as_ref()
                .map(|value| format!(" | volume {}", value))
                .unwrap_or_default()
        )
        .blue()
    );
    safe_println!(
        "{}",
        format!(
            "[SUMMARY] scanned {} inode(s), returned {}, deleted {}, recovered {}, bytes {}",
            report.scanned_inodes,
            report.returned_entries,
            report.deleted_entries,
            report.recovered_files,
            report.recovered_bytes
        )
        .cyan()
    );

    if let Some(journal) = &report.journal {
        safe_println!(
            "{}",
            format!(
                "[JOURNAL] inode {} | bytes {}{}{}{}{}",
                journal.inode,
                journal.bytes,
                journal
                    .magic
                    .as_ref()
                    .map(|value| format!(" | magic {}", value))
                    .unwrap_or_default(),
                journal
                    .block_type
                    .map(|value| format!(" | type {}", value))
                    .unwrap_or_default(),
                journal
                    .block_size
                    .map(|value| format!(" | block {}", value))
                    .unwrap_or_default(),
                journal
                    .maxlen
                    .map(|value| format!(" | maxlen {}", value))
                    .unwrap_or_default()
            )
            .cyan()
        );
    }

    if !report.entries.is_empty() {
        safe_println!("{}", "[ENTRIES]".cyan());
        for entry in &report.entries {
            let state = if entry.deleted { "deleted" } else { "live" };
            let label = entry
                .path
                .clone()
                .unwrap_or_else(|| format!("inode_{}", entry.inode));
            safe_println!(
                "  [{}] {} {} {}",
                entry.inode,
                state.red(),
                entry.file_type.yellow(),
                label.white()
            );
            safe_println!(
                "      links={} size={} storage={} blocks={}{}",
                entry.links_count,
                entry.size,
                entry.storage,
                entry.block_count,
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

impl InodeRecord {
    fn deleted(&self) -> bool {
        self.dtime != 0 || (self.links_count == 0 && self.mode != 0)
    }
}

fn parse_superblock(data: &[u8], volume_offset: usize) -> Option<Superblock> {
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

fn parse_group_descriptors(
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

fn read_inode_record(
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

fn build_live_path_map(
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

fn summarize_journal(
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

fn recover_inode_bytes(
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

fn write_recovered_file(
    output_dir: &Path,
    entry: &ExtEntry,
    bytes: &[u8],
    overwrite: bool,
) -> io::Result<PathBuf> {
    let label = entry
        .path
        .as_deref()
        .map(sanitize_relative_path)
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from(format!("inode_{}", entry.inode)));
    let mut candidate = output_dir.join(label);

    if let Some(parent) = candidate.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if !overwrite {
        let stem = candidate
            .file_stem()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("inode_{}", entry.inode));
        let ext = candidate
            .extension()
            .map(|value| value.to_string_lossy().to_string());
        let mut suffix = 1usize;
        while candidate.exists() {
            let file_name = match &ext {
                Some(ext) => format!("{}_{}.{}", stem, suffix, ext),
                None => format!("{}_{}", stem, suffix),
            };
            candidate = output_dir.join(file_name);
            suffix += 1;
        }
    }

    std::fs::write(&candidate, bytes)?;
    Ok(candidate)
}

fn inode_type_name(mode: u16) -> &'static str {
    match mode & 0xF000 {
        0x4000 => "dir",
        0x8000 => "file",
        0xA000 => "symlink",
        0x2000 => "char",
        0x6000 => "block",
        0x1000 => "fifo",
        0xC000 => "socket",
        _ => "unknown",
    }
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

fn decode_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .filter(|byte| byte.is_ascii_graphic() || *byte == b' ')
        .map(char::from)
        .collect()
}

fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn be_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::{ExtOptions, inspect_ext_bytes};

    #[test]
    fn enumerates_deleted_ext_entries_and_journal() {
        let image = build_test_image();
        let report = inspect_ext_bytes(
            &image,
            "ext.img".to_string(),
            &ExtOptions {
                max_inodes: 16,
                include_directories: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(report.superblock.kind, "ext4");
        assert_eq!(report.deleted_entries, 2);
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.path.as_deref() == Some("live.txt"))
        );
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.inode == 12 && entry.deleted)
        );
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.inode == 13 && entry.storage == "extents")
        );
        assert_eq!(report.journal.as_ref().unwrap().inode, 8);
        assert_eq!(report.journal.as_ref().unwrap().block_size, Some(1024));
    }

    #[test]
    fn recovers_deleted_ext_direct_and_extent_files() {
        let image = build_test_image();
        let output_dir =
            std::env::temp_dir().join(format!("hashendra-ext-recovery-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&output_dir);

        let report = inspect_ext_bytes(
            &image,
            "ext.img".to_string(),
            &ExtOptions {
                max_inodes: 16,
                deleted_only: true,
                extract_data_to: Some(output_dir.clone()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(report.returned_entries, 2);
        assert_eq!(report.recovered_files, 2);

        let direct = report
            .entries
            .iter()
            .find(|entry| entry.inode == 12)
            .unwrap();
        let direct_path = direct.extracted_path.as_ref().unwrap();
        assert_eq!(std::fs::read(direct_path).unwrap(), b"hello");

        let extent = report
            .entries
            .iter()
            .find(|entry| entry.inode == 13)
            .unwrap();
        let extent_path = extent.extracted_path.as_ref().unwrap();
        assert_eq!(std::fs::read(extent_path).unwrap(), b"extent-data");

        let _ = std::fs::remove_dir_all(output_dir);
    }

    fn build_test_image() -> Vec<u8> {
        let mut image = vec![0u8; 64 * 1024];
        let sb = 1024usize;
        image[sb + 0x00..sb + 0x04].copy_from_slice(&32u32.to_le_bytes());
        image[sb + 0x04..sb + 0x08].copy_from_slice(&64u32.to_le_bytes());
        image[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
        image[sb + 0x18..sb + 0x1C].copy_from_slice(&0u32.to_le_bytes());
        image[sb + 0x20..sb + 0x24].copy_from_slice(&64u32.to_le_bytes());
        image[sb + 0x28..sb + 0x2C].copy_from_slice(&32u32.to_le_bytes());
        image[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        image[sb + 0x58..sb + 0x5A].copy_from_slice(&128u16.to_le_bytes());
        image[sb + 0x5C..sb + 0x60].copy_from_slice(&0x4u32.to_le_bytes());
        image[sb + 0x60..sb + 0x64].copy_from_slice(&0x40u32.to_le_bytes());
        image[sb + 0x78..sb + 0x80].copy_from_slice(b"evidence");
        image[sb + 0xE0..sb + 0xE4].copy_from_slice(&8u32.to_le_bytes());

        let gd = 2048usize;
        image[gd + 0x08..gd + 0x0C].copy_from_slice(&5u32.to_le_bytes());

        let inode_table = 5 * 1024usize;
        let root = build_inode(0x41ED, 1024, 2, 0, 0, &[10], None);
        write_inode(&mut image, inode_table, 2, &root);
        let journal = build_inode(0x81A4, 1024, 1, 0, 0, &[14], None);
        write_inode(&mut image, inode_table, 8, &journal);
        let live = build_inode(0x81A4, 4, 1, 0, 0, &[11], None);
        write_inode(&mut image, inode_table, 11, &live);
        let deleted = build_inode(0x81A4, 5, 0, 1, 0, &[12], None);
        write_inode(&mut image, inode_table, 12, &deleted);
        let extent = build_extent_inode(11, 13);
        write_inode(&mut image, inode_table, 13, &extent);

        let dir_block = 10 * 1024usize;
        write_dir_entry(&mut image[dir_block..dir_block + 1024], 0, 2, ".", 2, 12);
        write_dir_entry(&mut image[dir_block..dir_block + 1024], 12, 2, "..", 2, 12);
        write_dir_entry(
            &mut image[dir_block..dir_block + 1024],
            24,
            11,
            "live.txt",
            1,
            1024 - 24,
        );

        image[11 * 1024..11 * 1024 + 4].copy_from_slice(b"live");
        image[12 * 1024..12 * 1024 + 5].copy_from_slice(b"hello");
        image[13 * 1024..13 * 1024 + 11].copy_from_slice(b"extent-data");

        let journal_block = 14 * 1024usize;
        image[journal_block..journal_block + 4].copy_from_slice(&0xC03B3998u32.to_be_bytes());
        image[journal_block + 4..journal_block + 8].copy_from_slice(&4u32.to_be_bytes());
        image[journal_block + 12..journal_block + 16].copy_from_slice(&1024u32.to_be_bytes());
        image[journal_block + 16..journal_block + 20].copy_from_slice(&64u32.to_be_bytes());
        image[journal_block + 20..journal_block + 24].copy_from_slice(&1u32.to_be_bytes());

        image
    }

    fn build_inode(
        mode: u16,
        size: u32,
        links_count: u16,
        dtime: u32,
        flags: u32,
        blocks: &[u32],
        note: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut inode = vec![0u8; 128];
        inode[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
        inode[0x04..0x08].copy_from_slice(&size.to_le_bytes());
        inode[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
        inode[0x1A..0x1C].copy_from_slice(&links_count.to_le_bytes());
        inode[0x1C..0x20].copy_from_slice(&((blocks.len() as u32) * 2).to_le_bytes());
        inode[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
        for (index, block) in blocks.iter().enumerate() {
            inode[0x28 + index * 4..0x2C + index * 4].copy_from_slice(&block.to_le_bytes());
        }
        if let Some(extra) = note {
            let len = extra.len().min(16);
            inode[0x64..0x64 + len].copy_from_slice(&extra[..len]);
        }
        inode
    }

    fn build_extent_inode(size: u32, block: u32) -> Vec<u8> {
        let mut inode = build_inode(0x81A4, size, 0, 2, 0x80000, &[], None);
        inode[0x1C..0x20].copy_from_slice(&2u32.to_le_bytes());
        inode[0x28..0x2A].copy_from_slice(&0xF30Au16.to_le_bytes());
        inode[0x2A..0x2C].copy_from_slice(&1u16.to_le_bytes());
        inode[0x2C..0x2E].copy_from_slice(&4u16.to_le_bytes());
        inode[0x2E..0x30].copy_from_slice(&0u16.to_le_bytes());
        inode[0x34..0x38].copy_from_slice(&0u32.to_le_bytes());
        inode[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes());
        inode[0x3A..0x3C].copy_from_slice(&0u16.to_le_bytes());
        inode[0x3C..0x40].copy_from_slice(&block.to_le_bytes());
        inode
    }

    fn write_inode(image: &mut [u8], inode_table: usize, inode: usize, bytes: &[u8]) {
        let offset = inode_table + (inode - 1) * 128;
        image[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn write_dir_entry(
        block: &mut [u8],
        offset: usize,
        inode: u32,
        name: &str,
        file_type: u8,
        rec_len: usize,
    ) {
        let name_bytes = name.as_bytes();
        block[offset..offset + 4].copy_from_slice(&inode.to_le_bytes());
        block[offset + 4..offset + 6].copy_from_slice(&(rec_len as u16).to_le_bytes());
        block[offset + 6] = name_bytes.len() as u8;
        block[offset + 7] = file_type;
        block[offset + 8..offset + 8 + name_bytes.len()].copy_from_slice(name_bytes);
    }
}
