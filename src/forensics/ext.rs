use crate::safe_println;
use colored::*;
use memmap2::Mmap;
use serde::Serialize;
use std::collections::BTreeMap;
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
pub(crate) struct Superblock {
    pub(crate) kind: String,
    pub(crate) block_size: u64,
    pub(crate) blocks_count: u64,
    pub(crate) inodes_count: u32,
    pub(crate) blocks_per_group: u32,
    pub(crate) inodes_per_group: u32,
    pub(crate) inode_size: u16,
    pub(crate) descriptor_size: u16,
    pub(crate) first_data_block: u32,
    pub(crate) journal_inode: Option<u32>,
    pub(crate) volume_name: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) struct GroupDesc {
    pub(crate) inode_table_block: u64,
}

#[derive(Clone)]
pub(crate) struct InodeRecord {
    pub(crate) inode: u32,
    pub(crate) mode: u16,
    pub(crate) size: u64,
    pub(crate) links_count: u16,
    pub(crate) dtime: u32,
    pub(crate) blocks: Vec<u64>,
    pub(crate) storage: String,
    pub(crate) directory: bool,
    pub(crate) regular: bool,
    pub(crate) recovery_note: Option<String>,
}
pub fn inspect_ext_image(path: &Path, options: &ExtOptions) -> io::Result<ExtReport> {
    let file = File::open(path)?;
    // SAFETY: the file is opened read-only and never truncated or
    // written while mapped; the mapping is only read.
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

        if let Some(dir) = &options.extract_data_to
            && record.regular && !record.blocks.is_empty() {
                let bytes = recover_inode_bytes(data, options.volume_offset, &superblock, record)?;
                let written = write_recovered_file(dir, &entry, &bytes, options.overwrite)?;
                entry.extracted_path = Some(written.display().to_string());
                recovered_files += 1;
                recovered_bytes = recovered_bytes.saturating_add(bytes.len() as u64);
            }

        entries.push(entry);
    }

    let notes = vec![
        "Deleted ext-family recovery enumerates inodes directly; deleted names are only shown when they still have live directory references."
            .to_string(),
        "Regular files recover via extents and direct/indirect block pointers. Inline symlinks and journal replay are not rebuilt yet."
            .to_string(),
    ];

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

mod parse;

pub(crate) use parse::*;

#[cfg(test)]
#[path = "ext/ext_tests.rs"]
mod ext_tests;
