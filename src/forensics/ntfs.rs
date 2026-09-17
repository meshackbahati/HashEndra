use memmap2::Mmap;
use serde::Serialize;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

// safe_println! is defined in utils/io.rs via #[macro_export]

#[derive(Debug, Clone)]
pub struct NtfsOptions {
    pub volume_offset: usize,
    pub max_records: usize,
    pub deleted_only: bool,
    pub include_directories: bool,
    pub extract_data_to: Option<PathBuf>,
    pub overwrite: bool,
}

impl Default for NtfsOptions {
    fn default() -> Self {
        Self {
            volume_offset: 0,
            max_records: 256,
            deleted_only: false,
            include_directories: false,
            extract_data_to: None,
            overwrite: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NtfsBootInfo {
    pub volume_offset: u64,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub cluster_size: u64,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mft_offset: u64,
    pub mft_mirror_lcn: u64,
    pub record_size: usize,
    pub index_record_size: usize,
    pub serial: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NtfsEntry {
    pub record_number: u64,
    pub sequence_number: u16,
    pub in_use: bool,
    pub deleted: bool,
    pub directory: bool,
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub parent_reference: Option<u64>,
    pub allocated_size: Option<u64>,
    pub real_size: Option<u64>,
    pub resident_data_size: Option<usize>,
    pub non_resident_data_size: Option<u64>,
    pub data_runs: Option<usize>,
    pub extracted_path: Option<String>,
    pub recovery_note: Option<String>,
    pub alternate_data_streams: Vec<NtfsAlternateDataStream>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NtfsReport {
    pub path: String,
    pub boot: NtfsBootInfo,
    pub scanned_records: usize,
    pub returned_entries: usize,
    pub deleted_entries: usize,
    pub resident_recovered: usize,
    pub non_resident_recovered: usize,
    pub recovered_bytes: u64,
    pub system_artifacts: NtfsSystemArtifacts,
    pub entries: Vec<NtfsEntry>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NtfsAlternateDataStream {
    pub name: String,
    pub resident: bool,
    pub compressed: bool,
    pub encrypted: bool,
    pub sparse: bool,
    pub size: Option<u64>,
    pub allocated_size: Option<u64>,
    pub initialized_size: Option<u64>,
    pub data_runs: Option<usize>,
    pub extracted_path: Option<String>,
    pub recovery_note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NtfsSystemArtifacts {
    pub bitmap: Option<NtfsBitmapSummary>,
    pub logfile: Option<NtfsLogFileSummary>,
    pub usn_journal: Option<NtfsUsnJrnlSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NtfsBitmapSummary {
    pub tracked_clusters: u64,
    pub allocated_clusters: u64,
    pub free_clusters: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NtfsLogFileSummary {
    pub bytes: u64,
    pub restart_pages: usize,
    pub record_pages: usize,
    pub first_magic: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NtfsUsnJrnlSummary {
    pub stream_name: String,
    pub bytes: u64,
    pub records: usize,
    pub sample_names: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum DataStream {
    Resident(Vec<u8>),
    NonResident(NonResidentData),
}

#[derive(Debug, Clone)]
pub(crate) struct NonResidentData {
    pub(crate) allocated_size: u64,
    pub(crate) real_size: u64,
    pub(crate) initialized_size: u64,
    pub(crate) runs: Vec<DataRun>,
    pub(crate) compression_unit_shift: u8,
    pub(crate) compressed: bool,
    pub(crate) encrypted: bool,
    pub(crate) sparse: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct DataRun {
    pub(crate) start_lcn: Option<u64>,
    pub(crate) cluster_count: u64,
}

pub(crate) struct ParsedEntry {
    pub(crate) entry: NtfsEntry,
    pub(crate) primary_stream: Option<DataStream>,
    pub(crate) alternate_streams: Vec<NamedDataStream>,
}

pub(crate) struct NamedDataStream {
    pub(crate) report: NtfsAlternateDataStream,
    pub(crate) stream: DataStream,
}

#[derive(Clone)]
pub(crate) struct BitmapData {
    pub(crate) bits: Vec<u8>,
    pub(crate) summary: NtfsBitmapSummary,
}

pub(crate) struct RecoveryAttempt {
    pub(crate) path: Option<PathBuf>,
    pub(crate) bytes_recovered: u64,
    pub(crate) stream_kind: StreamKind,
    pub(crate) note: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) enum StreamKind {
    Resident,
    NonResident,
}

pub fn inspect_ntfs_image(path: &Path, options: &NtfsOptions) -> io::Result<NtfsReport> {
    let file = File::open(path)?;
    // SAFETY: the file is opened read-only and never truncated or
    // written while mapped; the mapping is only read.
    let mmap = unsafe { Mmap::map(&file)? };
    inspect_ntfs_bytes(&mmap[..], path.display().to_string(), options)
}

pub fn inspect_ntfs_bytes(
    data: &[u8],
    path: String,
    options: &NtfsOptions,
) -> io::Result<NtfsReport> {
    let boot = parse_boot_info(data, options.volume_offset).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no NTFS boot sector found at the requested offset",
        )
    })?;

    let mut scanned_records = 0usize;
    let mut deleted_entries = 0usize;
    let mut resident_recovered = 0usize;
    let mut non_resident_recovered = 0usize;
    let mut recovered_bytes = 0u64;
    let mut notes = Vec::new();
    let mut parsed_entries = Vec::new();

    if boot.mft_offset as usize >= data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MFT offset falls outside the image",
        ));
    }

    if let Some(dir) = &options.extract_data_to {
        std::fs::create_dir_all(dir)?;
    }

    let mut empty_run = 0usize;
    for index in 0..options.max_records {
        let offset = boot
            .mft_offset.saturating_add(index.saturating_mul(boot.record_size) as u64) as usize;
        let Some(raw_record) = data.get(offset..offset + boot.record_size) else {
            break;
        };

        scanned_records += 1;

        if raw_record.get(..4) != Some(b"FILE") {
            empty_run += 1;
            if empty_run >= 32 && !parsed_entries.is_empty() {
                break;
            }
            continue;
        }
        empty_run = 0;

        let Some(parsed) = parse_record(raw_record, index as u64) else {
            continue;
        };

        if parsed.entry.deleted {
            deleted_entries += 1;
        }
        parsed_entries.push(parsed);
    }

    let bitmap = parse_bitmap_data(data, &boot, &parsed_entries);
    let system_artifacts = analyze_system_artifacts(data, &boot, &parsed_entries, bitmap.as_ref());

    let mut entries = Vec::new();
    for mut parsed in parsed_entries {
        if options.deleted_only && !parsed.entry.deleted {
            continue;
        }
        if !options.include_directories && parsed.entry.directory {
            continue;
        }

        if let (Some(dir), Some(stream)) =
            (&options.extract_data_to, parsed.primary_stream.as_ref())
            && !parsed.entry.directory {
                let recovery = EntryRecovery {
                    output_dir: dir.as_path(),
                    image: data,
                    boot: &boot,
                    bitmap: bitmap.as_ref(),
                    overwrite: options.overwrite,
                };
                let attempt = recover_entry_data(
                    &recovery,
                    &parsed.entry,
                    None,
                    stream,
                )?;
                if let Some(written) = attempt.path {
                    parsed.entry.extracted_path = Some(written.display().to_string());
                    recovered_bytes = recovered_bytes.saturating_add(attempt.bytes_recovered);
                    match attempt.stream_kind {
                        StreamKind::Resident => resident_recovered += 1,
                        StreamKind::NonResident => non_resident_recovered += 1,
                    }
                }
                if parsed.entry.recovery_note.is_none() {
                    parsed.entry.recovery_note = attempt.note;
                }
            }

        if let Some(dir) = &options.extract_data_to {
            for alternate in &mut parsed.alternate_streams {
                let recovery = EntryRecovery {
                    output_dir: dir.as_path(),
                    image: data,
                    boot: &boot,
                    bitmap: bitmap.as_ref(),
                    overwrite: options.overwrite,
                };
                let attempt = recover_entry_data(
                    &recovery,
                    &parsed.entry,
                    Some(&alternate.report.name),
                    &alternate.stream,
                )?;
                if let Some(written) = attempt.path {
                    alternate.report.extracted_path = Some(written.display().to_string());
                    recovered_bytes = recovered_bytes.saturating_add(attempt.bytes_recovered);
                    match attempt.stream_kind {
                        StreamKind::Resident => resident_recovered += 1,
                        StreamKind::NonResident => non_resident_recovered += 1,
                    }
                }
                if alternate.report.recovery_note.is_none() {
                    alternate.report.recovery_note = attempt.note;
                }
            }
        }

        parsed.entry.alternate_data_streams = parsed
            .alternate_streams
            .into_iter()
            .map(|stream| stream.report)
            .collect();
        entries.push(parsed.entry);
    }

    if entries.is_empty() {
        notes.push("No MFT file records matched the current filters.".to_string());
    }
    notes.push(
        "Primary and named $DATA streams are recoverable. Bitmap-guided heuristics can extend incomplete deleted-file recovery when contiguous free clusters follow the declared runlist."
            .to_string(),
    );
    notes.push(
        "Encrypted NTFS streams are recovered as raw encrypted bytes; decrypting EFS content still requires the volume's keys or certificates."
            .to_string(),
    );

    Ok(NtfsReport {
        path,
        boot,
        scanned_records,
        returned_entries: entries.len(),
        deleted_entries,
        resident_recovered,
        non_resident_recovered,
        recovered_bytes,
        system_artifacts,
        entries,
        notes,
    })
}

pub(crate) fn write_recovered_file(
    output_dir: &Path,
    entry: &NtfsEntry,
    stream_name: Option<&str>,
    bytes: &[u8],
    overwrite: bool,
) -> io::Result<PathBuf> {
    let mut name = entry
        .name
        .as_deref()
        .map(sanitize_component)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("record_{}", entry.record_number));

    if name == "." || name == ".." {
        name = format!("record_{}", entry.record_number);
    }

    if let Some(stream_name) = stream_name {
        let suffix = sanitize_component(stream_name);
        name = if suffix.is_empty() {
            format!("{}__ads", name)
        } else {
            format!("{}__ads__{}", name, suffix)
        };
    }

    let mut candidate = output_dir.join(name);
    if !overwrite {
        let stem = candidate
            .file_stem()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("record_{}", entry.record_number));
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

pub(crate) fn sanitize_component(value: &str) -> String {
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

mod parse;
mod recover;
mod report;

pub(crate) use parse::*;
pub(crate) use recover::*;

// Public API consumed by the binary.
pub use report::print_ntfs_report;

#[cfg(test)]
#[path = "ntfs/ntfs_fixtures.rs"]
mod ntfs_fixtures;
#[cfg(test)]
#[path = "ntfs/ntfs_tests.rs"]
mod ntfs_tests;
