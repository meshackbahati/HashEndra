use crate::safe_println;
use colored::*;
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
enum DataStream {
    Resident(Vec<u8>),
    NonResident(NonResidentData),
}

#[derive(Debug, Clone)]
struct NonResidentData {
    allocated_size: u64,
    real_size: u64,
    initialized_size: u64,
    runs: Vec<DataRun>,
    compression_unit_shift: u8,
    compressed: bool,
    encrypted: bool,
    sparse: bool,
}

#[derive(Debug, Clone)]
struct DataRun {
    start_lcn: Option<u64>,
    cluster_count: u64,
}

struct ParsedEntry {
    entry: NtfsEntry,
    primary_stream: Option<DataStream>,
    alternate_streams: Vec<NamedDataStream>,
}

struct NamedDataStream {
    report: NtfsAlternateDataStream,
    stream: DataStream,
}

#[derive(Clone)]
struct BitmapData {
    bits: Vec<u8>,
    summary: NtfsBitmapSummary,
}

struct RecoveryAttempt {
    path: Option<PathBuf>,
    bytes_recovered: u64,
    stream_kind: StreamKind,
    note: Option<String>,
}

#[derive(Clone, Copy)]
enum StreamKind {
    Resident,
    NonResident,
}

pub fn inspect_ntfs_image(path: &Path, options: &NtfsOptions) -> io::Result<NtfsReport> {
    let file = File::open(path)?;
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
            .mft_offset
            .checked_add((index.checked_mul(boot.record_size).unwrap_or(usize::MAX)) as u64)
            .unwrap_or(u64::MAX) as usize;
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
        {
            if !parsed.entry.directory {
                let attempt = recover_entry_data(
                    dir,
                    &parsed.entry,
                    None,
                    stream,
                    data,
                    &boot,
                    bitmap.as_ref(),
                    options.overwrite,
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
        }

        if let Some(dir) = &options.extract_data_to {
            for alternate in &mut parsed.alternate_streams {
                let attempt = recover_entry_data(
                    dir,
                    &parsed.entry,
                    Some(&alternate.report.name),
                    &alternate.stream,
                    data,
                    &boot,
                    bitmap.as_ref(),
                    options.overwrite,
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

pub fn print_ntfs_report(report: &NtfsReport) {
    safe_println!(
        "{}",
        format!(
            "[NTFS] {} | volume 0x{:X} | MFT 0x{:X}",
            report.path, report.boot.volume_offset, report.boot.mft_offset
        )
        .cyan()
    );
    safe_println!(
        "{}",
        format!(
            "[BOOT] sector {} | cluster {} | record {} | serial {}",
            report.boot.bytes_per_sector,
            report.boot.cluster_size,
            report.boot.record_size,
            report.boot.serial
        )
        .blue()
    );
    safe_println!(
        "{}",
        format!(
            "[SUMMARY] scanned {} record(s), returned {}, deleted {}, resident recovered {}, non-resident recovered {}, bytes {}",
            report.scanned_records,
            report.returned_entries,
            report.deleted_entries,
            report.resident_recovered,
            report.non_resident_recovered,
            report.recovered_bytes
        )
        .cyan()
    );

    if !report.entries.is_empty() {
        safe_println!("{}", "[ENTRIES]".cyan());
        for entry in &report.entries {
            let state = if entry.deleted { "deleted" } else { "live" };
            let kind = if entry.directory { "dir" } else { "file" };
            safe_println!(
                "  [{}] {} {} {}",
                entry.record_number,
                state.red(),
                kind.yellow(),
                entry.name.as_deref().unwrap_or("<unnamed>").white()
            );
            safe_println!(
                "      parent={} seq={} size={} resident={} nonresident={} runs={}{}",
                entry
                    .parent_reference
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                entry.sequence_number,
                entry
                    .real_size
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                entry
                    .resident_data_size
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "0".to_string()),
                entry
                    .non_resident_data_size
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "0".to_string()),
                entry
                    .data_runs
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "0".to_string()),
                entry
                    .extracted_path
                    .as_ref()
                    .map(|path| format!(" | extracted {}", path))
                    .unwrap_or_default()
            );
            if let Some(note) = &entry.recovery_note {
                safe_println!("      note={}", note.yellow());
            }
            for ads in &entry.alternate_data_streams {
                safe_println!(
                    "      ads={} resident={} compressed={} encrypted={} sparse={} size={} runs={}{}",
                    ads.name.cyan(),
                    ads.resident,
                    ads.compressed,
                    ads.encrypted,
                    ads.sparse,
                    ads.size
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    ads.data_runs
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "0".to_string()),
                    ads.extracted_path
                        .as_ref()
                        .map(|path| format!(" | extracted {}", path))
                        .unwrap_or_default()
                );
                if let Some(note) = &ads.recovery_note {
                    safe_println!("          note={}", note.yellow());
                }
            }
        }
    }

    if let Some(bitmap) = &report.system_artifacts.bitmap {
        safe_println!(
            "{}",
            format!(
                "[BITMAP] tracked {} | allocated {} | free {}",
                bitmap.tracked_clusters, bitmap.allocated_clusters, bitmap.free_clusters
            )
            .cyan()
        );
    }
    if let Some(logfile) = &report.system_artifacts.logfile {
        safe_println!(
            "{}",
            format!(
                "[LOGFILE] bytes {} | restart pages {} | record pages {}{}",
                logfile.bytes,
                logfile.restart_pages,
                logfile.record_pages,
                logfile
                    .first_magic
                    .as_ref()
                    .map(|value| format!(" | first {}", value))
                    .unwrap_or_default()
            )
            .cyan()
        );
    }
    if let Some(usn) = &report.system_artifacts.usn_journal {
        safe_println!(
            "{}",
            format!(
                "[USN] stream {} | bytes {} | records {}",
                usn.stream_name, usn.bytes, usn.records
            )
            .cyan()
        );
        for name in &usn.sample_names {
            safe_println!("  {}", name);
        }
    }

    if !report.notes.is_empty() {
        safe_println!("{}", "[NOTES]".cyan());
        for note in &report.notes {
            safe_println!("  {}", note);
        }
    }
}

fn parse_boot_info(data: &[u8], volume_offset: usize) -> Option<NtfsBootInfo> {
    let boot = data.get(volume_offset..volume_offset + 512)?;
    if boot.get(3..11)? != b"NTFS    " {
        return None;
    }
    if boot.get(510..512) != Some(&[0x55, 0xAA]) {
        return None;
    }

    let bytes_per_sector = le_u16(boot, 11)?;
    let sectors_per_cluster = *boot.get(13)?;
    let cluster_size = bytes_per_sector as u64 * sectors_per_cluster as u64;
    let total_sectors = le_u64(boot, 40)?;
    let mft_lcn = le_u64(boot, 48)?;
    let mft_mirror_lcn = le_u64(boot, 56)?;
    let record_size = decode_record_size(*boot.get(64)?, cluster_size)?;
    let index_record_size = decode_record_size(*boot.get(68)?, cluster_size)?;
    let serial = le_u64(boot, 72)?;

    Some(NtfsBootInfo {
        volume_offset: volume_offset as u64,
        bytes_per_sector,
        sectors_per_cluster,
        cluster_size,
        total_sectors,
        mft_lcn,
        mft_offset: volume_offset as u64 + mft_lcn.saturating_mul(cluster_size),
        mft_mirror_lcn,
        record_size,
        index_record_size,
        serial: format!("0x{:016X}", serial),
    })
}

fn decode_record_size(raw: u8, cluster_size: u64) -> Option<usize> {
    let signed = raw as i8;
    if signed > 0 {
        Some((cluster_size * signed as u64) as usize)
    } else if signed < 0 {
        Some(1usize << (-signed as usize))
    } else {
        None
    }
}

fn parse_record(record: &[u8], fallback_record_number: u64) -> Option<ParsedEntry> {
    let fixed = apply_fixup(record)?;
    if fixed.get(..4) != Some(b"FILE") {
        return None;
    }

    let sequence_number = le_u16(&fixed, 16)?;
    let first_attribute_offset = le_u16(&fixed, 20)? as usize;
    let flags = le_u16(&fixed, 22)?;
    let in_use = flags & 0x01 != 0;
    let directory = flags & 0x02 != 0;
    let record_number = le_u32(&fixed, 44)
        .map(u64::from)
        .unwrap_or(fallback_record_number);

    let mut best_name: Option<(u8, String)> = None;
    let mut parent_reference = None;
    let mut allocated_size = None;
    let mut real_size = None;
    let mut primary_stream = None;
    let mut recovery_note = None;
    let mut alternate_streams = Vec::new();

    let mut offset = first_attribute_offset;
    while offset + 16 <= fixed.len() {
        let attr_type = le_u32(&fixed, offset)?;
        if attr_type == 0xFFFF_FFFF {
            break;
        }

        let attr_length = le_u32(&fixed, offset + 4)? as usize;
        if attr_length == 0 || offset + attr_length > fixed.len() {
            break;
        }

        let non_resident = fixed[offset + 8] != 0;
        let name_length = fixed[offset + 9];
        let attr_name = parse_attribute_name(&fixed, offset, attr_length, name_length);

        if non_resident {
            if attr_type == 0x80 {
                let flags = le_u16(&fixed, offset + 12).unwrap_or(0);
                let non_resident =
                    parse_non_resident_data_attr(&fixed, offset, attr_length, flags)?;

                if let Some(name) = attr_name {
                    alternate_streams.push(NamedDataStream {
                        report: NtfsAlternateDataStream {
                            name,
                            resident: false,
                            compressed: non_resident.compressed,
                            encrypted: non_resident.encrypted,
                            sparse: non_resident.sparse,
                            size: Some(non_resident.real_size),
                            allocated_size: Some(non_resident.allocated_size),
                            initialized_size: Some(non_resident.initialized_size),
                            data_runs: Some(non_resident.runs.len()),
                            extracted_path: None,
                            recovery_note: None,
                        },
                        stream: DataStream::NonResident(non_resident),
                    });
                } else if primary_stream.is_none() {
                    real_size = Some(non_resident.real_size);
                    allocated_size = Some(non_resident.allocated_size);
                    if non_resident.encrypted {
                        recovery_note = Some(
                            "encrypted non-resident stream will be recovered as raw encrypted bytes"
                                .to_string(),
                        );
                    }
                    primary_stream = Some(DataStream::NonResident(non_resident));
                }
            }
        } else {
            let value_length = le_u32(&fixed, offset + 16)? as usize;
            let value_offset = le_u16(&fixed, offset + 20)? as usize;
            let value = fixed.get(offset + value_offset..offset + value_offset + value_length)?;

            match attr_type {
                0x30 => {
                    if let Some(file_name) = parse_file_name_attr(value) {
                        let current_rank = best_name
                            .as_ref()
                            .map(|(namespace, _)| namespace_rank(*namespace))
                            .unwrap_or(0);
                        let next_rank = namespace_rank(file_name.namespace);
                        if best_name.is_none() || next_rank >= current_rank {
                            best_name = Some((file_name.namespace, file_name.name));
                            parent_reference = Some(file_name.parent_reference);
                            allocated_size = Some(file_name.allocated_size);
                            real_size = Some(file_name.real_size);
                        }
                    }
                }
                0x80 => {
                    if let Some(name) = attr_name {
                        alternate_streams.push(NamedDataStream {
                            report: NtfsAlternateDataStream {
                                name,
                                resident: true,
                                compressed: false,
                                encrypted: false,
                                sparse: false,
                                size: Some(value.len() as u64),
                                allocated_size: Some(value.len() as u64),
                                initialized_size: Some(value.len() as u64),
                                data_runs: None,
                                extracted_path: None,
                                recovery_note: None,
                            },
                            stream: DataStream::Resident(value.to_vec()),
                        });
                    } else if primary_stream.is_none() {
                        primary_stream = Some(DataStream::Resident(value.to_vec()));
                        real_size = Some(value.len() as u64);
                        allocated_size = Some(value.len() as u64);
                    }
                }
                _ => {}
            }
        }

        offset += attr_length;
    }

    let namespace = best_name
        .as_ref()
        .map(|(namespace, _)| namespace_name(*namespace).to_string());
    let name = best_name.map(|(_, name)| name);
    let resident_data_size = match primary_stream.as_ref() {
        Some(DataStream::Resident(data)) => Some(data.len()),
        _ => None,
    };
    let non_resident_data_size = match primary_stream.as_ref() {
        Some(DataStream::NonResident(stream)) => Some(stream.real_size),
        _ => None,
    };
    let data_runs = match primary_stream.as_ref() {
        Some(DataStream::NonResident(stream)) => Some(stream.runs.len()),
        _ => None,
    };

    Some(ParsedEntry {
        entry: NtfsEntry {
            record_number,
            sequence_number,
            in_use,
            deleted: !in_use,
            directory,
            name,
            namespace,
            parent_reference,
            allocated_size,
            real_size,
            resident_data_size,
            non_resident_data_size,
            data_runs,
            extracted_path: None,
            recovery_note,
            alternate_data_streams: Vec::new(),
        },
        primary_stream,
        alternate_streams,
    })
}

fn apply_fixup(record: &[u8]) -> Option<Vec<u8>> {
    let mut fixed = record.to_vec();
    let usa_offset = le_u16(&fixed, 4)? as usize;
    let usa_count = le_u16(&fixed, 6)? as usize;
    if usa_count < 2 || usa_offset + usa_count * 2 > fixed.len() {
        return Some(fixed);
    }

    let usa = fixed.get(usa_offset..usa_offset + usa_count * 2)?.to_vec();
    let sequence = u16::from_le_bytes([usa[0], usa[1]]);

    for index in 0..usa_count - 1 {
        let end = (index + 1) * 512 - 2;
        if end + 2 > fixed.len() {
            break;
        }
        let current = u16::from_le_bytes([fixed[end], fixed[end + 1]]);
        if current != sequence {
            return Some(fixed);
        }
        let replacement_offset = 2 + index * 2;
        fixed[end..end + 2].copy_from_slice(&usa[replacement_offset..replacement_offset + 2]);
    }

    Some(fixed)
}

struct FileNameAttr {
    parent_reference: u64,
    allocated_size: u64,
    real_size: u64,
    namespace: u8,
    name: String,
}

fn parse_file_name_attr(value: &[u8]) -> Option<FileNameAttr> {
    if value.len() < 66 {
        return None;
    }

    let parent_reference = le_u64(value, 0)? & 0x0000_FFFF_FFFF_FFFF;
    let allocated_size = le_u64(value, 40)?;
    let real_size = le_u64(value, 48)?;
    let name_length = value[64] as usize;
    let namespace = value[65];
    let name_bytes = value.get(66..66 + name_length * 2)?;
    let utf16: Vec<u16> = name_bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    let name = String::from_utf16(&utf16).ok()?;

    Some(FileNameAttr {
        parent_reference,
        allocated_size,
        real_size,
        namespace,
        name,
    })
}

fn namespace_rank(namespace: u8) -> u8 {
    match namespace {
        3 => 4,
        1 => 3,
        0 => 2,
        2 => 1,
        _ => 0,
    }
}

fn namespace_name(namespace: u8) -> &'static str {
    match namespace {
        0 => "POSIX",
        1 => "Win32",
        2 => "DOS",
        3 => "Win32&DOS",
        _ => "Unknown",
    }
}

fn parse_attribute_name(
    record: &[u8],
    attr_offset: usize,
    attr_length: usize,
    name_length: u8,
) -> Option<String> {
    if name_length == 0 {
        return None;
    }

    let name_offset = le_u16(record, attr_offset + 10)? as usize;
    let start = attr_offset.checked_add(name_offset)?;
    let end = start.checked_add(name_length as usize * 2)?;
    if end > attr_offset.checked_add(attr_length)? {
        return None;
    }
    let bytes = record.get(start..end)?;
    let utf16 = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&utf16)
        .ok()
        .filter(|value| !value.is_empty())
}

fn parse_non_resident_data_attr(
    record: &[u8],
    attr_offset: usize,
    attr_length: usize,
    flags: u16,
) -> Option<NonResidentData> {
    let data_runs_offset = le_u16(record, attr_offset + 32)? as usize;
    let compression_unit_shift = le_u16(record, attr_offset + 34).unwrap_or(0) as u8;
    let allocated_size = le_u64(record, attr_offset + 40)?;
    let real_size = le_u64(record, attr_offset + 48)?;
    let initialized_size = le_u64(record, attr_offset + 56).unwrap_or(real_size);
    let runlist_start = attr_offset.checked_add(data_runs_offset)?;
    let runlist_end = attr_offset.checked_add(attr_length)?;
    let runlist = record.get(runlist_start..runlist_end)?;
    let runs = parse_data_runs(runlist)?;

    Some(NonResidentData {
        allocated_size,
        real_size,
        initialized_size,
        runs,
        compression_unit_shift,
        compressed: flags & 0x0001 != 0,
        encrypted: flags & 0x4000 != 0,
        sparse: flags & 0x8000 != 0,
    })
}

fn parse_data_runs(runlist: &[u8]) -> Option<Vec<DataRun>> {
    let mut runs = Vec::new();
    let mut offset = 0usize;
    let mut current_lcn = 0i64;

    while offset < runlist.len() {
        let header = *runlist.get(offset)?;
        offset += 1;
        if header == 0 {
            break;
        }

        let length_size = (header & 0x0F) as usize;
        let offset_size = (header >> 4) as usize;
        if length_size == 0 || offset + length_size + offset_size > runlist.len() {
            return None;
        }

        let cluster_count = read_unsigned_le(runlist.get(offset..offset + length_size)?)?;
        offset += length_size;

        let start_lcn = if offset_size == 0 {
            None
        } else {
            let delta = read_signed_le(runlist.get(offset..offset + offset_size)?)?;
            offset += offset_size;
            current_lcn = current_lcn.checked_add(delta)?;
            if current_lcn < 0 {
                return None;
            }
            Some(current_lcn as u64)
        };

        runs.push(DataRun {
            start_lcn,
            cluster_count,
        });
    }

    (!runs.is_empty()).then_some(runs)
}

fn read_unsigned_le(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }

    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= (*byte as u64) << (index * 8);
    }
    Some(value)
}

fn read_signed_le(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }

    let mut extended = [0u8; 8];
    extended[..bytes.len()].copy_from_slice(bytes);
    if bytes.last()? & 0x80 != 0 {
        for byte in &mut extended[bytes.len()..] {
            *byte = 0xFF;
        }
    }
    Some(i64::from_le_bytes(extended))
}

fn parse_bitmap_data(
    image: &[u8],
    boot: &NtfsBootInfo,
    entries: &[ParsedEntry],
) -> Option<BitmapData> {
    let stream = entries
        .iter()
        .find(|entry| entry.entry.name.as_deref() == Some("$Bitmap"))
        .and_then(|entry| entry.primary_stream.as_ref())?;
    let bytes = recover_stream_bytes_for_analysis(image, boot, stream, None).ok()?;
    let allocated_clusters = bytes
        .iter()
        .map(|byte| byte.count_ones() as u64)
        .sum::<u64>();
    let tracked_clusters = (bytes.len() as u64).saturating_mul(8);

    Some(BitmapData {
        bits: bytes,
        summary: NtfsBitmapSummary {
            tracked_clusters,
            allocated_clusters,
            free_clusters: tracked_clusters.saturating_sub(allocated_clusters),
        },
    })
}

fn analyze_system_artifacts(
    image: &[u8],
    boot: &NtfsBootInfo,
    entries: &[ParsedEntry],
    bitmap: Option<&BitmapData>,
) -> NtfsSystemArtifacts {
    let mut artifacts = NtfsSystemArtifacts {
        bitmap: bitmap.map(|value| value.summary.clone()),
        ..Default::default()
    };

    if let Some(stream) = entries
        .iter()
        .find(|entry| entry.entry.name.as_deref() == Some("$LogFile"))
        .and_then(|entry| entry.primary_stream.as_ref())
    {
        if let Ok(bytes) = recover_stream_bytes_for_analysis(image, boot, stream, bitmap) {
            let page_size = 4096usize;
            let mut restart_pages = 0usize;
            let mut record_pages = 0usize;
            for page in bytes.chunks(page_size) {
                match page.get(..4) {
                    Some(b"RSTR") => restart_pages += 1,
                    Some(b"RCRD") => record_pages += 1,
                    _ => {}
                }
            }
            artifacts.logfile = Some(NtfsLogFileSummary {
                bytes: bytes.len() as u64,
                restart_pages,
                record_pages,
                first_magic: bytes
                    .get(..4)
                    .map(|value| String::from_utf8_lossy(value).to_string()),
            });
        }
    }

    if let Some((stream_name, stream)) = entries
        .iter()
        .find(|entry| entry.entry.name.as_deref() == Some("$UsnJrnl"))
        .and_then(|entry| {
            entry.alternate_streams.iter().find_map(|stream| {
                (stream.report.name == "$J" || stream.report.name == "J")
                    .then_some((stream.report.name.clone(), &stream.stream))
            })
        })
    {
        if let Ok(bytes) = recover_stream_bytes_for_analysis(image, boot, stream, bitmap) {
            artifacts.usn_journal = Some(parse_usn_journal_summary(&stream_name, &bytes));
        }
    }

    artifacts
}

fn recover_stream_bytes_for_analysis(
    image: &[u8],
    boot: &NtfsBootInfo,
    stream: &DataStream,
    bitmap: Option<&BitmapData>,
) -> Result<Vec<u8>, String> {
    match stream {
        DataStream::Resident(bytes) => Ok(bytes.clone()),
        DataStream::NonResident(stream) => {
            recover_non_resident_bytes(image, boot, stream, bitmap).map(|(bytes, _)| bytes)
        }
    }
}

fn parse_usn_journal_summary(stream_name: &str, bytes: &[u8]) -> NtfsUsnJrnlSummary {
    let mut offset = 0usize;
    let mut records = 0usize;
    let mut sample_names = Vec::new();

    while offset + 60 <= bytes.len() {
        let Some(record_length) = le_u32(bytes, offset).map(|value| value as usize) else {
            break;
        };
        if record_length == 0 {
            break;
        }
        if record_length < 60 || offset + record_length > bytes.len() {
            offset += 8;
            continue;
        }

        let major = le_u16(bytes, offset + 4).unwrap_or(0);
        if !(2..=4).contains(&major) {
            offset += 8;
            continue;
        }

        let name_length = le_u16(bytes, offset + 56).unwrap_or(0) as usize;
        let name_offset = le_u16(bytes, offset + 58).unwrap_or(0) as usize;
        if name_length > 0 {
            let start = offset.saturating_add(name_offset);
            let end = start.saturating_add(name_length);
            if let Some(name_bytes) = bytes.get(start..end) {
                let utf16 = name_bytes
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect::<Vec<_>>();
                if let Ok(name) = String::from_utf16(&utf16) {
                    if !name.is_empty() && sample_names.len() < 5 {
                        sample_names.push(name);
                    }
                }
            }
        }

        records += 1;
        offset += record_length;
    }

    NtfsUsnJrnlSummary {
        stream_name: stream_name.to_string(),
        bytes: bytes.len() as u64,
        records,
        sample_names,
    }
}

fn recover_entry_data(
    output_dir: &Path,
    entry: &NtfsEntry,
    stream_name: Option<&str>,
    stream: &DataStream,
    image: &[u8],
    boot: &NtfsBootInfo,
    bitmap: Option<&BitmapData>,
    overwrite: bool,
) -> io::Result<RecoveryAttempt> {
    match stream {
        DataStream::Resident(bytes) => {
            if bytes.is_empty() {
                return Ok(RecoveryAttempt {
                    path: None,
                    bytes_recovered: 0,
                    stream_kind: StreamKind::Resident,
                    note: Some("resident stream is empty".to_string()),
                });
            }

            let written = write_recovered_file(output_dir, entry, stream_name, bytes, overwrite)?;
            Ok(RecoveryAttempt {
                path: Some(written),
                bytes_recovered: bytes.len() as u64,
                stream_kind: StreamKind::Resident,
                note: None,
            })
        }
        DataStream::NonResident(stream) => {
            let (bytes, mut note) = match recover_non_resident_bytes(image, boot, stream, bitmap) {
                Ok(result) => result,
                Err(reason) => {
                    return Ok(RecoveryAttempt {
                        path: None,
                        bytes_recovered: 0,
                        stream_kind: StreamKind::NonResident,
                        note: Some(reason),
                    });
                }
            };

            if stream.encrypted {
                note = Some(note.unwrap_or_else(|| {
                    "encrypted stream recovered as raw encrypted bytes".to_string()
                }));
            }

            let written = write_recovered_file(output_dir, entry, stream_name, &bytes, overwrite)?;
            Ok(RecoveryAttempt {
                path: Some(written),
                bytes_recovered: bytes.len() as u64,
                stream_kind: StreamKind::NonResident,
                note: note.or_else(|| {
                    (stream.initialized_size < stream.real_size).then_some(
                        "stream extends beyond initialized bytes; trailing content may be zero-filled"
                            .to_string(),
                    )
                }),
            })
        }
    }
}

fn recover_non_resident_bytes(
    image: &[u8],
    boot: &NtfsBootInfo,
    stream: &NonResidentData,
    bitmap: Option<&BitmapData>,
) -> Result<(Vec<u8>, Option<String>), String> {
    if stream.compressed {
        return recover_compressed_non_resident_bytes(image, boot, stream);
    }
    recover_raw_non_resident_bytes(image, boot, stream, bitmap)
}

fn recover_raw_non_resident_bytes(
    image: &[u8],
    boot: &NtfsBootInfo,
    stream: &NonResidentData,
    bitmap: Option<&BitmapData>,
) -> Result<(Vec<u8>, Option<String>), String> {
    let target_size = usize::try_from(stream.real_size)
        .map_err(|_| "stream size exceeds this build's memory limits".to_string())?;
    let mut bytes = Vec::with_capacity(target_size.min(1024 * 1024));

    for run in &stream.runs {
        if bytes.len() >= target_size {
            break;
        }

        let run_size = run
            .cluster_count
            .checked_mul(boot.cluster_size)
            .ok_or_else(|| "run length overflowed cluster math".to_string())?;
        let remaining = target_size - bytes.len();
        let to_copy = usize::try_from(run_size)
            .map_err(|_| "run length exceeds this build's address space".to_string())?
            .min(remaining);

        append_run_bytes(&mut bytes, image, boot, run.start_lcn, to_copy)?;
    }

    let mut note = None;
    if bytes.len() < target_size {
        if let Some(bitmap) = bitmap {
            if let Some(last_lcn) = last_concrete_lcn(stream) {
                let added_clusters =
                    extend_from_bitmap(&mut bytes, image, boot, bitmap, last_lcn, target_size)?;
                if added_clusters > 0 {
                    note = Some(format!(
                        "bitmap heuristic extended {} cluster(s) beyond the declared runlist",
                        added_clusters
                    ));
                }
            }
        }
    }

    if bytes.len() < target_size {
        return Err("runlist does not cover the full declared stream size".to_string());
    }

    bytes.truncate(target_size);
    Ok((bytes, note))
}

fn recover_compressed_non_resident_bytes(
    image: &[u8],
    boot: &NtfsBootInfo,
    stream: &NonResidentData,
) -> Result<(Vec<u8>, Option<String>), String> {
    let target_size = usize::try_from(stream.real_size)
        .map_err(|_| "stream size exceeds this build's memory limits".to_string())?;
    let unit_clusters = if stream.compression_unit_shift == 0 {
        1
    } else {
        1u64 << stream.compression_unit_shift
    };
    let units = split_runs_into_units(&stream.runs, unit_clusters)?;
    let mut bytes = Vec::with_capacity(target_size.min(1024 * 1024));

    for unit in units {
        if bytes.len() >= target_size {
            break;
        }
        let logical_bytes = usize::try_from(
            unit.logical_clusters
                .checked_mul(boot.cluster_size)
                .ok_or_else(|| "compressed unit overflowed cluster math".to_string())?,
        )
        .map_err(|_| "compressed unit exceeds this build's address space".to_string())?
        .min(target_size - bytes.len());

        if unit.physical_clusters == 0 {
            bytes.resize(bytes.len() + logical_bytes, 0);
            continue;
        }

        if unit.physical_clusters == unit.logical_clusters {
            let raw = read_run_slice_bytes(image, boot, &unit.runs, logical_bytes)?;
            bytes.extend_from_slice(&raw);
            continue;
        }

        let physical_bytes = usize::try_from(
            unit.physical_clusters
                .checked_mul(boot.cluster_size)
                .ok_or_else(|| "compressed physical span overflowed cluster math".to_string())?,
        )
        .map_err(|_| "compressed physical span exceeds this build's address space".to_string())?;
        let raw = read_run_slice_bytes(image, boot, &unit.runs, physical_bytes)?;
        let decompressed = decompress_lznt1(&raw, logical_bytes)?;
        bytes.extend_from_slice(&decompressed);
    }

    if bytes.len() < target_size {
        return Err("compressed runlist does not cover the full declared stream size".to_string());
    }
    bytes.truncate(target_size);
    Ok((
        bytes,
        Some("compressed stream rebuilt from NTFS compression units".to_string()),
    ))
}

fn append_run_bytes(
    output: &mut Vec<u8>,
    image: &[u8],
    boot: &NtfsBootInfo,
    start_lcn: Option<u64>,
    to_copy: usize,
) -> Result<(), String> {
    match start_lcn {
        Some(lcn) => {
            let start = boot
                .volume_offset
                .checked_add(
                    lcn.checked_mul(boot.cluster_size)
                        .ok_or_else(|| "run offset overflowed cluster math".to_string())?,
                )
                .ok_or_else(|| "run offset overflowed image bounds".to_string())?;
            let start = usize::try_from(start)
                .map_err(|_| "run offset exceeds this build's address space".to_string())?;
            let end = start
                .checked_add(to_copy)
                .ok_or_else(|| "run end overflowed image bounds".to_string())?;
            let slice = image
                .get(start..end)
                .ok_or_else(|| "run points outside the available image bytes".to_string())?;
            output.extend_from_slice(slice);
        }
        None => output.resize(output.len() + to_copy, 0),
    }
    Ok(())
}

fn last_concrete_lcn(stream: &NonResidentData) -> Option<u64> {
    stream.runs.iter().rev().find_map(|run| {
        run.start_lcn
            .map(|start| start.saturating_add(run.cluster_count))
    })
}

fn extend_from_bitmap(
    bytes: &mut Vec<u8>,
    image: &[u8],
    boot: &NtfsBootInfo,
    bitmap: &BitmapData,
    mut next_lcn: u64,
    target_size: usize,
) -> Result<u64, String> {
    let mut added_clusters = 0u64;
    let cluster_size = usize::try_from(boot.cluster_size)
        .map_err(|_| "cluster size exceeds this build's address space".to_string())?;

    while bytes.len() < target_size
        && next_lcn < bitmap.summary.tracked_clusters
        && bitmap_cluster_is_free(bitmap, next_lcn)
    {
        let to_copy = cluster_size.min(target_size - bytes.len());
        append_run_bytes(bytes, image, boot, Some(next_lcn), to_copy)?;
        next_lcn = next_lcn.saturating_add(1);
        added_clusters = added_clusters.saturating_add(1);
    }

    Ok(added_clusters)
}

fn bitmap_cluster_is_free(bitmap: &BitmapData, cluster: u64) -> bool {
    let byte = usize::try_from(cluster / 8).ok();
    let bit = (cluster % 8) as u8;
    byte.and_then(|index| bitmap.bits.get(index))
        .map(|value| value & (1 << bit) == 0)
        .unwrap_or(false)
}

struct CompressionUnit {
    runs: Vec<DataRun>,
    logical_clusters: u64,
    physical_clusters: u64,
}

fn split_runs_into_units(
    runs: &[DataRun],
    unit_clusters: u64,
) -> Result<Vec<CompressionUnit>, String> {
    if unit_clusters == 0 {
        return Err("invalid compression unit size".to_string());
    }

    let mut units = Vec::new();
    let mut current_runs = Vec::new();
    let mut current_logical = 0u64;
    let mut current_physical = 0u64;

    for run in runs {
        let mut remaining = run.cluster_count;
        let mut current_lcn = run.start_lcn;
        while remaining > 0 {
            let available = unit_clusters.saturating_sub(current_logical);
            let take = remaining.min(available);
            current_runs.push(DataRun {
                start_lcn: current_lcn,
                cluster_count: take,
            });
            current_logical += take;
            if current_lcn.is_some() {
                current_physical += take;
                current_lcn = current_lcn.map(|value| value.saturating_add(take));
            }
            remaining -= take;

            if current_logical == unit_clusters {
                units.push(CompressionUnit {
                    runs: std::mem::take(&mut current_runs),
                    logical_clusters: current_logical,
                    physical_clusters: current_physical,
                });
                current_logical = 0;
                current_physical = 0;
            }
        }
    }

    if current_logical > 0 {
        units.push(CompressionUnit {
            runs: current_runs,
            logical_clusters: current_logical,
            physical_clusters: current_physical,
        });
    }

    Ok(units)
}

fn read_run_slice_bytes(
    image: &[u8],
    boot: &NtfsBootInfo,
    runs: &[DataRun],
    target_size: usize,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(target_size.min(1024 * 1024));
    for run in runs {
        if bytes.len() >= target_size {
            break;
        }
        let run_size = run
            .cluster_count
            .checked_mul(boot.cluster_size)
            .ok_or_else(|| "run length overflowed cluster math".to_string())?;
        let to_copy = usize::try_from(run_size)
            .map_err(|_| "run length exceeds this build's address space".to_string())?
            .min(target_size - bytes.len());
        append_run_bytes(&mut bytes, image, boot, run.start_lcn, to_copy)?;
    }
    if bytes.len() < target_size {
        return Err("run slice does not cover the requested number of bytes".to_string());
    }
    bytes.truncate(target_size);
    Ok(bytes)
}

fn decompress_lznt1(input: &[u8], expected_size: usize) -> Result<Vec<u8>, String> {
    let mut src = 0usize;
    let mut output = Vec::with_capacity(expected_size.min(1024 * 1024));

    while src + 2 <= input.len() && output.len() < expected_size {
        let header = u16::from_le_bytes([input[src], input[src + 1]]);
        src += 2;
        let chunk_size = ((header & 0x0FFF) as usize) + 1;
        let compressed = header & 0x8000 != 0;
        let chunk_end = src.saturating_add(chunk_size).min(input.len());

        if !compressed {
            output.extend_from_slice(&input[src..chunk_end]);
            src = chunk_end;
            continue;
        }

        let chunk_start = output.len();
        while src < chunk_end && output.len() < expected_size {
            let flags = *input
                .get(src)
                .ok_or_else(|| "truncated compressed chunk flags".to_string())?;
            src += 1;

            for bit in 0..8 {
                if src >= chunk_end || output.len() >= expected_size {
                    break;
                }
                if (flags >> bit) & 1 == 0 {
                    output.push(input[src]);
                    src += 1;
                    continue;
                }

                if src + 2 > chunk_end {
                    return Err("truncated compressed chunk token".to_string());
                }

                let token = u16::from_le_bytes([input[src], input[src + 1]]);
                src += 2;
                let produced = output.len().saturating_sub(chunk_start);
                let mut displacement_bits = 12usize;
                while displacement_bits > 4 && produced >= (1usize << (16 - displacement_bits)) {
                    displacement_bits -= 1;
                }
                let length_bits = 16 - displacement_bits;
                let length_mask = (1u16 << length_bits) - 1;
                let length = (token & length_mask) as usize + 3;
                let displacement = ((token >> length_bits) as usize) + 1;
                for _ in 0..length {
                    let source = output
                        .len()
                        .checked_sub(displacement)
                        .ok_or_else(|| "invalid LZNT1 back-reference".to_string())?;
                    let byte = *output
                        .get(source)
                        .ok_or_else(|| "LZNT1 back-reference fell outside output".to_string())?;
                    output.push(byte);
                    if output.len() >= expected_size {
                        break;
                    }
                }
            }
        }
    }

    if output.len() < expected_size {
        return Err("LZNT1 decompression ended before the expected size".to_string());
    }

    output.truncate(expected_size);
    Ok(output)
}

fn write_recovered_file(
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

#[cfg(test)]
mod tests {
    use super::{NtfsOptions, inspect_ntfs_bytes};

    #[test]
    fn enumerates_deleted_resident_and_non_resident_entries() {
        let image = build_test_image();
        let report = inspect_ntfs_bytes(
            &image,
            "test.img".to_string(),
            &NtfsOptions {
                max_records: 4,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(report.boot.record_size, 1024);
        assert_eq!(report.deleted_entries, 2);
        assert_eq!(report.returned_entries, 3);

        let resident = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("secret.txt"))
            .unwrap();
        assert!(resident.deleted);
        assert_eq!(resident.resident_data_size, Some(5));
        assert_eq!(resident.real_size, Some(5));

        let non_resident = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("archive.bin"))
            .unwrap();
        assert!(non_resident.deleted);
        assert_eq!(non_resident.non_resident_data_size, Some(13));
        assert_eq!(non_resident.data_runs, Some(1));
    }

    #[test]
    fn filters_to_deleted_and_extracts_deleted_data() {
        let image = build_test_image();
        let output_dir =
            std::env::temp_dir().join(format!("hashendra-ntfs-recovery-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&output_dir);

        let report = inspect_ntfs_bytes(
            &image,
            "test.img".to_string(),
            &NtfsOptions {
                max_records: 4,
                deleted_only: true,
                extract_data_to: Some(output_dir.clone()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(report.returned_entries, 2);
        assert_eq!(report.resident_recovered, 2);
        assert_eq!(report.non_resident_recovered, 1);
        assert_eq!(report.recovered_bytes, 32);

        let resident_path = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("secret.txt"))
            .and_then(|entry| entry.extracted_path.as_ref())
            .unwrap();
        let resident = std::fs::read(resident_path).unwrap();
        assert_eq!(resident, b"hello");

        let non_resident_path = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("archive.bin"))
            .and_then(|entry| entry.extracted_path.as_ref())
            .unwrap();
        let non_resident = std::fs::read(non_resident_path).unwrap();
        assert_eq!(non_resident, b"forensic-data");

        let _ = std::fs::remove_dir_all(output_dir);
    }

    #[test]
    fn supports_nonzero_volume_offsets() {
        let mut prefixed = vec![0u8; 512];
        prefixed.extend(build_test_image());

        let report = inspect_ntfs_bytes(
            &prefixed,
            "offset.img".to_string(),
            &NtfsOptions {
                volume_offset: 512,
                max_records: 4,
                deleted_only: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(report.boot.volume_offset, 512);
        assert_eq!(report.returned_entries, 2);
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.name.as_deref() == Some("secret.txt"))
        );
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.name.as_deref() == Some("archive.bin"))
        );
    }

    #[test]
    fn reports_named_ads_and_system_artifacts() {
        let image = build_test_image();
        let report = inspect_ntfs_bytes(
            &image,
            "test.img".to_string(),
            &NtfsOptions {
                max_records: 10,
                include_directories: true,
                ..Default::default()
            },
        )
        .unwrap();

        let secret = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("secret.txt"))
            .unwrap();
        assert_eq!(secret.alternate_data_streams.len(), 1);
        assert_eq!(secret.alternate_data_streams[0].name, "Zone.Identifier");

        let bitmap = report.system_artifacts.bitmap.as_ref().unwrap();
        assert!(bitmap.tracked_clusters >= 64);
        assert!(bitmap.allocated_clusters >= 5);

        let logfile = report.system_artifacts.logfile.as_ref().unwrap();
        assert_eq!(logfile.restart_pages, 1);
        assert_eq!(logfile.first_magic.as_deref(), Some("RSTR"));

        let usn = report.system_artifacts.usn_journal.as_ref().unwrap();
        assert_eq!(usn.stream_name, "$J");
        assert_eq!(usn.records, 1);
        assert!(usn.sample_names.iter().any(|name| name == "deleted.tmp"));
    }

    #[test]
    fn recovers_ads_bitmap_extended_compressed_and_encrypted_streams() {
        let image = build_test_image();
        let output_dir =
            std::env::temp_dir().join(format!("hashendra-ntfs-streams-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&output_dir);

        let report = inspect_ntfs_bytes(
            &image,
            "test.img".to_string(),
            &NtfsOptions {
                max_records: 10,
                deleted_only: true,
                extract_data_to: Some(output_dir.clone()),
                ..Default::default()
            },
        )
        .unwrap();

        let secret = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("secret.txt"))
            .unwrap();
        let ads_path = secret.alternate_data_streams[0]
            .extracted_path
            .as_ref()
            .unwrap();
        assert_eq!(std::fs::read(ads_path).unwrap(), b"[ZoneTransfer]");

        let fragment = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("fragment.bin"))
            .unwrap();
        assert!(
            fragment
                .recovery_note
                .as_deref()
                .unwrap_or_default()
                .contains("bitmap heuristic")
        );
        let fragment_path = fragment.extracted_path.as_ref().unwrap();
        let fragment_bytes = std::fs::read(fragment_path).unwrap();
        assert_eq!(fragment_bytes.len(), 700);
        assert_eq!(&fragment_bytes[..4], b"frag");

        let compressed = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("compressed.bin"))
            .unwrap();
        assert!(
            compressed
                .recovery_note
                .as_deref()
                .unwrap_or_default()
                .contains("compressed stream rebuilt")
        );
        let compressed_path = compressed.extracted_path.as_ref().unwrap();
        assert_eq!(std::fs::read(compressed_path).unwrap(), vec![b'C'; 600]);

        let encrypted = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("secret.enc"))
            .unwrap();
        assert!(
            encrypted
                .recovery_note
                .as_deref()
                .unwrap_or_default()
                .contains("raw encrypted")
        );
        let encrypted_path = encrypted.extracted_path.as_ref().unwrap();
        assert_eq!(std::fs::read(encrypted_path).unwrap(), b"cipher");

        let _ = std::fs::remove_dir_all(output_dir);
    }

    fn build_test_image() -> Vec<u8> {
        let mut image = vec![0u8; 65536];
        image[3..11].copy_from_slice(b"NTFS    ");
        image[11..13].copy_from_slice(&512u16.to_le_bytes());
        image[13] = 1;
        image[40..48].copy_from_slice(&32768u64.to_le_bytes());
        image[48..56].copy_from_slice(&4u64.to_le_bytes());
        image[56..64].copy_from_slice(&8u64.to_le_bytes());
        image[64] = 0xF6;
        image[68] = 0xF4;
        image[72..80].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
        image[510] = 0x55;
        image[511] = 0xAA;

        let mft_offset = 4 * 512;
        let first = build_resident_record(0, true, false, Some("MFT"), None);
        let second = build_resident_record_with_streams(
            1,
            false,
            false,
            Some("secret.txt"),
            Some(b"hello"),
            &[("Zone.Identifier", b"[ZoneTransfer]")],
        );
        let third = build_non_resident_record(
            2,
            false,
            false,
            "archive.bin",
            b"forensic-data".len() as u64,
            512,
            &[(32, 1)],
        );
        let bitmap =
            build_resident_record(4, true, false, Some("$Bitmap"), Some(&build_bitmap_bytes()));
        let logfile = build_resident_record(
            5,
            true,
            false,
            Some("$LogFile"),
            Some(&build_logfile_bytes()),
        );
        let usn = build_resident_record_with_streams(
            6,
            true,
            false,
            Some("$UsnJrnl"),
            None,
            &[("$J", &build_usn_record("deleted.tmp"))],
        );
        let fragment =
            build_non_resident_record(7, false, false, "fragment.bin", 700, 1024, &[(40, 1)]);
        let compressed = build_non_resident_record_with_flags(
            8,
            false,
            false,
            "compressed.bin",
            600,
            1024,
            &[(42, 2)],
            0x0001,
            1,
        );
        let encrypted = build_non_resident_record_with_flags(
            9,
            false,
            false,
            "secret.enc",
            6,
            512,
            &[(44, 1)],
            0x4000,
            0,
        );
        image[mft_offset..mft_offset + 1024].copy_from_slice(&first);
        image[mft_offset + 1024..mft_offset + 2048].copy_from_slice(&second);
        image[mft_offset + 2048..mft_offset + 3072].copy_from_slice(&third);
        image[mft_offset + 4096..mft_offset + 5120].copy_from_slice(&bitmap);
        image[mft_offset + 5120..mft_offset + 6144].copy_from_slice(&logfile);
        image[mft_offset + 6144..mft_offset + 7168].copy_from_slice(&usn);
        image[mft_offset + 7168..mft_offset + 8192].copy_from_slice(&fragment);
        image[mft_offset + 8192..mft_offset + 9216].copy_from_slice(&compressed);
        image[mft_offset + 9216..mft_offset + 10240].copy_from_slice(&encrypted);
        image[32 * 512..32 * 512 + b"forensic-data".len()].copy_from_slice(b"forensic-data");
        image[40 * 512..40 * 512 + 512].fill(b'F');
        image[40 * 512..40 * 512 + 4].copy_from_slice(b"frag");
        image[41 * 512..41 * 512 + 188].fill(b'G');
        image[42 * 512..42 * 512 + 600].fill(b'C');
        image[44 * 512..44 * 512 + 6].copy_from_slice(b"cipher");

        image
    }

    fn build_resident_record(
        record_number: u32,
        in_use: bool,
        directory: bool,
        name: Option<&str>,
        resident_data: Option<&[u8]>,
    ) -> Vec<u8> {
        build_resident_record_with_streams(
            record_number,
            in_use,
            directory,
            name,
            resident_data,
            &[],
        )
    }

    fn build_resident_record_with_streams(
        record_number: u32,
        in_use: bool,
        directory: bool,
        name: Option<&str>,
        resident_data: Option<&[u8]>,
        named_streams: &[(&str, &[u8])],
    ) -> Vec<u8> {
        let mut record = vec![0u8; 1024];
        record[..4].copy_from_slice(b"FILE");
        record[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        record[6..8].copy_from_slice(&3u16.to_le_bytes());
        record[16..18].copy_from_slice(&1u16.to_le_bytes());
        record[18..20].copy_from_slice(&1u16.to_le_bytes());
        record[20..22].copy_from_slice(&0x38u16.to_le_bytes());

        let mut flags = 0u16;
        if in_use {
            flags |= 0x01;
        }
        if directory {
            flags |= 0x02;
        }
        record[22..24].copy_from_slice(&flags.to_le_bytes());
        record[28..32].copy_from_slice(&(1024u32).to_le_bytes());
        record[44..48].copy_from_slice(&record_number.to_le_bytes());

        let mut cursor = 0x38usize;
        if let Some(name) = name {
            cursor = write_resident_attr(
                &mut record,
                cursor,
                0x30,
                &build_file_name_attr(
                    name,
                    resident_data.map_or(0, |data| data.len() as u64),
                    resident_data.map_or(0, |data| data.len() as u64),
                ),
            );
        }

        if let Some(data) = resident_data {
            cursor = write_resident_attr(&mut record, cursor, 0x80, data);
        }

        for (stream_name, bytes) in named_streams {
            cursor = write_named_resident_attr(&mut record, cursor, 0x80, stream_name, bytes);
        }

        record[cursor..cursor + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        cursor += 4;
        record[24..28].copy_from_slice(&(cursor as u32).to_le_bytes());

        record[0x30..0x32].copy_from_slice(&0xAAAAu16.to_le_bytes());
        record[0x32..0x34].copy_from_slice(&0u16.to_le_bytes());
        record[0x34..0x36].copy_from_slice(&0u16.to_le_bytes());
        record[510..512].copy_from_slice(&0xAAAAu16.to_le_bytes());
        record[1022..1024].copy_from_slice(&0xAAAAu16.to_le_bytes());

        record
    }

    fn build_non_resident_record(
        record_number: u32,
        in_use: bool,
        directory: bool,
        name: &str,
        real_size: u64,
        allocated_size: u64,
        runs: &[(u64, u64)],
    ) -> Vec<u8> {
        build_non_resident_record_with_flags(
            record_number,
            in_use,
            directory,
            name,
            real_size,
            allocated_size,
            runs,
            0,
            0,
        )
    }

    fn build_non_resident_record_with_flags(
        record_number: u32,
        in_use: bool,
        directory: bool,
        name: &str,
        real_size: u64,
        allocated_size: u64,
        runs: &[(u64, u64)],
        flags: u16,
        compression_unit_shift: u16,
    ) -> Vec<u8> {
        let mut record = build_resident_record(record_number, in_use, directory, Some(name), None);
        let mut cursor = 0x38usize;
        cursor = write_resident_attr(
            &mut record,
            cursor,
            0x30,
            &build_file_name_attr(name, allocated_size, real_size),
        );
        cursor = write_non_resident_attr_with_flags(
            &mut record,
            cursor,
            0x80,
            real_size,
            allocated_size,
            runs,
            flags,
            compression_unit_shift,
        );
        record[cursor..cursor + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        cursor += 4;
        record[24..28].copy_from_slice(&(cursor as u32).to_le_bytes());
        record
    }

    fn build_file_name_attr(name: &str, allocated_size: u64, real_size: u64) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let mut value = vec![0u8; 66 + name_utf16.len() * 2];
        value[0..8].copy_from_slice(&5u64.to_le_bytes());
        value[40..48].copy_from_slice(&allocated_size.to_le_bytes());
        value[48..56].copy_from_slice(&real_size.to_le_bytes());
        value[64] = name_utf16.len() as u8;
        value[65] = 1;
        for (index, unit) in name_utf16.iter().enumerate() {
            let offset = 66 + index * 2;
            value[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        value
    }

    fn write_resident_attr(
        record: &mut [u8],
        offset: usize,
        attr_type: u32,
        value: &[u8],
    ) -> usize {
        let header_size = 24usize;
        let attr_len = align8(header_size + value.len());
        record[offset..offset + 4].copy_from_slice(&attr_type.to_le_bytes());
        record[offset + 4..offset + 8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        record[offset + 8] = 0;
        record[offset + 9] = 0;
        record[offset + 10..offset + 12].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 12..offset + 14].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 14..offset + 16].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 16..offset + 20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        record[offset + 20..offset + 22].copy_from_slice(&(header_size as u16).to_le_bytes());
        record[offset + 22] = 0;
        record[offset + 23] = 0;
        record[offset + header_size..offset + header_size + value.len()].copy_from_slice(value);
        offset + attr_len
    }

    fn write_named_resident_attr(
        record: &mut [u8],
        offset: usize,
        attr_type: u32,
        name: &str,
        value: &[u8],
    ) -> usize {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes = name_utf16
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        let name_offset = 24usize;
        let value_offset = align8(name_offset + name_bytes.len());
        let attr_len = align8(value_offset + value.len());
        record[offset..offset + 4].copy_from_slice(&attr_type.to_le_bytes());
        record[offset + 4..offset + 8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        record[offset + 8] = 0;
        record[offset + 9] = name_utf16.len() as u8;
        record[offset + 10..offset + 12].copy_from_slice(&(name_offset as u16).to_le_bytes());
        record[offset + 12..offset + 14].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 14..offset + 16].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 16..offset + 20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        record[offset + 20..offset + 22].copy_from_slice(&(value_offset as u16).to_le_bytes());
        record[offset + 22] = 0;
        record[offset + 23] = 0;
        record[offset + name_offset..offset + name_offset + name_bytes.len()]
            .copy_from_slice(&name_bytes);
        record[offset + value_offset..offset + value_offset + value.len()].copy_from_slice(value);
        offset + attr_len
    }

    fn write_non_resident_attr_with_flags(
        record: &mut [u8],
        offset: usize,
        attr_type: u32,
        real_size: u64,
        allocated_size: u64,
        runs: &[(u64, u64)],
        flags: u16,
        compression_unit_shift: u16,
    ) -> usize {
        let header_size = 64usize;
        let runlist = build_runlist(runs);
        let total_clusters: u64 = runs.iter().map(|(_, cluster_count)| *cluster_count).sum();
        let attr_len = align8(header_size + runlist.len());
        record[offset..offset + 4].copy_from_slice(&attr_type.to_le_bytes());
        record[offset + 4..offset + 8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        record[offset + 8] = 1;
        record[offset + 9] = 0;
        record[offset + 10..offset + 12].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 12..offset + 14].copy_from_slice(&flags.to_le_bytes());
        record[offset + 14..offset + 16].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 16..offset + 24].copy_from_slice(&0u64.to_le_bytes());
        record[offset + 24..offset + 32]
            .copy_from_slice(&total_clusters.saturating_sub(1).to_le_bytes());
        record[offset + 32..offset + 34].copy_from_slice(&(header_size as u16).to_le_bytes());
        record[offset + 34..offset + 36].copy_from_slice(&compression_unit_shift.to_le_bytes());
        record[offset + 36..offset + 40].copy_from_slice(&0u32.to_le_bytes());
        record[offset + 40..offset + 48].copy_from_slice(&allocated_size.to_le_bytes());
        record[offset + 48..offset + 56].copy_from_slice(&real_size.to_le_bytes());
        record[offset + 56..offset + 64].copy_from_slice(&real_size.to_le_bytes());
        record[offset + header_size..offset + header_size + runlist.len()]
            .copy_from_slice(&runlist);
        offset + attr_len
    }

    fn build_bitmap_bytes() -> Vec<u8> {
        let mut bitmap = vec![0u8; 8];
        for cluster in [32u64, 40, 42, 43, 44] {
            let index = (cluster / 8) as usize;
            let bit = (cluster % 8) as u8;
            bitmap[index] |= 1 << bit;
        }
        bitmap
    }

    fn build_logfile_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; 512];
        bytes[..4].copy_from_slice(b"RSTR");
        bytes
    }

    fn build_usn_record(name: &str) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes = name_utf16
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        let record_length = align8(60 + name_bytes.len());
        let mut record = vec![0u8; record_length];
        record[0..4].copy_from_slice(&(record_length as u32).to_le_bytes());
        record[4..6].copy_from_slice(&2u16.to_le_bytes());
        record[6..8].copy_from_slice(&0u16.to_le_bytes());
        record[56..58].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        record[58..60].copy_from_slice(&60u16.to_le_bytes());
        record[60..60 + name_bytes.len()].copy_from_slice(&name_bytes);
        record
    }

    fn build_runlist(runs: &[(u64, u64)]) -> Vec<u8> {
        let mut runlist = Vec::new();
        let mut previous_lcn = 0i64;

        for &(lcn, cluster_count) in runs {
            let length_bytes = minimal_unsigned_bytes(cluster_count);
            let delta = lcn as i64 - previous_lcn;
            let offset_bytes = minimal_signed_bytes(delta);
            runlist.push(((offset_bytes.len() as u8) << 4) | (length_bytes.len() as u8));
            runlist.extend_from_slice(&length_bytes);
            runlist.extend_from_slice(&offset_bytes);
            previous_lcn = lcn as i64;
        }

        runlist.push(0);
        runlist
    }

    fn minimal_unsigned_bytes(value: u64) -> Vec<u8> {
        let bytes = value.to_le_bytes();
        let mut width = bytes.len();
        while width > 1 && bytes[width - 1] == 0 {
            width -= 1;
        }
        bytes[..width].to_vec()
    }

    fn minimal_signed_bytes(value: i64) -> Vec<u8> {
        let bytes = value.to_le_bytes();
        let mut width = bytes.len();
        while width > 1 {
            let keep_sign = (bytes[width - 1] == 0x00 && bytes[width - 2] & 0x80 == 0)
                || (bytes[width - 1] == 0xFF && bytes[width - 2] & 0x80 != 0);
            if keep_sign {
                width -= 1;
            } else {
                break;
            }
        }
        bytes[..width].to_vec()
    }

    fn align8(value: usize) -> usize {
        (value + 7) & !7
    }
}
