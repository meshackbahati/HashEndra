use super::{BitmapData, DataRun, DataStream, NamedDataStream, NonResidentData, NtfsBootInfo};
use super::{NtfsAlternateDataStream, NtfsBitmapSummary, NtfsEntry, NtfsLogFileSummary};
use super::{NtfsSystemArtifacts, ParsedEntry};
use super::{le_u16, le_u32, le_u64};
use super::recover::{parse_usn_journal_summary, recover_stream_bytes_for_analysis};

pub(crate) fn parse_boot_info(data: &[u8], volume_offset: usize) -> Option<NtfsBootInfo> {
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

pub(crate) fn decode_record_size(raw: u8, cluster_size: u64) -> Option<usize> {
    let signed = raw as i8;
    if signed > 0 {
        Some((cluster_size * signed as u64) as usize)
    } else if signed < 0 {
        Some(1usize << (-signed as usize))
    } else {
        None
    }
}

pub(crate) fn parse_record(record: &[u8], fallback_record_number: u64) -> Option<ParsedEntry> {
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

pub(crate) fn apply_fixup(record: &[u8]) -> Option<Vec<u8>> {
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

pub(crate) struct FileNameAttr {
    parent_reference: u64,
    allocated_size: u64,
    real_size: u64,
    namespace: u8,
    name: String,
}

pub(crate) fn parse_file_name_attr(value: &[u8]) -> Option<FileNameAttr> {
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
        .as_chunks::<2>().0.iter()
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

pub(crate) fn namespace_rank(namespace: u8) -> u8 {
    match namespace {
        3 => 4,
        1 => 3,
        0 => 2,
        2 => 1,
        _ => 0,
    }
}

pub(crate) fn namespace_name(namespace: u8) -> &'static str {
    match namespace {
        0 => "POSIX",
        1 => "Win32",
        2 => "DOS",
        3 => "Win32&DOS",
        _ => "Unknown",
    }
}

pub(crate) fn parse_attribute_name(
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
        .as_chunks::<2>().0.iter()
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&utf16)
        .ok()
        .filter(|value| !value.is_empty())
}

pub(crate) fn parse_non_resident_data_attr(
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

pub(crate) fn parse_data_runs(runlist: &[u8]) -> Option<Vec<DataRun>> {
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

pub(crate) fn read_unsigned_le(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }

    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= (*byte as u64) << (index * 8);
    }
    Some(value)
}

pub(crate) fn read_signed_le(bytes: &[u8]) -> Option<i64> {
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

pub(crate) fn parse_bitmap_data(
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

pub(crate) fn analyze_system_artifacts(
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
        && let Ok(bytes) = recover_stream_bytes_for_analysis(image, boot, stream, bitmap) {
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

    if let Some((stream_name, stream)) = entries
        .iter()
        .find(|entry| entry.entry.name.as_deref() == Some("$UsnJrnl"))
        .and_then(|entry| {
            entry.alternate_streams.iter().find_map(|stream| {
                (stream.report.name == "$J" || stream.report.name == "J")
                    .then_some((stream.report.name.clone(), &stream.stream))
            })
        })
        && let Ok(bytes) = recover_stream_bytes_for_analysis(image, boot, stream, bitmap) {
            artifacts.usn_journal = Some(parse_usn_journal_summary(&stream_name, &bytes));
        }

    artifacts
}
