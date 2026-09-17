use super::{BitmapData, DataRun, DataStream, NonResidentData, NtfsBootInfo, NtfsEntry};
use super::{NtfsUsnJrnlSummary, RecoveryAttempt, StreamKind};
use super::{le_u16, le_u32, write_recovered_file};
use std::io;
use std::path::Path;

pub(crate) fn recover_stream_bytes_for_analysis(
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

pub(crate) fn parse_usn_journal_summary(stream_name: &str, bytes: &[u8]) -> NtfsUsnJrnlSummary {
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
                    .as_chunks::<2>().0.iter()
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect::<Vec<_>>();
                if let Ok(name) = String::from_utf16(&utf16)
                    && !name.is_empty() && sample_names.len() < 5 {
                        sample_names.push(name);
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

/// Inputs shared by every per-stream recovery call, so the arg list stays small.
pub(crate) struct EntryRecovery<'a> {
    pub(crate) output_dir: &'a Path,
    pub(crate) image: &'a [u8],
    pub(crate) boot: &'a NtfsBootInfo,
    pub(crate) bitmap: Option<&'a BitmapData>,
    pub(crate) overwrite: bool,
}

pub(crate) fn recover_entry_data(
    ctx: &EntryRecovery<'_>,
    entry: &NtfsEntry,
    stream_name: Option<&str>,
    stream: &DataStream,
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

            let written = write_recovered_file(ctx.output_dir, entry, stream_name, bytes, ctx.overwrite)?;
            Ok(RecoveryAttempt {
                path: Some(written),
                bytes_recovered: bytes.len() as u64,
                stream_kind: StreamKind::Resident,
                note: None,
            })
        }
        DataStream::NonResident(stream) => {
            let (bytes, mut note) = match recover_non_resident_bytes(ctx.image, ctx.boot, stream, ctx.bitmap) {
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

            let written = write_recovered_file(ctx.output_dir, entry, stream_name, &bytes, ctx.overwrite)?;
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

pub(crate) fn recover_non_resident_bytes(
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

pub(crate) fn recover_raw_non_resident_bytes(
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
    if bytes.len() < target_size
        && let Some(bitmap) = bitmap
            && let Some(last_lcn) = last_concrete_lcn(stream) {
                let added_clusters =
                    extend_from_bitmap(&mut bytes, image, boot, bitmap, last_lcn, target_size)?;
                if added_clusters > 0 {
                    note = Some(format!(
                        "bitmap heuristic extended {} cluster(s) beyond the declared runlist",
                        added_clusters
                    ));
                }
            }

    if bytes.len() < target_size {
        return Err("runlist does not cover the full declared stream size".to_string());
    }

    bytes.truncate(target_size);
    Ok((bytes, note))
}

pub(crate) fn recover_compressed_non_resident_bytes(
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

pub(crate) fn append_run_bytes(
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

pub(crate) fn last_concrete_lcn(stream: &NonResidentData) -> Option<u64> {
    stream.runs.iter().rev().find_map(|run| {
        run.start_lcn
            .map(|start| start.saturating_add(run.cluster_count))
    })
}

pub(crate) fn extend_from_bitmap(
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

pub(crate) fn bitmap_cluster_is_free(bitmap: &BitmapData, cluster: u64) -> bool {
    let byte = usize::try_from(cluster / 8).ok();
    let bit = (cluster % 8) as u8;
    byte.and_then(|index| bitmap.bits.get(index))
        .map(|value| value & (1 << bit) == 0)
        .unwrap_or(false)
}

pub(crate) struct CompressionUnit {
    runs: Vec<DataRun>,
    logical_clusters: u64,
    physical_clusters: u64,
}

pub(crate) fn split_runs_into_units(
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

pub(crate) fn read_run_slice_bytes(
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

pub(crate) fn decompress_lznt1(input: &[u8], expected_size: usize) -> Result<Vec<u8>, String> {
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
