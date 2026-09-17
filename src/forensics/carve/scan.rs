use super::config::sanitize_component;
use super::profiles::builtin_profiles;
use super::{BytePattern, CarveOptions, CarveProfile, CarveReport, ProfileMatch};
use crate::detectors::stego::{identify_file_signature, locate_file_end};
use crate::forensics::inspect::{inspect_artifact, ArtifactInspection};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub(crate) fn effective_profiles(options: &CarveOptions) -> Vec<CarveProfile> {
    let mut profiles = builtin_profiles();
    profiles.extend(options.profiles.clone());
    profiles
}

pub(crate) fn iter_source_files(path: &Path, recursive: bool) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }

    let walker = if recursive {
        walkdir::WalkDir::new(path)
    } else {
        walkdir::WalkDir::new(path).max_depth(1)
    };

    let mut files: Vec<_> = walker
        .into_iter()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.into_path())
        .filter(|candidate| candidate.is_file())
        .collect();
    files.sort();
    files
}

pub(crate) fn scan_profiles(data: &[u8], profiles: &[CarveProfile], quick: bool) -> Vec<ProfileMatch> {
    let local_data = data;
    let mut matches: Vec<(usize, usize, usize)> = profiles
        .par_iter()
        .enumerate()
        .flat_map(|(profile_index, profile)| {
            let mut profile_matches = Vec::new();
            for header in &profile.headers {
                if header.is_empty() || header.len() > local_data.len() {
                    continue;
                }
                let max_offset = local_data.len() - header.len();
                for offset in 0..=max_offset {
                    if header.matches_at(local_data, offset) {
                        profile_matches.push((offset, header.len(), profile_index));
                        if quick {
                            break;
                        }
                    }
                }
                if quick && !profile_matches.is_empty() {
                    break;
                }
            }
            profile_matches
        })
        .collect();

    // Sort by offset, then by extension for deterministic dedup
    matches.sort_by(|a, b| a.0.cmp(&b.0).then(
        profiles[a.2].extension.cmp(&profiles[b.2].extension)
    ));

    // Deduplicate: keep first match per (offset, extension) pair
    let mut seen = BTreeSet::new();
    matches
        .into_iter()
        .filter(|(offset, _, profile_index)| {
            seen.insert((*offset, profiles[*profile_index].extension.clone()))
        })
        .map(|(offset, header_len, profile_index)| ProfileMatch {
            offset,
            header_len,
            profile_index,
        })
        .collect()
}

pub(crate) fn determine_slice_end(
    data: &[u8],
    matches: &[ProfileMatch],
    index: usize,
    profiles: &[CarveProfile],
    options: &CarveOptions,
) -> usize {
    let current = &matches[index];
    let profile = &profiles[current.profile_index];

    // Priority 1: known end from locate_file_end (PNG IEND, JPEG EOI, etc.)
    if let Some(end) = locate_known_end(data, current.offset, &profile.extension) {
        return end.min(data.len());
    }

    // Priority 2: format-specific length hint from header
    if let Some(end) = compute_length_from_header(data, current.offset, &profile.extension) {
        return end.min(data.len());
    }

    // Priority 3: footer pattern match
    if let Some(footer) = &profile.footer
        && let Some(end) = find_pattern(data, current.offset + current.header_len, footer) {
            return end.saturating_add(footer.len()).min(data.len());
        }

    // Priority 4: next match boundary or max_size cap
    let next_offset = matches
        .iter()
        .skip(index + 1)
        .map(|candidate| candidate.offset)
        .find(|&offset| offset > current.offset);
    let capped_end = options
        .max_size
        .or(profile.max_size)
        .map(|limit| current.offset.saturating_add(limit))
        .unwrap_or(data.len())
        .min(data.len());

    next_offset.unwrap_or(capped_end).min(capped_end)
}

/// Estimates the file end from header length fields.
pub(crate) fn compute_length_from_header(data: &[u8], offset: usize, extension: &str) -> Option<usize> {
    let chunk = data.get(offset..)?;
    let file_len = chunk.len();

    match extension {
        // BMP: file size is at offset 2 (4 bytes LE)
        "bmp" if file_len >= 6 => {
            let sz = u32::from_le_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]) as usize;
            if sz >= offset + 6 && sz <= offset + file_len {
                Some(offset + sz)
            } else {
                None
            }
        }
        // GIF: trailer byte 0x3B. Scan from end.
        "gif" => {
            // Scan backward from the end for the trailer
            let search_start = (offset + 10).min(file_len);
            let rel_end = chunk[search_start.saturating_sub(10)..]
                .iter()
                .rposition(|&b| b == 0x3B)?;
            Some(offset + search_start.saturating_sub(10) + rel_end + 1)
        }
        // ZIP: EOCD + comment, up to 65557 bytes from end
        "zip" if file_len >= 22 => {
            let search_start = file_len.saturating_sub(22 + 65535);
            let eocd = chunk[search_start..file_len]
                .windows(4)
                .rposition(|w| w == b"PK\x05\x06")?;
            let eocd_abs = offset + search_start + eocd;
            if eocd_abs + 22 <= offset + file_len {
                let comment_len = u16::from_le_bytes([
                    data[eocd_abs + 20],
                    data[eocd_abs + 21],
                ]) as usize;
                Some((eocd_abs + 22 + comment_len).min(offset + file_len))
            } else {
                None
            }
        }
        // WAV/AVI: RIFF size at offset 4 (4 bytes LE)
        "wav" | "avi" if file_len >= 8 => {
            let sz = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) as usize;
            // RIFF size doesn't include the 8-byte header
            let total = offset + 8 + sz;
            if total <= offset + file_len && sz > 0 {
                Some(total)
            } else {
                None
            }
        }
        // MP3: scan for ID3v1 tag at end-128 or end-227
        "mp3" => {
            let mut end = file_len;
            // Check for ID3v1
            if file_len >= 128 && &chunk[file_len - 128..file_len - 125] == b"TAG" {
                end = file_len;
            }
            // Check for ID3v2 at start
            if file_len >= 10 && &chunk[..3] == b"ID3" {
                let size = ((chunk[6] as usize) << 21)
                    | ((chunk[7] as usize) << 14)
                    | ((chunk[8] as usize) << 7)
                    | (chunk[9] as usize);
                end = end.max(10 + size);
            }
            // Find first MPEG sync for duration estimate
            Some(offset + end)
        }
        _ => None,
    }
}

pub(crate) fn locate_known_end(data: &[u8], offset: usize, extension: &str) -> Option<usize> {
    let signature = identify_file_signature(&data[offset..])?;
    if signature.extension != extension {
        return None;
    }
    locate_file_end(data, offset, signature)
}

pub(crate) fn known_inspection(data: &[u8], offset: usize, slice_end: usize) -> Option<ArtifactInspection> {
    let signature = identify_file_signature(&data[offset..])?;
    inspect_artifact(&data[offset..slice_end], signature)
}

pub(crate) fn matches_type_filters(profile: &CarveProfile, filters: &BTreeSet<String>) -> bool {
    if filters.is_empty() {
        return true;
    }

    let extension = profile.extension.to_ascii_lowercase();
    let description = profile.description.to_ascii_lowercase();
    filters.contains(&extension) || filters.iter().any(|filter| description.contains(filter))
}

pub(crate) fn find_pattern(data: &[u8], start: usize, pattern: &BytePattern) -> Option<usize> {
    if pattern.is_empty() || start >= data.len() || pattern.len() > data.len().saturating_sub(start)
    {
        return None;
    }

    (start..=data.len() - pattern.len()).find(|&offset| pattern.matches_at(data, offset))
}

pub(crate) fn write_artifact(
    output_root: &Path,
    source_path: Option<&Path>,
    extension: &str,
    offset: usize,
    bytes: &[u8],
    overwrite: bool,
) -> io::Result<PathBuf> {
    let type_dir = output_root.join(extension);
    std::fs::create_dir_all(&type_dir)?;

    let source_stem = source_path
        .and_then(|path| path.file_stem())
        .or_else(|| source_path.and_then(|path| path.file_name()))
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "buffer".to_string());
    let base_name = format!("{}_{:08x}", sanitize_component(&source_stem), offset);
    let mut candidate = type_dir.join(format!("{}.{}", base_name, extension));

    if !overwrite {
        let mut suffix = 1usize;
        while candidate.exists() {
            candidate = type_dir.join(format!("{}_{}.{}", base_name, suffix, extension));
            suffix += 1;
        }
    }

    std::fs::write(&candidate, bytes)?;
    Ok(candidate)
}

pub(crate) fn write_audit_log(output_dir: &Path, report: &CarveReport) -> io::Result<PathBuf> {
    let path = output_dir.join("audit.txt");
    let mut file = File::create(&path)?;
    writeln!(file, "HashEndra Carve Audit")?;
    writeln!(file, "Input: {}", report.input)?;
    writeln!(
        file,
        "Config: {}",
        report.config_path.as_deref().unwrap_or("builtin")
    )?;
    writeln!(file, "Quick mode: {}", report.quick_mode)?;
    writeln!(file, "Scan offset: {}", report.scan_offset)?;
    writeln!(
        file,
        "Scan length: {}",
        report
            .scan_length
            .map(|value| value.to_string())
            .unwrap_or_else(|| "full".to_string())
    )?;
    writeln!(
        file,
        "Sector size: {}",
        report
            .sector_size
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string())
    )?;
    writeln!(file, "Files scanned: {}", report.files_scanned)?;
    writeln!(file, "Files readable: {}", report.files_readable)?;
    writeln!(file, "Matched: {}", report.matched)?;
    writeln!(file, "Written: {}", report.written)?;
    writeln!(file, "Bytes written: {}", report.bytes_written)?;
    writeln!(file, "Containers expanded: {}", report.containers_expanded)?;
    writeln!(
        file,
        "Container members written: {}",
        report.container_members_written
    )?;
    if !report.notes.is_empty() {
        writeln!(file, "Notes:")?;
        for note in &report.notes {
            writeln!(file, "  - {}", note)?;
        }
    }
    writeln!(file)?;

    for source in &report.sources {
        if source.artifacts.is_empty() {
            continue;
        }
        writeln!(file, "[{}]", source.source)?;
        for artifact in &source.artifacts {
            writeln!(
                file,
                "offset=0x{:08x} sector={} type={} length={} output={}",
                artifact.offset,
                artifact
                    .sector
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                artifact.extension,
                artifact.length.unwrap_or(0),
                artifact.extracted_path.as_deref().unwrap_or("audit-only")
            )?;
        }
        writeln!(file)?;
    }

    Ok(path)
}
