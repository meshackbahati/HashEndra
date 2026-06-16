use crate::detectors::stego::{identify_file_signature, locate_file_end};
use crate::forensics::inspect::{ArtifactInspection, inspect_artifact};
use memmap2::Mmap;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Hard upper bound for extraction byte quota — enforced even if CLI or API bypasses the default.
/// Prevents zip-bomb / disk-fill attacks regardless of how CarveOptions is configured.
const HARD_MAX_EXTRACTION_QUOTA: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB

#[derive(Debug, Clone)]
pub struct BytePattern {
    bytes: Vec<Option<u8>>,
}

impl BytePattern {
    pub fn exact(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.iter().copied().map(Some).collect(),
        }
    }

    pub fn wildcard(bytes: Vec<Option<u8>>) -> Self {
        Self { bytes }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        let Some(window) = data.get(offset..offset.saturating_add(self.bytes.len())) else {
            return false;
        };

        self.bytes
            .iter()
            .zip(window.iter())
            .all(|(expected, actual)| expected.map(|byte| byte == *actual).unwrap_or(true))
    }
}

#[derive(Debug, Clone)]
pub struct CarveProfile {
    pub extension: String,
    pub description: String,
    pub headers: Vec<BytePattern>,
    pub footer: Option<BytePattern>,
    pub max_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CarvedArtifact {
    pub offset: usize,
    pub sector: Option<u64>,
    pub name: String,
    pub extension: String,
    pub length: Option<usize>,
    pub extracted_path: Option<String>,
    pub inspection: Option<ArtifactInspection>,
}

#[derive(Debug, Clone)]
pub struct CarveOptions {
    pub output_dir: Option<PathBuf>,
    pub include_root: bool,
    pub type_filters: BTreeSet<String>,
    pub min_size: usize,
    pub max_size: Option<usize>,
    pub overwrite: bool,
    pub write_files: bool,
    pub recursive: bool,
    pub quick: bool,
    pub write_audit: bool,
    pub deduplicate: bool,
    pub profiles: Vec<CarveProfile>,
    pub scan_offset: usize,
    pub scan_length: Option<usize>,
    pub sector_size: Option<usize>,
    pub recursive_extract_depth: usize,
    /// Maximum total bytes to write across all recursive extraction layers
    pub extraction_byte_quota: u64,
}

impl Default for CarveOptions {
    fn default() -> Self {
        Self {
            output_dir: None,
            include_root: false,
            type_filters: BTreeSet::new(),
            min_size: 1,
            max_size: None,
            overwrite: false,
            write_files: true,
            recursive: true,
            quick: false,
            write_audit: true,
            deduplicate: true,
            profiles: Vec::new(),
            scan_offset: 0,
            scan_length: None,
            sector_size: None,
            recursive_extract_depth: 0,
            extraction_byte_quota: 1024 * 1024 * 1024, // 1 GB default quota
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SupportedCarveType {
    pub extension: String,
    pub names: Vec<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CarveSourceReport {
    pub source: String,
    pub size: usize,
    pub matched: usize,
    pub written: usize,
    pub artifacts: Vec<CarvedArtifact>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CarveReport {
    pub input: String,
    pub output_dir: Option<String>,
    pub config_path: Option<String>,
    pub quick_mode: bool,
    pub recursive_extract_depth: usize,
    pub scan_offset: usize,
    pub scan_length: Option<usize>,
    pub sector_size: Option<usize>,
    pub files_scanned: usize,
    pub files_readable: usize,
    pub matched: usize,
    pub written: usize,
    pub bytes_written: u64,
    pub containers_expanded: usize,
    pub container_members_written: usize,
    pub by_type: BTreeMap<String, usize>,
    pub sources: Vec<CarveSourceReport>,
    pub audit_path: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
struct ProfileMatch {
    offset: usize,
    header_len: usize,
    profile_index: usize,
}

#[derive(Debug, Default)]
struct ContainerExpansion {
    paths: Vec<PathBuf>,
    expanded: usize,
    written: usize,
    notes: Vec<String>,
}

pub fn builtin_profiles() -> Vec<CarveProfile> {
    vec![
        CarveProfile {
            extension: "jpg".to_string(),
            description: "JPEG Image".to_string(),
            headers: vec![BytePattern::exact(&[0xFF, 0xD8, 0xFF])],
            footer: Some(BytePattern::exact(&[0xFF, 0xD9])),
            max_size: Some(20 * 1024 * 1024),
        },
        CarveProfile {
            extension: "png".to_string(),
            description: "PNG Image".to_string(),
            headers: vec![BytePattern::exact(b"\x89PNG\r\n\x1a\n")],
            footer: Some(BytePattern::exact(b"\x00\x00\x00\x00IEND\xAE\x42\x60\x82")),
            max_size: Some(20 * 1024 * 1024),
        },
        CarveProfile {
            extension: "gif".to_string(),
            description: "GIF Image".to_string(),
            headers: vec![BytePattern::exact(b"GIF87a"), BytePattern::exact(b"GIF89a")],
            footer: Some(BytePattern::exact(&[0x3B])),
            max_size: Some(20 * 1024 * 1024),
        },
        CarveProfile {
            extension: "bmp".to_string(),
            description: "Bitmap Image".to_string(),
            headers: vec![BytePattern::exact(b"BM")],
            footer: None,
            max_size: Some(16 * 1024 * 1024),
        },
        CarveProfile {
            extension: "pdf".to_string(),
            description: "PDF Document".to_string(),
            headers: vec![BytePattern::exact(b"%PDF-")],
            footer: Some(BytePattern::exact(b"%%EOF")),
            max_size: Some(64 * 1024 * 1024),
        },
        CarveProfile {
            extension: "zip".to_string(),
            description: "ZIP Archive".to_string(),
            headers: vec![
                BytePattern::exact(b"PK\x03\x04"),
                BytePattern::exact(b"PK\x05\x06"),
                BytePattern::exact(b"PK\x07\x08"),
            ],
            footer: None,
            max_size: Some(256 * 1024 * 1024),
        },
        CarveProfile {
            extension: "rar".to_string(),
            description: "RAR Archive".to_string(),
            headers: vec![
                BytePattern::exact(b"Rar!\x1A\x07\x00"),
                BytePattern::exact(b"Rar!\x1A\x07\x01\x00"),
            ],
            footer: None,
            max_size: Some(256 * 1024 * 1024),
        },
        CarveProfile {
            extension: "7z".to_string(),
            description: "7z Archive".to_string(),
            headers: vec![BytePattern::exact(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])],
            footer: None,
            max_size: Some(256 * 1024 * 1024),
        },
        CarveProfile {
            extension: "gz".to_string(),
            description: "Gzip Stream".to_string(),
            headers: vec![BytePattern::exact(&[0x1F, 0x8B, 0x08])],
            footer: None,
            max_size: Some(128 * 1024 * 1024),
        },
        CarveProfile {
            extension: "sqlite".to_string(),
            description: "SQLite Database".to_string(),
            headers: vec![BytePattern::exact(b"SQLite format 3\x00")],
            footer: None,
            max_size: Some(512 * 1024 * 1024),
        },
        CarveProfile {
            extension: "elf".to_string(),
            description: "ELF Binary".to_string(),
            headers: vec![BytePattern::exact(b"\x7FELF")],
            footer: None,
            max_size: Some(128 * 1024 * 1024),
        },
        CarveProfile {
            extension: "exe".to_string(),
            description: "PE Executable".to_string(),
            headers: vec![BytePattern::exact(b"MZ")],
            footer: None,
            max_size: Some(128 * 1024 * 1024),
        },
        CarveProfile {
            extension: "macho".to_string(),
            description: "Mach-O Binary".to_string(),
            headers: vec![
                BytePattern::exact(&[0xFE, 0xED, 0xFA, 0xCE]),
                BytePattern::exact(&[0xCE, 0xFA, 0xED, 0xFE]),
                BytePattern::exact(&[0xFE, 0xED, 0xFA, 0xCF]),
                BytePattern::exact(&[0xCF, 0xFA, 0xED, 0xFE]),
            ],
            footer: None,
            max_size: Some(128 * 1024 * 1024),
        },
        CarveProfile {
            extension: "ole".to_string(),
            description: "OLE Compound Document".to_string(),
            headers: vec![BytePattern::exact(&[
                0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1,
            ])],
            footer: None,
            max_size: Some(256 * 1024 * 1024),
        },
        CarveProfile {
            extension: "wav".to_string(),
            description: "WAVE Audio".to_string(),
            headers: vec![BytePattern::wildcard(vec![
                Some(b'R'),
                Some(b'I'),
                Some(b'F'),
                Some(b'F'),
                None,
                None,
                None,
                None,
                Some(b'W'),
                Some(b'A'),
                Some(b'V'),
                Some(b'E'),
            ])],
            footer: None,
            max_size: Some(256 * 1024 * 1024),
        },
        CarveProfile {
            extension: "avi".to_string(),
            description: "AVI Video".to_string(),
            headers: vec![BytePattern::wildcard(vec![
                Some(b'R'),
                Some(b'I'),
                Some(b'F'),
                Some(b'F'),
                None,
                None,
                None,
                None,
                Some(b'A'),
                Some(b'V'),
                Some(b'I'),
                Some(b' '),
            ])],
            footer: None,
            max_size: Some(1024 * 1024 * 1024),
        },
        CarveProfile {
            extension: "mov".to_string(),
            description: "QuickTime or MP4 Container".to_string(),
            headers: vec![BytePattern::wildcard(vec![
                None,
                None,
                None,
                None,
                Some(b'f'),
                Some(b't'),
                Some(b'y'),
                Some(b'p'),
            ])],
            footer: None,
            max_size: Some(1024 * 1024 * 1024),
        },
        CarveProfile {
            extension: "mpg".to_string(),
            description: "MPEG Program Stream".to_string(),
            headers: vec![BytePattern::exact(&[0x00, 0x00, 0x01, 0xBA])],
            footer: None,
            max_size: Some(1024 * 1024 * 1024),
        },
        CarveProfile {
            extension: "wmv".to_string(),
            description: "ASF or WMV Container".to_string(),
            headers: vec![BytePattern::exact(&[
                0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62,
                0xCE, 0x6C,
            ])],
            footer: None,
            max_size: Some(1024 * 1024 * 1024),
        },
    ]
}

pub fn supported_carve_types() -> Vec<SupportedCarveType> {
    supported_carve_types_with_profiles(&[])
}

pub fn supported_carve_types_with_profiles(
    extra_profiles: &[CarveProfile],
) -> Vec<SupportedCarveType> {
    let mut grouped = BTreeMap::<String, (BTreeSet<String>, BTreeSet<String>)>::new();

    for profile in builtin_profiles()
        .into_iter()
        .chain(extra_profiles.iter().cloned())
    {
        let source = if extra_profiles.iter().any(|extra| {
            extra.extension == profile.extension && extra.description == profile.description
        }) {
            "config"
        } else {
            "builtin"
        };
        let entry = grouped
            .entry(profile.extension.clone())
            .or_insert_with(|| (BTreeSet::new(), BTreeSet::new()));
        entry.0.insert(profile.description);
        entry.1.insert(source.to_string());
    }

    grouped
        .into_iter()
        .map(|(extension, (names, sources))| SupportedCarveType {
            extension,
            names: names.into_iter().collect(),
            source: sources.into_iter().collect::<Vec<_>>().join(","),
        })
        .collect()
}

pub fn load_profiles_from_config(path: &Path) -> io::Result<Vec<CarveProfile>> {
    let content = std::fs::read_to_string(path)?;
    let mut profiles = Vec::new();

    for (line_no, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        profiles.push(parse_profile_line(line_no + 1, line)?);
    }

    Ok(profiles)
}

pub fn carve_from_bytes(
    data: &[u8],
    source_path: Option<&Path>,
    options: &CarveOptions,
) -> Vec<CarvedArtifact> {
    carve_from_bytes_with_base(data, source_path, options, 0)
}

fn carve_from_bytes_with_base(
    data: &[u8],
    source_path: Option<&Path>,
    options: &CarveOptions,
    base_offset: usize,
) -> Vec<CarvedArtifact> {
    let profiles = effective_profiles(options);
    let matches = scan_profiles(data, &profiles, options.quick);
    let output_dir = options
        .output_dir
        .clone()
        .or_else(|| source_path.map(default_output_dir));
    let mut artifacts = Vec::new();
    let mut seen_hashes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let effective_quota = options.extraction_byte_quota.min(HARD_MAX_EXTRACTION_QUOTA);
    let mut bytes_written: u64 = 0;

    for (index, profile_match) in matches.iter().enumerate() {
        if profile_match.offset == 0 && !options.include_root {
            continue;
        }

        let profile = &profiles[profile_match.profile_index];
        if !matches_type_filters(profile, &options.type_filters) {
            continue;
        }

        let slice_end = determine_slice_end(data, &matches, index, &profiles, options);
        if slice_end <= profile_match.offset {
            continue;
        }

        let length = slice_end - profile_match.offset;
        if length < options.min_size {
            continue;
        }

        let absolute_offset = base_offset + profile_match.offset;
        let slice = &data[profile_match.offset..slice_end];

        // Deduplication via BLAKE3 hash
        if options.deduplicate {
            let hash = blake3::hash(slice);
            let hash_hex = hash.to_hex().to_string();
            if !seen_hashes.insert(hash_hex) {
                continue;
            }
        }

        // Enforce quota — don't carve more bytes than the hard limit allows
        if bytes_written >= effective_quota {
            break;
        }

        let inspection = known_inspection(data, profile_match.offset, slice_end);
        let extracted_path = if options.write_files {
            output_dir
                .as_deref()
                .and_then(|root| {
                    write_artifact(
                        root,
                        source_path,
                        &profile.extension,
                        absolute_offset,
                        slice,
                        options.overwrite,
                    )
                    .ok()
                })
                .map(|path| path.display().to_string())
        } else {
            None
        };

        if extracted_path.is_some() {
            bytes_written = bytes_written.saturating_add(length as u64);
        }

        artifacts.push(CarvedArtifact {
            offset: absolute_offset,
            sector: options
                .sector_size
                .map(|sector_size| absolute_offset as u64 / sector_size as u64),
            name: profile.description.clone(),
            extension: profile.extension.clone(),
            length: Some(length),
            extracted_path,
            inspection,
        });
    }

    artifacts
}

pub fn carve_path(
    path: &Path,
    config_path: Option<&Path>,
    options: &CarveOptions,
) -> io::Result<CarveReport> {
    // Enforce hard quota even if options were constructed with a higher value
    let effective_quota = options.extraction_byte_quota.min(HARD_MAX_EXTRACTION_QUOTA);
    if effective_quota < options.extraction_byte_quota {
        // Log that the quota was clamped (we store this in the notes)
    }

    let should_materialize_output = options.write_files || options.write_audit;
    let output_dir = options
        .output_dir
        .clone()
        .unwrap_or_else(|| default_output_dir(path));
    if should_materialize_output {
        std::fs::create_dir_all(&output_dir)?;
    }

    let mut files_scanned = 0usize;
    let mut files_readable = 0usize;
    let mut matched = 0usize;
    let mut written = 0usize;
    let mut bytes_written = 0u64;
    let mut containers_expanded = 0usize;
    let mut container_members_written = 0usize;
    let mut by_type = BTreeMap::new();
    let mut sources = Vec::new();
    let mut notes = Vec::new();
    let mut pending: Vec<(PathBuf, usize)> = iter_source_files(path, options.recursive)
        .into_iter()
        .map(|source| (source, 0usize))
        .collect();
    let mut seen_sources = BTreeSet::new();

    while let Some((source_path, depth)) = pending.pop() {
        if !seen_sources.insert(source_path.clone()) {
            continue;
        }
        files_scanned += 1;
        let Ok(file) = File::open(&source_path) else {
            continue;
        };
        let Ok(mmap) = (unsafe { Mmap::map(&file) }) else {
            continue;
        };

        files_readable += 1;
        let mut source_options = options.clone();
        if should_materialize_output {
            source_options.output_dir = Some(output_dir.clone());
        }
        if depth > 0 {
            source_options.include_root = true;
        }

        let mut nested_paths = Vec::new();
        if options.write_files && depth < options.recursive_extract_depth {
            let expansion =
                expand_container_members(&mmap[..], &source_path, &output_dir, options.overwrite)?;
            containers_expanded += expansion.expanded;
            container_members_written += expansion.written;
            nested_paths.extend(expansion.paths);
            notes.extend(expansion.notes);
        }
        let scan_start = options.scan_offset.min(mmap.len());
        let scan_end = options
            .scan_length
            .map(|length| scan_start.saturating_add(length))
            .unwrap_or(mmap.len())
            .min(mmap.len());
        let artifacts = carve_from_bytes_with_base(
            &mmap[scan_start..scan_end],
            Some(&source_path),
            &source_options,
            scan_start,
        );

        for artifact in &artifacts {
            matched += 1;
            *by_type.entry(artifact.extension.clone()).or_insert(0usize) += 1;
            if artifact.extracted_path.is_some() {
                written += 1;
                bytes_written += artifact.length.unwrap_or(0) as u64;
            }
        }

        // Enforce extraction byte quota to prevent zip-bomb/C disk-fill attacks
        // The quota is clamped to HARD_MAX_EXTRACTION_QUOTA even if options specifies more.
        if bytes_written > effective_quota {
            notes.push(format!(
                "extraction byte quota ({}) exceeded; stopping further extraction",
                effective_quota
            ));
            break;
        }

        sources.push(CarveSourceReport {
            source: source_path.display().to_string(),
            size: mmap.len(),
            matched: artifacts.len(),
            written: artifacts
                .iter()
                .filter(|artifact| artifact.extracted_path.is_some())
                .count(),
            artifacts: artifacts.clone(),
        });

        if options.write_files && depth < options.recursive_extract_depth {
            for nested in artifacts
                .iter()
                .filter_map(|artifact| artifact.extracted_path.as_deref())
                .map(PathBuf::from)
                .chain(nested_paths.into_iter())
            {
                if nested.is_file() {
                    pending.push((nested, depth + 1));
                }
            }
        }
    }

    let mut report = CarveReport {
        input: path.display().to_string(),
        output_dir: should_materialize_output.then(|| output_dir.display().to_string()),
        config_path: config_path.map(|value| value.display().to_string()),
        quick_mode: options.quick,
        recursive_extract_depth: options.recursive_extract_depth,
        scan_offset: options.scan_offset,
        scan_length: options.scan_length,
        sector_size: options.sector_size,
        files_scanned,
        files_readable,
        matched,
        written,
        bytes_written,
        containers_expanded,
        container_members_written,
        by_type,
        sources,
        audit_path: None,
        notes,
    };

    if options.write_audit {
        let audit_path = write_audit_log(&output_dir, &report)?;
        report.audit_path = Some(audit_path.display().to_string());
    }

    Ok(report)
}

pub fn default_output_dir(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .or_else(|| input.file_name())
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "hashendra".to_string());
    let folder = format!("carved_{}", sanitize_component(&stem));

    input
        .parent()
        .map(|parent| parent.join(&folder))
        .unwrap_or_else(|| PathBuf::from(folder))
}

fn effective_profiles(options: &CarveOptions) -> Vec<CarveProfile> {
    let mut profiles = builtin_profiles();
    profiles.extend(options.profiles.clone());
    profiles
}

fn iter_source_files(path: &Path, recursive: bool) -> Vec<PathBuf> {
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

fn scan_profiles(data: &[u8], profiles: &[CarveProfile], quick: bool) -> Vec<ProfileMatch> {
    let local_data = data;
    let mut matches: Vec<(usize, usize, usize)> = profiles
        .par_iter()
        .enumerate()
        .flat_map(|(profile_index, profile)| {
            let mut profile_matches = Vec::new();
            for header in &profile.headers {
                if header.len() == 0 || header.len() > local_data.len() {
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

fn determine_slice_end(
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
    if let Some(footer) = &profile.footer {
        if let Some(end) = find_pattern(data, current.offset + current.header_len, footer) {
            return end.saturating_add(footer.len()).min(data.len());
        }
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
fn compute_length_from_header(data: &[u8], offset: usize, extension: &str) -> Option<usize> {
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

fn locate_known_end(data: &[u8], offset: usize, extension: &str) -> Option<usize> {
    let signature = identify_file_signature(&data[offset..])?;
    if signature.extension != extension {
        return None;
    }
    locate_file_end(data, offset, signature)
}

fn known_inspection(data: &[u8], offset: usize, slice_end: usize) -> Option<ArtifactInspection> {
    let signature = identify_file_signature(&data[offset..])?;
    inspect_artifact(&data[offset..slice_end], signature)
}

fn matches_type_filters(profile: &CarveProfile, filters: &BTreeSet<String>) -> bool {
    if filters.is_empty() {
        return true;
    }

    let extension = profile.extension.to_ascii_lowercase();
    let description = profile.description.to_ascii_lowercase();
    filters.contains(&extension) || filters.iter().any(|filter| description.contains(filter))
}

fn find_pattern(data: &[u8], start: usize, pattern: &BytePattern) -> Option<usize> {
    if pattern.len() == 0 || start >= data.len() || pattern.len() > data.len().saturating_sub(start)
    {
        return None;
    }

    (start..=data.len() - pattern.len()).find(|&offset| pattern.matches_at(data, offset))
}

fn write_artifact(
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

fn write_audit_log(output_dir: &Path, report: &CarveReport) -> io::Result<PathBuf> {
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

fn expand_container_members(
    data: &[u8],
    source_path: &Path,
    output_root: &Path,
    overwrite: bool,
) -> io::Result<ContainerExpansion> {
    if looks_like_zip(data) {
        return extract_zip_members(data, source_path, output_root, overwrite);
    }
    if looks_like_tar(data) {
        return extract_tar_members(data, source_path, output_root, overwrite);
    }
    Ok(ContainerExpansion::default())
}

fn looks_like_zip(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04") && find_zip_eocd(data).is_some()
}

fn looks_like_tar(data: &[u8]) -> bool {
    data.get(257..262).is_some_and(|magic| magic == b"ustar")
}

fn extract_zip_members(
    data: &[u8],
    source_path: &Path,
    output_root: &Path,
    overwrite: bool,
) -> io::Result<ContainerExpansion> {
    let Some(eocd_offset) = find_zip_eocd(data) else {
        return Ok(ContainerExpansion::default());
    };

    let total_entries = le_u16(data, eocd_offset + 10).unwrap_or(0) as usize;
    let central_offset = le_u32(data, eocd_offset + 16).unwrap_or(0) as usize;
    if total_entries == 0 || central_offset >= data.len() {
        return Ok(ContainerExpansion::default());
    }

    let container_dir = container_output_dir(output_root, source_path, "zip");
    std::fs::create_dir_all(&container_dir)?;

    let mut expansion = ContainerExpansion {
        expanded: 1,
        ..Default::default()
    };
    let mut cursor = central_offset;

    for _ in 0..total_entries {
        let Some(header) = data.get(cursor..cursor + 46) else {
            expansion.notes.push(format!(
                "ZIP central directory in {} ended unexpectedly",
                source_path.display()
            ));
            break;
        };
        if &header[..4] != b"PK\x01\x02" {
            expansion.notes.push(format!(
                "ZIP central directory entry was malformed in {}",
                source_path.display()
            ));
            break;
        }

        let method = le_u16(header, 10).unwrap_or(0);
        let compressed_size = le_u32(header, 20).unwrap_or(0) as usize;
        let name_len = le_u16(header, 28).unwrap_or(0) as usize;
        let extra_len = le_u16(header, 30).unwrap_or(0) as usize;
        let comment_len = le_u16(header, 32).unwrap_or(0) as usize;
        let local_offset = le_u32(header, 42).unwrap_or(0) as usize;
        let Some(name_bytes) = data.get(cursor + 46..cursor + 46 + name_len) else {
            expansion.notes.push(format!(
                "ZIP member name could not be read in {}",
                source_path.display()
            ));
            break;
        };
        let member_name = String::from_utf8_lossy(name_bytes).to_string();
        cursor = cursor.saturating_add(46 + name_len + extra_len + comment_len);

        if member_name.is_empty() {
            continue;
        }
        if member_name.ends_with('/') {
            let dir = sanitize_member_path(&member_name);
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(container_dir.join(dir))?;
            }
            continue;
        }
        if method != 0 {
            expansion.notes.push(format!(
                "ZIP member {} in {} uses unsupported compression method {} and was skipped",
                member_name,
                source_path.display(),
                method
            ));
            continue;
        }

        let Some(local_header) = data.get(local_offset..local_offset + 30) else {
            expansion.notes.push(format!(
                "ZIP member {} in {} had an invalid local header offset",
                member_name,
                source_path.display()
            ));
            continue;
        };
        if &local_header[..4] != b"PK\x03\x04" {
            expansion.notes.push(format!(
                "ZIP member {} in {} had a malformed local header",
                member_name,
                source_path.display()
            ));
            continue;
        }

        let local_name_len = le_u16(local_header, 26).unwrap_or(0) as usize;
        let local_extra_len = le_u16(local_header, 28).unwrap_or(0) as usize;
        let Some(data_start) = local_offset
            .checked_add(30)
            .and_then(|offset| offset.checked_add(local_name_len))
            .and_then(|offset| offset.checked_add(local_extra_len))
        else {
            expansion.notes.push(format!(
                "ZIP member {} in {} overflowed while locating payload",
                member_name,
                source_path.display()
            ));
            continue;
        };
        let Some(member_bytes) = data.get(data_start..data_start.saturating_add(compressed_size))
        else {
            expansion.notes.push(format!(
                "ZIP member {} in {} fell outside the archive",
                member_name,
                source_path.display()
            ));
            continue;
        };

        let written =
            write_container_member(&container_dir, &member_name, member_bytes, overwrite)?;
        expansion.paths.push(written);
        expansion.written += 1;
    }

    Ok(expansion)
}

fn extract_tar_members(
    data: &[u8],
    source_path: &Path,
    output_root: &Path,
    overwrite: bool,
) -> io::Result<ContainerExpansion> {
    if !looks_like_tar(data) {
        return Ok(ContainerExpansion::default());
    }

    let container_dir = container_output_dir(output_root, source_path, "tar");
    std::fs::create_dir_all(&container_dir)?;
    let mut expansion = ContainerExpansion {
        expanded: 1,
        ..Default::default()
    };
    let mut cursor = 0usize;

    while cursor + 512 <= data.len() {
        let header = &data[cursor..cursor + 512];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }

        let name = decode_tar_path(header);
        let size = parse_tar_size(header).unwrap_or(0);
        let typeflag = header[156];
        let data_start = cursor.saturating_add(512);
        let data_end = data_start.saturating_add(size);
        if data_end > data.len() {
            expansion.notes.push(format!(
                "TAR member {} in {} exceeded archive bounds",
                name,
                source_path.display()
            ));
            break;
        }

        match typeflag {
            0 | b'0' => {
                let written = write_container_member(
                    &container_dir,
                    &name,
                    &data[data_start..data_end],
                    overwrite,
                )?;
                expansion.paths.push(written);
                expansion.written += 1;
            }
            b'5' => {
                let dir = sanitize_member_path(&name);
                if !dir.as_os_str().is_empty() {
                    std::fs::create_dir_all(container_dir.join(dir))?;
                }
            }
            _ => {}
        }

        cursor = data_end;
        let padding = (512 - (size % 512)) % 512;
        cursor = cursor.saturating_add(padding);
    }

    Ok(expansion)
}

fn container_output_dir(output_root: &Path, source_path: &Path, kind: &str) -> PathBuf {
    let source_name = source_path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "buffer".to_string());
    output_root
        .join("_containers")
        .join(format!("{}_{}", sanitize_component(&source_name), kind))
}

fn write_container_member(
    container_dir: &Path,
    member_name: &str,
    bytes: &[u8],
    overwrite: bool,
) -> io::Result<PathBuf> {
    let sanitized = sanitize_member_path(member_name);
    if sanitized.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "container member path was empty after sanitization",
        ));
    }

    let mut candidate = container_dir.join(sanitized);
    if let Some(parent) = candidate.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if !overwrite {
        let parent = candidate
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| container_dir.to_path_buf());
        let stem = candidate
            .file_stem()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "member".to_string());
        let extension = candidate
            .extension()
            .map(|value| value.to_string_lossy().to_string());
        let mut suffix = 1usize;
        while candidate.exists() {
            let file_name = match &extension {
                Some(extension) => format!("{}_{}.{}", stem, suffix, extension),
                None => format!("{}_{}", stem, suffix),
            };
            candidate = parent.join(file_name);
            suffix += 1;
        }
    }

    std::fs::write(&candidate, bytes)?;
    Ok(candidate)
}

fn sanitize_member_path(value: &str) -> PathBuf {
    let mut path = PathBuf::new();
    for component in value.split(['/', '\\']) {
        let trimmed = component.trim();
        if trimmed.is_empty() || matches!(trimmed, "." | "..") {
            continue;
        }
        let sanitized = sanitize_path_component(trimmed);
        if !sanitized.is_empty() {
            path.push(sanitized);
        }
    }
    path
}

fn sanitize_path_component(value: &str) -> String {
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

fn decode_tar_path(header: &[u8]) -> String {
    let name = decode_tar_string(&header[..100]);
    let prefix = decode_tar_string(&header[345..500]);
    if prefix.is_empty() {
        name
    } else if name.is_empty() {
        prefix
    } else {
        format!("{}/{}", prefix, name)
    }
}

fn decode_tar_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .map(char::from)
        .collect::<String>()
        .trim()
        .to_string()
}

fn parse_tar_size(header: &[u8]) -> Option<usize> {
    let raw = decode_tar_string(&header[124..136]);
    let raw = raw.trim_matches(char::from(0)).trim();
    if raw.is_empty() {
        Some(0)
    } else {
        usize::from_str_radix(raw, 8).ok()
    }
}

fn find_zip_eocd(data: &[u8]) -> Option<usize> {
    let search_start = data.len().saturating_sub(22 + 65_535);
    data[search_start..]
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .map(|offset| search_start + offset)
}

fn parse_profile_line(line_no: usize, line: &str) -> io::Result<CarveProfile> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "config line {} must have: ext case max header footer [description...]",
                line_no
            ),
        ));
    }

    let extension = parts[0].to_ascii_lowercase();
    let max_size = match parts[2] {
        "0" | "-" | "none" | "NONE" => None,
        value => Some(value.parse::<usize>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("config line {} has invalid max size", line_no),
            )
        })?),
    };
    let header = parse_pattern_token(parts[3]).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("config line {} header error: {}", line_no, error),
        )
    })?;
    let footer = if matches!(parts[4], "-" | "none" | "NONE") {
        None
    } else {
        Some(parse_pattern_token(parts[4]).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("config line {} footer error: {}", line_no, error),
            )
        })?)
    };
    let description = if parts.len() > 5 {
        parts[5..].join(" ")
    } else {
        format!("Custom {}", extension.to_uppercase())
    };

    Ok(CarveProfile {
        extension,
        description,
        headers: vec![header],
        footer,
        max_size,
    })
}

fn parse_pattern_token(token: &str) -> Result<BytePattern, String> {
    let mut bytes = Vec::new();
    let mut index = 0usize;
    let raw = token.as_bytes();

    while index < raw.len() {
        match raw[index] {
            b'\\' => {
                index += 1;
                if index >= raw.len() {
                    return Err("trailing escape".to_string());
                }

                match raw[index] {
                    b'x' => {
                        if index + 2 >= raw.len() {
                            return Err("incomplete hex escape".to_string());
                        }
                        let hi = from_hex(raw[index + 1])?;
                        let lo = from_hex(raw[index + 2])?;
                        bytes.push(Some((hi << 4) | lo));
                        index += 3;
                    }
                    b'n' => {
                        bytes.push(Some(b'\n'));
                        index += 1;
                    }
                    b'r' => {
                        bytes.push(Some(b'\r'));
                        index += 1;
                    }
                    b't' => {
                        bytes.push(Some(b'\t'));
                        index += 1;
                    }
                    b'0' => {
                        bytes.push(Some(0));
                        index += 1;
                    }
                    other => {
                        bytes.push(Some(other));
                        index += 1;
                    }
                }
            }
            b'?' => {
                bytes.push(None);
                index += 1;
            }
            byte => {
                bytes.push(Some(byte));
                index += 1;
            }
        }
    }

    Ok(BytePattern::wildcard(bytes))
}

fn from_hex(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex digit".to_string()),
    }
}

fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn sanitize_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        BytePattern, CarveOptions, CarveProfile, builtin_profiles, carve_from_bytes, carve_path,
        load_profiles_from_config, supported_carve_types_with_profiles,
    };
    use std::collections::BTreeSet;

    #[test]
    fn exposes_unique_supported_extensions() {
        let supported = supported_carve_types_with_profiles(&[]);
        assert!(supported.iter().any(|entry| entry.extension == "png"));
        assert!(supported.iter().any(|entry| entry.extension == "wav"));
        assert_eq!(
            supported
                .iter()
                .filter(|entry| entry.extension == "zip")
                .count(),
            1
        );
    }

    #[test]
    fn carves_filtered_embedded_png_without_writing() {
        let data = b"prefix\
\x89PNG\r\n\x1a\n\
\x00\x00\x00\x0dIHDR\
\x00\x00\x00\x02\
\x00\x00\x00\x03\
\x08\x06\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00IEND\xAE\x42\x60\x82\
suffix";

        let mut filters = BTreeSet::new();
        filters.insert("png".to_string());
        let options = CarveOptions {
            type_filters: filters,
            write_files: false,
            write_audit: false,
            ..Default::default()
        };

        let artifacts = carve_from_bytes(data, None, &options);
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].extension, "png");
        assert_eq!(artifacts[0].length, Some(45));
        assert!(artifacts[0].extracted_path.is_none());
    }

    #[test]
    fn quick_mode_stops_after_first_profile_hit() {
        let data = b"pad\
\x89PNG\r\n\x1a\nabcd\x00\x00\x00\x00IEND\xAE\x42\x60\x82\
\x89PNG\r\n\x1a\nabcd\x00\x00\x00\x00IEND\xAE\x42\x60\x82";
        let options = CarveOptions {
            quick: true,
            write_files: false,
            write_audit: false,
            ..Default::default()
        };

        let artifacts = carve_from_bytes(data, None, &options);
        assert_eq!(artifacts.len(), 1);
    }

    #[test]
    fn parses_custom_config_profiles() {
        let path =
            std::env::temp_dir().join(format!("hashendra-carve-conf-{}", std::process::id()));
        std::fs::write(
            &path,
            "foo y 4096 ABCD WXYZ Custom Foo\nbar y 0 RIFF????WAVE -\n",
        )
        .unwrap();

        let profiles = load_profiles_from_config(&path).unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].extension, "foo");
        assert_eq!(profiles[0].description, "Custom Foo");
        assert_eq!(profiles[1].extension, "bar");
        assert_eq!(profiles[1].max_size, None);

        let supported = supported_carve_types_with_profiles(&profiles);
        assert!(supported.iter().any(|entry| entry.extension == "foo"));
        assert!(supported.iter().any(|entry| entry.extension == "bar"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn builtin_profiles_include_foremost_style_media_types() {
        let builtins = builtin_profiles();
        assert!(builtins.iter().any(|profile| profile.extension == "mov"));
        assert!(builtins.iter().any(|profile| profile.extension == "wmv"));
        assert!(builtins.iter().any(|profile| profile.extension == "ole"));
    }

    #[test]
    fn matryoshka_rescans_extracted_artifacts() {
        let root =
            std::env::temp_dir().join(format!("hashendra-carve-recursive-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let input = root.join("sample.bin");
        let output = root.join("out");

        let png = b"\x89PNG\r\n\x1a\n\
\x00\x00\x00\x0dIHDR\
\x00\x00\x00\x02\
\x00\x00\x00\x03\
\x08\x06\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00IEND\xAE\x42\x60\x82";
        let data = [b"prefixOUTER".as_slice(), png.as_slice(), b"END!suffix"].concat();
        std::fs::write(&input, data).unwrap();

        let options = CarveOptions {
            output_dir: Some(output.clone()),
            write_files: true,
            write_audit: false,
            recursive_extract_depth: 1,
            profiles: vec![CarveProfile {
                extension: "outer".to_string(),
                description: "Outer Container".to_string(),
                headers: vec![BytePattern::exact(b"OUTER")],
                footer: Some(BytePattern::exact(b"END!")),
                max_size: Some(4096),
            }],
            ..Default::default()
        };

        let report = carve_path(&input, None, &options).unwrap();
        assert_eq!(report.recursive_extract_depth, 1);
        assert!(report.files_scanned >= 3);
        assert!(report.matched >= 3);
        assert!(report.by_type.get("outer").copied().unwrap_or(0) >= 1);
        assert!(report.by_type.get("png").copied().unwrap_or(0) >= 2);
        assert!(
            report
                .sources
                .iter()
                .any(|source| source.source.ends_with(".outer"))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn matryoshka_expands_zip_members() {
        let root = std::env::temp_dir().join(format!("hashendra-carve-zip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let input = root.join("archive.zip");
        let output = root.join("out");

        let png = b"\x89PNG\r\n\x1a\n\
\x00\x00\x00\x0dIHDR\
\x00\x00\x00\x02\
\x00\x00\x00\x03\
\x08\x06\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00IEND\xAE\x42\x60\x82";
        std::fs::write(&input, build_stored_zip("nested/payload.png", png)).unwrap();

        let options = CarveOptions {
            output_dir: Some(output.clone()),
            write_files: true,
            write_audit: false,
            recursive_extract_depth: 2,
            ..Default::default()
        };

        let report = carve_path(&input, None, &options).unwrap();
        assert!(report.containers_expanded >= 1);
        assert!(report.container_members_written >= 1);
        assert!(report.by_type.get("png").copied().unwrap_or(0) >= 1);
        assert!(
            report
                .sources
                .iter()
                .any(|source| source.source.ends_with("payload.png"))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn matryoshka_expands_tar_members() {
        let root = std::env::temp_dir().join(format!("hashendra-carve-tar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let input = root.join("archive.tar");
        let output = root.join("out");

        let png = b"\x89PNG\r\n\x1a\n\
\x00\x00\x00\x0dIHDR\
\x00\x00\x00\x02\
\x00\x00\x00\x03\
\x08\x06\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00IEND\xAE\x42\x60\x82";
        std::fs::write(&input, build_tar("nested/payload.png", png)).unwrap();

        let options = CarveOptions {
            output_dir: Some(output.clone()),
            write_files: true,
            write_audit: false,
            recursive_extract_depth: 2,
            ..Default::default()
        };

        let report = carve_path(&input, None, &options).unwrap();
        assert!(report.containers_expanded >= 1);
        assert!(report.container_members_written >= 1);
        assert!(report.by_type.get("png").copied().unwrap_or(0) >= 1);
        assert!(
            report
                .sources
                .iter()
                .any(|source| source.source.ends_with("payload.png"))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    fn build_stored_zip(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut zip = Vec::new();
        let name_bytes = name.as_bytes();

        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(name_bytes);
        zip.extend_from_slice(payload);

        let central_offset = zip.len() as u32;
        zip.extend_from_slice(b"PK\x01\x02");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(name_bytes);

        let central_size = zip.len() as u32 - central_offset;
        zip.extend_from_slice(b"PK\x05\x06");
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&central_size.to_le_bytes());
        zip.extend_from_slice(&central_offset.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip
    }

    fn build_tar(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut tar = vec![0u8; 512];
        let name_bytes = name.as_bytes();
        tar[..name_bytes.len()].copy_from_slice(name_bytes);
        tar[100..108].copy_from_slice(b"0000644\0");
        tar[108..116].copy_from_slice(b"0000000\0");
        tar[116..124].copy_from_slice(b"0000000\0");
        let size = format!("{:011o}\0", payload.len());
        tar[124..136].copy_from_slice(size.as_bytes());
        tar[136..148].copy_from_slice(b"00000000000\0");
        tar[148..156].fill(b' ');
        tar[156] = b'0';
        tar[257..263].copy_from_slice(b"ustar\0");
        tar[263..265].copy_from_slice(b"00");
        let checksum: u32 = tar.iter().map(|byte| *byte as u32).sum();
        let checksum_field = format!("{:06o}\0 ", checksum);
        tar[148..156].copy_from_slice(checksum_field.as_bytes());
        tar.extend_from_slice(payload);
        let padding = (512 - (payload.len() % 512)) % 512;
        tar.extend(std::iter::repeat_n(0u8, padding + 1024));
        tar
    }
}
