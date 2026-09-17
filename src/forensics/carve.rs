use crate::forensics::inspect::ArtifactInspection;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

/// Hard upper bound for extraction byte quota — enforced even if CLI or API bypasses the default.
/// Prevents zip-bomb / disk-fill attacks regardless of how CarveOptions is configured.
pub(crate) const HARD_MAX_EXTRACTION_QUOTA: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB

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

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
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
pub(crate) struct ProfileMatch {
    offset: usize,
    header_len: usize,
    profile_index: usize,
}

#[derive(Debug, Default)]
pub(crate) struct ContainerExpansion {
    paths: Vec<PathBuf>,
    expanded: usize,
    written: usize,
    notes: Vec<String>,
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

mod config;
mod containers;
mod engine;
mod profiles;
mod scan;

pub(crate) use config::*;
pub(crate) use engine::*;
pub(crate) use profiles::*;
pub(crate) use scan::*;

// Public API consumed by the binary and integration tests.
pub use engine::carve_path;

#[cfg(test)]
#[path = "carve/carve_tests.rs"]
mod carve_tests;
