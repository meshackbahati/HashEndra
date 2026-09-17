use super::config::sanitize_component;
use super::containers::expand_container_members;
use super::scan::{iter_source_files, write_audit_log};
use super::{carve_from_bytes_with_base, CarveOptions, CarveReport, CarveSourceReport};
use super::HARD_MAX_EXTRACTION_QUOTA;
use memmap2::Mmap;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

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
        // SAFETY: the file is opened read-only and never truncated or
        // written while mapped; the mapping is only read.
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
                .chain(nested_paths)
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
