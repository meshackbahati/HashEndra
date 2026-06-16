use crate::core::patterns::{DetectionResult, ScanningContext, scan_input};
use crate::detectors::stego::{identify_file_signature, locate_file_end};
use crate::forensics::carve::{CarveOptions, CarvedArtifact, carve_from_bytes};
use crate::forensics::inspect::inspect_artifact;
use crate::forensics::strings::{extract_printable_strings, extract_utf16le_strings};
use crate::safe_println;
use colored::*;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

// safe_println! is defined in utils/io.rs via #[macro_export]

const MIN_FORENSIC_CONFIDENCE: f32 = 0.70;
const MIN_SECONDARY_CONFIDENCE: f32 = 0.45;
const MAX_CANDIDATE_LEN: usize = 512;

lazy_static! {
    static ref EMBEDDED_HEX_RE: Regex = Regex::new(r"[A-Fa-f0-9]{32,128}").unwrap();
    static ref ASSIGNMENT_VALUE_RE: Regex = Regex::new(
        r#"(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,63})\s*[:=]\s*["']?(?P<value>[$./A-Za-z0-9:_#%+\-=/]{8,512})["']?"#
    )
    .unwrap();
}

#[derive(Debug, Clone, Serialize)]
pub struct ForensicHit {
    pub offset: usize,
    pub value: String,
    pub source: &'static str,
    pub results: Vec<DetectionResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForensicReport {
    pub size: usize,
    pub entropy: f64,
    pub ascii_strings: usize,
    pub utf16_strings: usize,
    pub root_artifact: Option<CarvedArtifact>,
    pub hits: Vec<ForensicHit>,
    pub artifacts: Vec<CarvedArtifact>,
}

pub fn build_forensic_report(
    data: &[u8],
    path: Option<&Path>,
    extract_artifacts: bool,
) -> ForensicReport {
    let ascii_strings = extract_printable_strings(data, 8);
    let utf16_strings = extract_utf16le_strings(data, 4);
    let mut reported = HashSet::new();
    let mut hits = Vec::new();

    for (start, chunk) in &ascii_strings {
        collect_hits(chunk, *start, "ascii", &mut reported, &mut hits);
    }
    for (start, chunk) in &utf16_strings {
        collect_hits(chunk, *start, "utf16le", &mut reported, &mut hits);
    }

    let root_artifact = collect_root_artifact(data);
    let artifacts = collect_artifacts(data, path, extract_artifacts);

    ForensicReport {
        size: data.len(),
        entropy: crate::core::scanner::calculate_entropy(data),
        ascii_strings: ascii_strings.len(),
        utf16_strings: utf16_strings.len(),
        root_artifact,
        hits,
        artifacts,
    }
}

pub fn summarize_hit_counts(report: &ForensicReport) -> BTreeMap<String, usize> {
    let mut by_name = BTreeMap::new();
    for hit in &report.hits {
        if let Some(top) = hit.results.first() {
            *by_name.entry(top.name.clone()).or_insert(0usize) += 1;
        }
    }
    by_name
}

pub fn print_forensic_report(report: &ForensicReport) {
    safe_println!(
        "{}",
        format!(
            "[TRIAGE] entropy {:.3} | ascii strings {} | utf16 strings {} | hits {} | embedded {}",
            report.entropy,
            report.ascii_strings,
            report.utf16_strings,
            report.hits.len(),
            report.artifacts.len()
        )
        .cyan()
    );

    if let Some(root_artifact) = &report.root_artifact {
        safe_println!("\n[FORMAT]");
        print_artifact_details(root_artifact, None);
    }

    if !report.artifacts.is_empty() {
        safe_println!("\n[ARTIFACTS] Embedded file signatures:");
        for (idx, artifact) in report.artifacts.iter().enumerate() {
            print_artifact_details(artifact, Some(idx));
        }
    }

    if !report.hits.is_empty() {
        safe_println!("\n[HITS]");
        for (name, count) in summarize_hit_counts(report) {
            safe_println!("  {} -> {}", name, count);
        }
    }

    for hit in &report.hits {
        print_forensic_hit(hit);
    }
}

pub fn print_forensic_hit(hit: &ForensicHit) {
    safe_println!(
        "[FORENSIC @ 0x{:08x}] [{}] Found: {}",
        hit.offset,
        hit.source.to_uppercase().yellow(),
        hit.value.cyan().bold()
    );
    for res in &hit.results {
        safe_println!("  - {} ({:.0}%)", res.name, res.confidence * 100.0);
        if !res.extracted_parameters.is_empty() {
            for (key, val) in &res.extracted_parameters {
                safe_println!("    +- {}: {}", key.yellow(), val.white());
            }
        }
    }
}

fn print_artifact_details(artifact: &CarvedArtifact, index: Option<usize>) {
    let location = if artifact.offset == 0 {
        "Start of file".to_string()
    } else {
        format!("Offset 0x{:X}", artifact.offset)
    };
    let length = artifact
        .length
        .map(|len| format!("{} bytes", len))
        .unwrap_or_else(|| "unknown length".to_string());

    match index {
        Some(idx) => safe_println!(
            "  - [{}] {} matches {} ({}, .{}){}",
            idx,
            location.yellow(),
            artifact.name.green(),
            length,
            artifact.extension,
            artifact
                .sector
                .map(|sector| format!(" [sector {}]", sector))
                .unwrap_or_default()
        ),
        None => safe_println!(
            "  {} -> {} ({}, .{}){}",
            location.yellow(),
            artifact.name.green(),
            length,
            artifact.extension,
            artifact
                .sector
                .map(|sector| format!(" [sector {}]", sector))
                .unwrap_or_default()
        ),
    }

    if let Some(inspection) = &artifact.inspection {
        safe_println!("    [INSPECT] {}", inspection.summary.cyan());
        for (key, value) in &inspection.details {
            safe_println!("      {}: {}", key.yellow(), value.white());
        }
    }

    if let Some(path) = &artifact.extracted_path {
        safe_println!("    [EXTRACTED] Saved to {}", path.cyan());
    }
}

fn collect_hits(
    chunk: &str,
    start: usize,
    source: &'static str,
    reported: &mut HashSet<(usize, String)>,
    hits: &mut Vec<ForensicHit>,
) {
    for (offset, candidate) in extract_forensic_candidates(chunk, start) {
        if !reported.insert((offset, candidate.clone())) {
            continue;
        }

        let results = scan_input(&candidate, ScanningContext::Filesystem);
        let reportable: Vec<_> = results
            .into_iter()
            .filter(|result| result.confidence >= MIN_SECONDARY_CONFIDENCE)
            .collect();

        if reportable
            .first()
            .map(|result| result.confidence >= MIN_FORENSIC_CONFIDENCE)
            .unwrap_or(false)
        {
            hits.push(ForensicHit {
                offset,
                value: candidate,
                source,
                results: reportable,
            });
        }
    }
}

fn collect_artifacts(
    data: &[u8],
    path: Option<&Path>,
    extract_artifacts: bool,
) -> Vec<CarvedArtifact> {
    let options = CarveOptions {
        write_files: extract_artifacts,
        ..Default::default()
    };
    carve_from_bytes(data, path, &options)
}

fn collect_root_artifact(data: &[u8]) -> Option<CarvedArtifact> {
    let signature = identify_file_signature(data)?;
    let end = locate_file_end(data, 0, signature);
    let slice_end = end.unwrap_or(data.len()).min(data.len());

    Some(CarvedArtifact {
        offset: 0,
        sector: None,
        name: signature.name.to_string(),
        extension: signature.extension.to_string(),
        length: end,
        extracted_path: None,
        inspection: inspect_artifact(&data[..slice_end], signature),
    })
}

pub(crate) fn extract_forensic_candidates(chunk: &str, base_offset: usize) -> Vec<(usize, String)> {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    let mut token_start: Option<usize> = None;

    for (idx, ch) in chunk.char_indices() {
        if is_token_char(ch) {
            if token_start.is_none() {
                token_start = Some(idx);
            }
        } else if let Some(start) = token_start.take() {
            let token = &chunk[start..idx];
            let absolute_offset = base_offset + start;
            push_candidate(&mut candidates, &mut seen, absolute_offset, token);
            push_label_value_parts(&mut candidates, &mut seen, absolute_offset, token);
        }
    }

    if let Some(start) = token_start {
        let token = &chunk[start..];
        let absolute_offset = base_offset + start;
        push_candidate(&mut candidates, &mut seen, absolute_offset, token);
        push_label_value_parts(&mut candidates, &mut seen, absolute_offset, token);
    }

    for m in EMBEDDED_HEX_RE.find_iter(chunk) {
        push_candidate(
            &mut candidates,
            &mut seen,
            base_offset + m.start(),
            m.as_str(),
        );
    }

    for caps in ASSIGNMENT_VALUE_RE.captures_iter(chunk) {
        if let Some(value) = caps.name("value") {
            push_candidate(
                &mut candidates,
                &mut seen,
                base_offset + value.start(),
                value.as_str(),
            );
        }
    }

    candidates.sort_by_key(|(offset, _)| *offset);
    candidates
}

fn push_candidate(
    candidates: &mut Vec<(usize, String)>,
    seen: &mut HashSet<(usize, String)>,
    offset: usize,
    token: &str,
) {
    let token = token.trim();
    if !looks_like_forensic_token(token) {
        return;
    }

    let entry = (offset, token.to_string());
    if seen.insert(entry.clone()) {
        candidates.push(entry);
    }
}

fn push_label_value_parts(
    candidates: &mut Vec<(usize, String)>,
    seen: &mut HashSet<(usize, String)>,
    offset: usize,
    token: &str,
) {
    for delimiter in ['=', ':'] {
        if token.matches(delimiter).count() != 1 {
            continue;
        }

        if let Some(idx) = token.find(delimiter) {
            let value = &token[idx + 1..];
            if !value.is_empty() {
                push_candidate(candidates, seen, offset + idx + 1, value);
            }
        }
    }
}

fn is_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            '$' | '.' | '/' | '+' | '=' | '_' | '-' | ':' | '#' | '%'
        )
}

fn looks_like_forensic_token(token: &str) -> bool {
    if token.len() < 8 || token.len() > MAX_CANDIDATE_LEN {
        return false;
    }

    if (token.ends_with('=') || token.ends_with(':'))
        && token.chars().filter(|c| *c == '=' || *c == ':').count() == 1
        && token[..token.len() - 1]
            .chars()
            .all(|c| c.is_ascii_uppercase() || matches!(c, '_' | '-' | '.'))
    {
        return false;
    }

    let has_digit = token.chars().any(|c| c.is_ascii_digit());
    let has_special = token.chars().any(|c| "$./+=_:-#%".contains(c));
    let is_hexish =
        token.len() >= 16 && token.len() % 2 == 0 && token.chars().all(|c| c.is_ascii_hexdigit());
    let is_mixed_case = token.len() >= 20
        && token.chars().any(|c| c.is_ascii_uppercase())
        && token.chars().any(|c| c.is_ascii_lowercase());

    has_digit || has_special || is_hexish || is_mixed_case
}

#[cfg(test)]
mod tests {
    use super::extract_forensic_candidates;

    #[test]
    fn extracts_mixed_tokens_from_printable_region() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln";
        let text = format!(
            "user=alice hash=5f4dcc3b5aa765d61d8327deb882cf99 jwt={} API_KEY=\"SGVsbG8gV29ybGQ=\" trailer",
            jwt
        );

        let candidates = extract_forensic_candidates(&text, 0);

        assert!(
            candidates
                .iter()
                .any(|(_, token)| token == "5f4dcc3b5aa765d61d8327deb882cf99")
        );
        assert!(candidates.iter().any(|(_, token)| token == jwt));
        assert!(
            candidates
                .iter()
                .any(|(_, token)| token == "SGVsbG8gV29ybGQ=")
        );
    }
}
