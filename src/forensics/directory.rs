use crate::forensics::filetypes::{detect_path_file_type, read_path_metadata};
use crate::forensics::report::ForensicReport;
use crate::utils::io_manager::FileManager;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct DirectoryFileReport {
    pub path: String,
    pub size: Option<u64>,
    pub file_type: String,
    pub format_summary: Option<String>,
    pub readable: bool,
    pub suspicious: bool,
    pub entropy: Option<f64>,
    pub ascii_strings: usize,
    pub utf16_strings: usize,
    pub hits: usize,
    pub artifacts: usize,
    pub report: Option<ForensicReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectoryScanReport {
    pub root: String,
    pub files_scanned: usize,
    pub files_analyzed: usize,
    pub suspicious_files: usize,
    pub total_hits: usize,
    pub total_artifacts: usize,
    pub type_counts: BTreeMap<String, usize>,
    pub files: Vec<DirectoryFileReport>,
}

pub fn scan_directory(path: &Path, extract_artifacts: bool) -> DirectoryScanReport {
    let mut files_scanned = 0usize;
    let mut files_analyzed = 0usize;
    let mut suspicious_files = 0usize;
    let mut total_hits = 0usize;
    let mut total_artifacts = 0usize;
    let mut type_counts = BTreeMap::new();
    let mut files = Vec::new();

    for entry in walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let file_path = entry.path();
        if !file_path.is_file() {
            continue;
        }

        files_scanned += 1;
        let file_type = detect_path_file_type(file_path);
        *type_counts.entry(file_type.clone()).or_insert(0usize) += 1;

        let mut file_report = DirectoryFileReport {
            path: file_path.display().to_string(),
            size: read_path_metadata(file_path).map(|meta| meta.size),
            file_type,
            format_summary: None,
            readable: false,
            suspicious: false,
            entropy: None,
            ascii_strings: 0,
            utf16_strings: 0,
            hits: 0,
            artifacts: 0,
            report: None,
        };

        let mut manager = FileManager::new();
        if manager
            .map_file(file_path.to_str().unwrap_or_default())
            .is_ok()
        {
            if let Some(report) = manager.build_report(extract_artifacts) {
                let suspicious = !report.hits.is_empty() || !report.artifacts.is_empty();

                files_analyzed += 1;
                total_hits += report.hits.len();
                total_artifacts += report.artifacts.len();
                if suspicious {
                    suspicious_files += 1;
                }

                file_report.readable = true;
                file_report.suspicious = suspicious;
                file_report.format_summary = report.root_artifact.as_ref().map(|artifact| {
                    artifact
                        .inspection
                        .as_ref()
                        .map(|inspection| inspection.summary.clone())
                        .unwrap_or_else(|| artifact.name.clone())
                });
                file_report.entropy = Some(report.entropy);
                file_report.ascii_strings = report.ascii_strings;
                file_report.utf16_strings = report.utf16_strings;
                file_report.hits = report.hits.len();
                file_report.artifacts = report.artifacts.len();
                if suspicious {
                    file_report.report = Some(report);
                }
            }
        }

        files.push(file_report);
    }

    DirectoryScanReport {
        root: path.display().to_string(),
        files_scanned,
        files_analyzed,
        suspicious_files,
        total_hits,
        total_artifacts,
        type_counts,
        files,
    }
}

#[cfg(test)]
mod tests {
    use super::scan_directory;

    #[test]
    fn summarizes_directory_hits_and_types() {
        let root = std::env::temp_dir().join(format!(
            "hashendra-dir-test-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("main")
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let sample = root.join("vars.txt");
        std::fs::write(
            &sample,
            b"API_KEY=\"SGVsbG8gV29ybGQ=\"\nJWT=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln\n",
        )
        .unwrap();

        let report = scan_directory(&root, false);

        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.files_analyzed, 1);
        assert_eq!(report.suspicious_files, 1);
        assert_eq!(report.total_hits, 2);
        assert_eq!(report.total_artifacts, 0);
        assert_eq!(
            report.type_counts.get("Plain / text-like").copied(),
            Some(1)
        );
        assert_eq!(report.files[0].hits, 2);
        assert!(report.files[0].report.is_some());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn known_file_format_does_not_become_suspicious_by_itself() {
        let root =
            std::env::temp_dir().join(format!("hashendra-dir-png-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let sample = root.join("tiny.png");
        std::fs::write(
            &sample,
            b"\x89PNG\r\n\x1a\n\
\x00\x00\x00\x0dIHDR\
\x00\x00\x00\x01\
\x00\x00\x00\x01\
\x08\x06\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00IEND\xAE\x42\x60\x82",
        )
        .unwrap();

        let report = scan_directory(&root, false);

        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.suspicious_files, 0);
        assert_eq!(report.total_artifacts, 0);
        assert_eq!(
            report.files[0].format_summary.as_deref(),
            Some("PNG image 1x1 (rgba, 8-bit)")
        );
        assert!(report.files[0].report.is_none());

        let _ = std::fs::remove_dir_all(&root);
    }
}
