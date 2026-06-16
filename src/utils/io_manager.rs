use crate::forensics::report::{ForensicReport, build_forensic_report, print_forensic_report};
use crate::safe_println;
use memmap2::Mmap;
use std::fs::File;
use std::io::Result;
use std::path::{Path, PathBuf};

// safe_println! is defined in utils/io.rs via #[macro_export]

pub struct FileManager {
    mmap: Option<Mmap>,
    path: Option<PathBuf>,
}

impl FileManager {
    pub fn new() -> Self {
        Self {
            mmap: None,
            path: None,
        }
    }

    pub fn map_file(&mut self, path: &str) -> Result<()> {
        self.path = Some(PathBuf::from(path));
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        self.mmap = Some(mmap);
        Ok(())
    }

    pub fn get_data(&self) -> Option<&[u8]> {
        self.mmap.as_ref().map(|m| &m[..])
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn build_report(&self, extract_artifacts: bool) -> Option<ForensicReport> {
        let data = self.get_data()?;
        Some(build_forensic_report(data, self.path(), extract_artifacts))
    }

    pub fn scan_binary(&self, extract_artifacts: bool) {
        if let Some(report) = self.build_report(extract_artifacts) {
            safe_println!(
                "[SCAN] Starting high-speed forensic scan ({} bytes)...",
                report.size
            );
            print_forensic_report(&report);
        }
    }
}
