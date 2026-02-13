use std::fs::File;
use memmap2::Mmap;
use std::io::{self, Write, Result};
use colored::*;
use crate::core::patterns::{scan_input, ScanningContext};

macro_rules! safe_println {
    ($($arg:tt)*) => {
        if let Err(e) = writeln!(io::stdout(), $($arg)*) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                std::process::exit(0);
            }
            panic!("IO error: {}", e);
        }
    }
}

pub struct FileManager {
    mmap: Option<Mmap>,
}

impl FileManager {
    pub fn new() -> Self {
        Self { mmap: None }
    }

    pub fn map_file(&mut self, path: &str) -> Result<()> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        self.mmap = Some(mmap);
        Ok(())
    }

    pub fn get_data(&self) -> Option<&[u8]> {
        self.mmap.as_ref().map(|m| &m[..])
    }

    pub fn scan_binary(&self) {
        if let Some(data) = self.get_data() {
            safe_println!("[SCAN] Starting high-speed forensic scan ({} bytes)...", data.len());
            
            let mut start = 0;
            for i in 0..data.len() {
                let byte = data[i];
                if !byte.is_ascii_graphic() && !byte.is_ascii_whitespace() {
                    let len = i - start;
                    if len >= 8 {
                        if let Ok(current_string) = std::str::from_utf8(&data[start..i]) {
                            let raw_blob = current_string.trim();
                            
                            // Scan the whole blob first
                            let results = scan_input(raw_blob, ScanningContext::Filesystem);
                            if !results.is_empty() && results[0].confidence > 0.8 {
                                report_forensic_match(start, raw_blob, results);
                            } else {
                                // If no high-confidence match, split by common delimiters
                                // labeled data like "SECRET_HASH: $2a$..." often fails anchored matches
                                for part in raw_blob.split(|c| c == ':' || c == '=' || c == ' ' || c == '\t') {
                                    let part = part.trim();
                                    if part.len() >= 8 {
                                        let sub_results = scan_input(part, ScanningContext::Filesystem);
                                        if !sub_results.is_empty() && sub_results[0].confidence > 0.8 {
                                            report_forensic_match(start, part, sub_results);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    start = i + 1;
                }
            }
        }
    }
}

fn report_forensic_match(offset: usize, blob: &str, results: Vec<crate::core::patterns::DetectionResult>) {
    safe_println!("[FORENSIC @ 0x{:08x}] Found: {}", offset, blob.cyan().bold());
    for res in results {
        safe_println!("  - {} ({:.0}%)", res.name, res.confidence * 100.0);
        if !res.extracted_parameters.is_empty() {
            for (key, val) in &res.extracted_parameters {
                safe_println!("    +- {}: {}", key.yellow(), val.white());
            }
        }
    }
}
