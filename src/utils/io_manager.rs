use std::fs::File;
use memmap2::Mmap;
use std::io::{self, Write, Result};
use std::path::PathBuf;
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
    path: Option<PathBuf>,
}

impl FileManager {
    pub fn new() -> Self {
        Self { mmap: None, path: None }
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

    pub fn scan_binary(&self) {
        if let Some(data) = self.get_data() {
            safe_println!("[SCAN] Starting high-speed forensic scan ({} bytes)...", data.len());
            
            // 1. Signature Scanning
            use crate::detectors::stego::scan_for_signatures;
            let file_matches = scan_for_signatures(data);
            
            if !file_matches.is_empty() {
                safe_println!("\n[FORENSIC] Detected embedded file signatures:");
                
                // Prepare output directory if we need to extract
                let output_dir = if let Some(p) = &self.path {
                    let file_stem = p.file_stem().unwrap_or_default().to_string_lossy();
                    format!("extracted_{}", file_stem)
                } else {
                    "extracted_files".to_string()
                };

                for (idx, m) in file_matches.iter().enumerate() {
                    let location = if m.offset == 0 { "Start of file".to_string() } else { format!("Offset 0x{:X}", m.offset) };
                    safe_println!("  - [{}] {} matches {} ({})", idx, location.yellow(), m.signature.name.green(), m.signature.description);
                    
                    // If it's NOT at the start (or if it is but we are scanning a blob/stream), suggest extraction
                    if m.offset > 0 || file_matches.len() > 1 {
                        // Check if we should extract
                        let ext = m.signature.extension;
                        
                        // Ensure directory exists
                        if std::fs::create_dir_all(&output_dir).is_ok() {
                            let filename = format!("{}/extracted_{:08x}.{}", output_dir, m.offset, ext);
                            
                            // Limit extraction size? 
                            // If we don't know the end, we extract till end of file
                            let content = &data[m.offset..];
                            if let Ok(_) = std::fs::write(&filename, content) {
                                 safe_println!("    [EXTRACTED] Saved to {}", filename.cyan());
                            } else {
                                 safe_println!("    [FAIL] Could not write extraction");
                            }
                        } else {
                             safe_println!("    [FAIL] Could not create output directory {}", output_dir);
                        }
                    }
                }
            }

            let mut start = 0;
            // ... existing string scan logic
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
