use crate::detectors::stego::identify_file_signature;
use serde::Serialize;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct PathMetadata {
    pub size: u64,
    pub is_dir: bool,
}

pub fn read_path_metadata(path: &Path) -> Option<PathMetadata> {
    let meta = std::fs::metadata(path).ok()?;
    Some(PathMetadata {
        size: meta.len(),
        is_dir: meta.is_dir(),
    })
}

pub fn detect_path_file_type(path: &Path) -> String {
    if path.is_dir() {
        return "Directory".to_string();
    }

    let Ok(mut file) = std::fs::File::open(path) else {
        return "Unreadable".to_string();
    };

    let mut header = [0u8; 64];
    let Ok(read_len) = file.read(&mut header) else {
        return "Unreadable".to_string();
    };

    detect_buffer_type(&header[..read_len])
}

pub fn detect_buffer_type(data: &[u8]) -> String {
    if data.is_empty() {
        return "Empty file".to_string();
    }

    if let Some(sig) = identify_file_signature(data) {
        return format!("{} ({})", sig.name, sig.description);
    }

    if data
        .iter()
        .all(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
    {
        "Plain / text-like".to_string()
    } else {
        "Unknown binary".to_string()
    }
}
