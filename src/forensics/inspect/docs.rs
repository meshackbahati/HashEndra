use super::{find_zip_eocd, format_bytes, format_hex, le_u16, le_u32, plural_y, ArtifactInspection};
use std::collections::BTreeMap;

pub(crate) fn inspect_pdf(data: &[u8]) -> Option<ArtifactInspection> {
    if !data.starts_with(b"%PDF-") || data.len() < 8 { return None; }
    let version_end = data[5..]
        .iter()
        .position(|byte| !matches!(byte, b'0'..=b'9' | b'.'))
        .map(|idx| 5 + idx)
        .unwrap_or(data.len().min(8));
    let version = String::from_utf8_lossy(&data[5..version_end]).to_string();
    let eof_markers = data.windows(5).filter(|window| *window == b"%%EOF").count();
    let object_markers = data.windows(4).filter(|window| *window == b" obj").count();

    // Extract metadata from PDF info dictionary
    let content = String::from_utf8_lossy(data);
    let mut details = BTreeMap::new();
    details.insert("version".to_string(), version.clone());
    details.insert("eof_markers".to_string(), eof_markers.to_string());
    details.insert("object_markers".to_string(), object_markers.to_string());

    // Extract common PDF metadata keys
    for key in &["/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer", "/ModDate", "/CreationDate"] {
        if let Some(pos) = content.find(key) {
            let after = &content[pos + key.len()..];
            if let Some(paren_start) = after.find('(') {
                let val_start = paren_start + 1;
                if let Some(paren_end) = after[val_start..].find(')') {
                    let val = &after[val_start..val_start + paren_end];
                    let clean_val = val.to_string();
                    details.insert(key[1..].to_ascii_lowercase(), clean_val);
                }
            }
        }
    }

    Some(ArtifactInspection {
        format: "PDF".to_string(),
        summary: format!("PDF document version {}", version),
        details,
    })
}

pub(crate) fn inspect_zip(data: &[u8]) -> Option<ArtifactInspection> {
    let eocd = find_zip_eocd(data)?;
    if eocd + 22 > data.len() { return None; }
    let total_entries = le_u16(data, eocd + 10)? as usize;
    let central_directory_size = le_u32(data, eocd + 12)? as usize;
    let central_directory_offset = le_u32(data, eocd + 16)? as usize;
    let comment_length = le_u16(data, eocd + 20)? as usize;
    let central_end = central_directory_offset.checked_add(central_directory_size)?;
    if central_end > data.len() { return None; }

    let mut entry_names = Vec::new();
    let mut encrypted_entries = 0usize;
    let mut compressed_total = 0u64;
    let mut uncompressed_total = 0u64;
    let mut methods = Vec::new();
    let mut cursor = central_directory_offset;

    while cursor + 46 <= central_end && entry_names.len() < total_entries.min(128) {
        if &data[cursor..cursor + 4] != b"PK\x01\x02" { break; }
        let flags = le_u16(data, cursor + 8)?;
        let method = le_u16(data, cursor + 10)?;
        let compressed = le_u32(data, cursor + 20)? as u64;
        let uncompressed = le_u32(data, cursor + 24)? as u64;
        let name_len = le_u16(data, cursor + 28)? as usize;
        let extra_len = le_u16(data, cursor + 30)? as usize;
        let comment_len_local = le_u16(data, cursor + 32)? as usize;
        let name_start = cursor + 46;
        let name_end = name_start.checked_add(name_len)?;
        if name_end > data.len() { break; }

        if flags & 0x1 != 0 { encrypted_entries += 1; }
        compressed_total += compressed;
        uncompressed_total += uncompressed;

        let method_name = zip_method_name(method).to_string();
        if !methods.contains(&method_name) { methods.push(method_name); }
        entry_names.push(String::from_utf8_lossy(&data[name_start..name_end]).to_string());
        cursor = name_end.checked_add(extra_len)?.checked_add(comment_len_local)?;
    }

    let mut details = BTreeMap::new();
    details.insert("entries".to_string(), total_entries.to_string());
    details.insert("central_directory_offset".to_string(), format_hex(central_directory_offset as u64));
    details.insert("central_directory_size".to_string(), central_directory_size.to_string());
    details.insert("comment_length".to_string(), comment_length.to_string());
    details.insert("compressed_size".to_string(), format_bytes(compressed_total));
    details.insert("uncompressed_size".to_string(), format_bytes(uncompressed_total));
    if !methods.is_empty() { details.insert("compression_methods".to_string(), methods.join(", ")); }
    if !entry_names.is_empty() { details.insert("sample_entries".to_string(), entry_names.join(", ")); }
    if encrypted_entries > 0 { details.insert("encrypted_entries".to_string(), encrypted_entries.to_string()); }

    Some(ArtifactInspection {
        format: "ZIP".to_string(),
        summary: format!("ZIP archive with {} entr{}", total_entries, plural_y(total_entries)),
        details,
    })
}

pub(crate) fn zip_method_name(method: u16) -> &'static str {
    match method {
        0 => "stored", 1 => "shrunk", 8 => "deflate", 12 => "bzip2",
        14 => "lzma", 93 => "zstd", _ => "other",
    }
}
