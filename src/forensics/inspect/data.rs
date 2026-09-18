use super::{be_u16, be_u32, format_hex, le_u16, le_u32, ArtifactInspection};
use std::collections::BTreeMap;

pub(crate) fn inspect_sqlite(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 60 || !data.starts_with(b"SQLite format 3\0") { return None; }
    let page_size_raw = be_u16(data, 16)?;
    let page_size = if page_size_raw == 1 { 65536 } else { page_size_raw as u32 };
    let write_version = *data.get(18)?;
    let read_version = *data.get(19)?;
    let schema_format = be_u32(data, 44)?;
    let text_encoding = be_u32(data, 56)?;
    let pages = be_u32(data, 28)?;

    let mut details = BTreeMap::new();
    details.insert("page_size".to_string(), page_size.to_string());
    details.insert("write_version".to_string(), sqlite_journal_name(write_version).to_string());
    details.insert("read_version".to_string(), sqlite_journal_name(read_version).to_string());
    details.insert("schema_format".to_string(), schema_format.to_string());
    details.insert("text_encoding".to_string(), sqlite_encoding_name(text_encoding).to_string());
    details.insert("pages".to_string(), pages.to_string());
    Some(ArtifactInspection {
        format: "SQLite".to_string(),
        summary: format!("SQLite 3 database with {}-byte pages", page_size),
        details,
    })
}

pub(crate) fn sqlite_journal_name(value: u8) -> &'static str {
    match value { 1 => "rollback", 2 => "wal", _ => "unknown" }
}

pub(crate) fn sqlite_encoding_name(value: u32) -> &'static str {
    match value { 1 => "utf-8", 2 => "utf-16le", 3 => "utf-16be", _ => "unknown" }
}

pub(crate) fn inspect_gzip(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 10 || &data[..3] != b"\x1F\x8B\x08" { return None; }
    let flags = *data.get(3)?;
    let mtime = le_u32(data, 4)?;
    let xfl = *data.get(8)?;
    let os = *data.get(9)?;
    let mut cursor = 10usize;

    if flags & 0x04 != 0 {
        let xlen = le_u16(data, cursor)? as usize;
        cursor = cursor.checked_add(2 + xlen)?;
        if cursor > data.len() {
            return None; // Truncated FEXTRA field.
        }
    }
    let original_name = if flags & 0x08 != 0 {
        let rest = data.get(cursor..)?;
        let end = rest.iter().position(|&byte| byte == 0).map(|idx| cursor + idx)?;
        let name = String::from_utf8_lossy(&data[cursor..end]).to_string();
        Some(name)
    } else { None };

    let mut details = BTreeMap::new();
    details.insert("compression".to_string(), "deflate".to_string());
    details.insert("flags".to_string(), format!("0x{:02X}", flags));
    details.insert("mtime_unix".to_string(), mtime.to_string());
    details.insert("extra_flags".to_string(), xfl.to_string());
    details.insert("os".to_string(), gzip_os_name(os).to_string());
    if let Some(name) = &original_name { details.insert("original_name".to_string(), name.clone()); }
    Some(ArtifactInspection {
        format: "GZIP".to_string(),
        summary: original_name.map(|n| format!("Gzip stream for {}", n)).unwrap_or_else(|| "Gzip stream".to_string()),
        details,
    })
}

pub(crate) fn gzip_os_name(value: u8) -> &'static str {
    match value { 0 => "fat", 3 => "unix", 7 => "macintosh", 11 => "ntfs", 255 => "unknown", _ => "other" }
}

// ── OOXML (Office Open XML) ─────────────────────────────────

pub(crate) fn inspect_ooxml(data: &[u8]) -> Option<ArtifactInspection> {
    if !data.starts_with(b"PK\x03\x04") { return None; }
    let mut details = BTreeMap::new();
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;

    // Try to read core.xml for document metadata
    let core_paths = [
        "docProps/core.xml",
        "docProps/app.xml",
    ];
    for path in &core_paths {
        if let Ok(mut file) = archive.by_name(path) {
            let mut content = String::new();
            if std::io::Read::read_to_string(&mut file, &mut content).is_ok() {
                extract_ooxml_metadata(&content, &mut details, file.name());
            }
        }
    }

    // Identify type from [Content_Types].xml
    if let Ok(mut file) = archive.by_name("[Content_Types].xml") {
        let mut content = String::new();
        if std::io::Read::read_to_string(&mut file, &mut content).is_ok() {
            if content.contains("wordprocessingml") {
                details.insert("document_type".to_string(), "Word Document".to_string());
            } else if content.contains("spreadsheetml") {
                details.insert("document_type".to_string(), "Excel Spreadsheet".to_string());
            } else if content.contains("presentationml") {
                details.insert("document_type".to_string(), "PowerPoint Presentation".to_string());
            }
        }
    }

    // Count parts
    let file_count = archive.len();
    details.insert("parts".to_string(), file_count.to_string());

    let doc_type = details.get("document_type").map(|s| s.as_str()).unwrap_or("Office Document");
    let summary = match details.get("title") {
        Some(t) => format!("{}: {}", doc_type, t),
        None => format!("{} with {} parts", doc_type, file_count),
    };

    Some(ArtifactInspection { format: "OOXML".to_string(), summary, details })
}

pub(crate) fn extract_ooxml_metadata(xml: &str, details: &mut BTreeMap<String, String>, _path: &str) {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    let mut reader = Reader::from_str(xml);
    let mut in_element = String::new();
    let mut text = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let stripped = name.rsplit(':').next().unwrap_or(&name).to_string();
                in_element = stripped;
                text.clear();
            }
            Ok(Event::Text(ref e)) => {
                text = e.unescape().unwrap_or_default().to_string();
            }
            Ok(Event::End(_)) => {
                if !text.is_empty() && !in_element.is_empty() {
                    match in_element.as_str() {
                        "title" | "creator" | "subject" | "description" | "keywords" =>
                            { details.insert(in_element.clone(), text.clone()); }
                        "created" | "modified" => {
                            let clean = text.trim().to_string();
                            if clean.len() >= 10 {
                                details.insert(if in_element == "created" { "date_created" } else { "date_modified" }.to_string(), clean);
                            }
                        }
                        "revision" => { details.insert("revision".to_string(), text.clone()); }
                        "lastModifiedBy" => { details.insert("last_modified_by".to_string(), text.clone()); }
                        "Application" => { details.insert("application".to_string(), text.clone()); }
                        "AppVersion" => { details.insert("app_version".to_string(), text.clone()); }
                        "TotalTime" => { details.insert("edit_time_minutes".to_string(), text.clone()); }
                        "Pages" => { details.insert("pages".to_string(), text.clone()); }
                        "Words" => { details.insert("words".to_string(), text.clone()); }
                        "Characters" => { details.insert("characters".to_string(), text.clone()); }
                        "Lines" => { details.insert("lines".to_string(), text.clone()); }
                        "Paragraphs" => { details.insert("paragraphs".to_string(), text.clone()); }
                        "Slides" => { details.insert("slides".to_string(), text.clone()); }
                        "Notes" => { details.insert("notes".to_string(), text.clone()); }
                        "HiddenSlides" => { details.insert("hidden_slides".to_string(), text.clone()); }
                        "Company" => { details.insert("company".to_string(), text.clone()); }
                        "Manager" => { details.insert("manager".to_string(), text.clone()); }
                        "ScaleCrop" => { details.insert("scale_crop".to_string(), text.clone()); }
                        "LinksUpToDate" => { details.insert("links_up_to_date".to_string(), text.clone()); }
                        "SharedDoc" => { details.insert("shared_doc".to_string(), text.clone()); }
                        "HyperlinksChanged" => { details.insert("hyperlinks_changed".to_string(), text.clone()); }
                        "Category" => { details.insert("category".to_string(), text.clone()); }
                        "ContentStatus" => { details.insert("content_status".to_string(), text.clone()); }
                        _ => {}
                    }
                }
                in_element.clear();
                text.clear();
            }
            Ok(Event::Eof) => break,
            _ => {} // ignore other event types (CData, Comment, Decl, etc.)
        }
    }
}

// ── OLE / RAR / 7z ─────────────────────────────────────────

pub(crate) fn inspect_ole(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 8 || data[..8] != [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] { return None; }
    let mut details = BTreeMap::new();
    if data.len() >= 24 {
        let minor = le_u16(data, 24)?;
        let major = le_u16(data, 26)?;
        details.insert("version".to_string(), format!("{}.{}", major, minor));
    }
    let byte_order = le_u16(data, 28)?;
    details.insert("byte_order".to_string(), if byte_order == 0xFFFE { "little_endian" } else { "big_endian" }.to_string());
    if let Some(sector_shift) = data.get(30).copied() {
        details.insert("sector_size".to_string(), format!("{} bytes", 1 << sector_shift as u64));
    }
    Some(ArtifactInspection {
        format: "OLE".to_string(),
        summary: "OLE2 Compound Document".to_string(),
        details,
    })
}

pub(crate) fn inspect_rar(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 15 { return None; }
    let version = if &data[..7] == b"Rar!\x1A\x07\x00" { "4.x" }
                  else if data.len() >= 8 && &data[..8] == b"Rar!\x1A\x07\x01\x00" { "5.x" }
                  else { return None; };
    let mut details = BTreeMap::new();
    details.insert("format_version".to_string(), version.to_string());
    if *data.get(9).unwrap_or(&0) & 0x04 != 0 {
        details.insert("volume".to_string(), "multi-part".to_string());
    }
    if *data.get(9).unwrap_or(&0) & 0x08 != 0 {
        details.insert("has_comment".to_string(), "yes".to_string());
    }
    Some(ArtifactInspection {
        format: "RAR".to_string(),
        summary: format!("RAR archive ({})", version),
        details,
    })
}

pub(crate) fn inspect_7z(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 32 || data[..6] != [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] { return None; }
    let mut details = BTreeMap::new();
    let major = data.get(6).copied().unwrap_or(0);
    let minor = data.get(7).copied().unwrap_or(0);
    details.insert("version".to_string(), format!("{}.{}", major, minor));
    if data.len() >= 32 {
        let crc = le_u32(data, 12)?;
        details.insert("header_crc".to_string(), format_hex(crc as u64));
    }
    Some(ArtifactInspection {
        format: "7z".to_string(),
        summary: format!("7z archive ({}.{})", major, minor),
        details,
    })
}

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod gzip_bounds_tests {
    use super::*;

    #[test]
    fn fextra_past_eof_returns_none() {
        // Magic + FHCRC-less flags with FEXTRA claiming 300 bytes in a 20-byte input.
        let mut header = vec![0x1F, 0x8B, 0x08, 0x04, 0, 0, 0, 0, 0, 0xFF, 0x2C, 0x01];
        header.extend_from_slice(&[0u8; 8]);
        assert!(inspect_gzip(&header).is_none());
    }

    #[test]
    fn fname_without_nul_returns_none() {
        let mut header = vec![0x1F, 0x8B, 0x08, 0x08, 0, 0, 0, 0, 0, 0xFF];
        header.extend_from_slice(b"unterminated");
        assert!(inspect_gzip(&header).is_none());
    }

    #[test]
    fn minimal_valid_header_parses() {
        let header = [0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0x03];
        assert!(inspect_gzip(&header).is_some());
    }
}
