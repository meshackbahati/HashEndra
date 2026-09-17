use super::{format_hex, le_u16, le_u32, plural_y, ArtifactInspection};
use std::collections::BTreeMap;
use super::images::parse_tiff_ifd;

pub(crate) fn inspect_bmp(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 26 || &data[..2] != b"BM" { return None; }
    let file_size = le_u32(data, 2)?;
    let data_offset = le_u32(data, 10)?;
    let header_size = le_u32(data, 14)?;
    let width = le_i32(data, 18)?;
    let height = le_i32(data, 22)?;
    let planes = le_u16(data, 26)?;
    let bpp = le_u16(data, 28)?;
    let compression = le_u32(data, 30)?;

    let mut details = BTreeMap::new();
    details.insert("file_size".to_string(), format_bytes(file_size as u64));
    details.insert("data_offset".to_string(), format_hex(data_offset as u64));
    details.insert("header_size".to_string(), header_size.to_string());
    details.insert("width".to_string(), width.abs().to_string());
    details.insert("height".to_string(), height.abs().to_string());
    details.insert("planes".to_string(), planes.to_string());
    details.insert("bit_depth".to_string(), bpp.to_string());
    details.insert("compression".to_string(), bmp_compression_name(compression).to_string());

    let abs_h = height.unsigned_abs();
    let summary = format!("BMP image {}x{} ({}-bit)", width.abs(), abs_h, bpp);
    Some(ArtifactInspection { format: "BMP".to_string(), summary, details })
}

pub(crate) fn le_i32(data: &[u8], offset: usize) -> Option<i32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn bmp_compression_name(v: u32) -> &'static str {
    match v { 0 => "none (RGB)", 1 => "RLE8", 2 => "RLE4", 3 => "BITFIELDS", 4 => "JPEG", 5 => "PNG", _ => "other" }
}

pub(crate) fn format_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut unit = 0usize;
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{} {}", n, UNITS[unit]) }
    else { format!("{:.1} {}", v, UNITS[unit]) }
}

// ── ICO ────────────────────────────────────────────────────

pub(crate) fn inspect_ico(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 6 || &data[..4] != b"\0\0\x01\0" { return None; }
    let count = le_u16(data, 4)?;
    let mut details = BTreeMap::new();
    details.insert("icon_count".to_string(), count.to_string());
    let max = count.min(50) as usize;
    for i in 0..max {
        let off = 6 + i * 16;
        if off + 16 > data.len() { break; }
        let w = if data[off] == 0 { 256 } else { data[off] as u32 };
        let h = if data[off + 1] == 0 { 256 } else { data[off + 1] as u32 };
        let bpp = data.get(off + 6).copied().unwrap_or(0);
        let sz = le_u32(data, off + 8).unwrap_or(0);
        details.insert(format!("entry_{}", i), format!("{}x{} {}bpp {}B", w, h, bpp, sz));
    }
    Some(ArtifactInspection {
        format: "ICO".to_string(),
        summary: format!("Icon with {} entr{}", count, plural_y(count as usize)),
        details,
    })
}

// ── TIFF ───────────────────────────────────────────────────

pub(crate) fn inspect_tiff(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 8 { return None; }
    let details = parse_tiff_ifd(data);
    let w = details.get("image_width").or(details.get("pixel_x_dimension")).and_then(|v| v.parse::<u32>().ok());
    let h = details.get("image_length").or(details.get("pixel_y_dimension")).and_then(|v| v.parse::<u32>().ok());
    let _ = w; let _ = h;
    let summary = match (w, h) {
        (Some(w), Some(h)) => format!("TIFF image {}x{}", w, h),
        _ => "TIFF image".to_string(),
    };
    Some(ArtifactInspection { format: "TIFF".to_string(), summary, details })
}

// ── RIFF (dispatches to WAV or AVI) ────────────────────────
