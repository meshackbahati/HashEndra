use crate::detectors::stego::{identify_file_signature, FileSignature};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactInspection {
    pub format: String,
    pub summary: String,
    pub details: BTreeMap<String, String>,
}

pub fn inspect_data(data: &[u8]) -> Option<ArtifactInspection> {
    let signature = identify_file_signature(data)?;
    inspect_artifact(data, signature)
}

pub fn inspect_artifact(data: &[u8], signature: &FileSignature) -> Option<ArtifactInspection> {
    match signature.extension {
        "jpg" | "jpeg" => inspect_jpeg_exif(data),
        "png" => inspect_png(data),
        "gif" => inspect_gif(data),
        "bmp" => inspect_bmp(data),
        "pdf" => inspect_pdf(data),
        "zip" => inspect_zip(data),
        "elf" => inspect_elf(data),
        "exe" => inspect_pe(data),
        "macho" => inspect_macho(data),
        "sqlite" => inspect_sqlite(data),
        "gz" => inspect_gzip(data),
        "riff" => inspect_riff(data),
        "mp3" => inspect_id3(data),
        "flac" => inspect_flac(data),
        "mp4" | "mov" => inspect_mp4(data),
        "avi" => inspect_avi(data),
        "docx" | "xlsx" | "pptx" => inspect_ooxml(data),
        "ole" => inspect_ole(data),
        "rar" => inspect_rar(data),
        "7z" => inspect_7z(data),
        "ico" => inspect_ico(data),
        "tiff" | "tif" => inspect_tiff(data),
        _ => None,
    }
}

fn be_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn be_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn be_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_u16(data: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    if little_endian { le_u16(data, offset) } else { be_u16(data, offset) }
}

fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    if little_endian { le_u32(data, offset) } else { be_u32(data, offset) }
}

fn read_u64(data: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
    if little_endian { le_u64(data, offset) } else { be_u64(data, offset) }
}

fn format_hex(value: u64) -> String {
    format!("0x{:X}", value)
}

fn plural_y(count: usize) -> &'static str {
    if count == 1 { "y" } else { "ies" }
}

fn find_zip_eocd(data: &[u8]) -> Option<usize> {
    let search_start = data.len().saturating_sub(22 + 65_535);
    data[search_start..]
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .map(|idx| search_start + idx)
}

// ── JPEG EXIF ──────────────────────────────────────────────

fn inspect_jpeg_exif(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return None;
    }
    let mut details = BTreeMap::new();
    let mut dims_shown = false;

    // Parse JPEG markers for dimensions and comments
    let mut offset = 2usize;
    while offset + 4 <= data.len() {
        if data[offset] != 0xFF {
            break;
        }
        let marker = data[offset + 1];
        if marker == 0xDA {
            break; // SOS - image data starts
        }
        if marker == 0xD9 {
            break;
        }
        if marker == 0xD8 || marker == 0xD0 || marker == 0xD1 ||
           marker == 0xD2 || marker == 0xD3 || marker == 0xD4 ||
           marker == 0xD5 || marker == 0xD6 || marker == 0xD7 {
            offset += 2;
            continue;
        }
        if offset + 4 > data.len() {
            break;
        }
        let seg_len = be_u16(data, offset + 2)? as usize;
        if seg_len < 2 || offset + 2 + seg_len > data.len() {
            break;
        }
        let seg_data = &data[offset + 4..offset + 2 + seg_len];
        match marker {
            0xE0 => {
                // JFIF
                if !dims_shown {
                    if let Some(density) = seg_data.get(0..5) {
                        if density == b"JFIF\0" {
                            details.insert("jfif_version".to_string(),
                                format!("{}.{}", seg_data.get(5).unwrap_or(&0), seg_data.get(6).unwrap_or(&0)));
                            details.insert("density".to_string(),
                                format!("{}x{} {}", be_u16(seg_data, 8).unwrap_or(0), be_u16(seg_data, 10).unwrap_or(0),
                                    match seg_data.get(7).unwrap_or(&0) {
                                        1 => "dots/inch",
                                        2 => "dots/cm",
                                        _ => "aspect",
                                    }));
                        }
                    }
                }
            }
            0xE1 => {
                // EXIF
                if !dims_shown && let Some(exif) = parse_exif_ifd(seg_data) {
                    details.extend(exif);
                    dims_shown = true;
                }
            }
            0xFE => {
                // Comment
                if !seg_data.is_empty() {
                    let comment = String::from_utf8_lossy(seg_data).to_string();
                    details.insert("comment".to_string(), comment);
                }
            }
            0xC0 | 0xC1 | 0xC2 | 0xC3 => {
                // SOF0-3: dimensions
                if !dims_shown && seg_data.len() >= 5 {
                    details.insert("width".to_string(), be_u16(seg_data, 3).unwrap_or(0).to_string());
                    details.insert("height".to_string(), be_u16(seg_data, 1).unwrap_or(0).to_string());
                    details.insert("precision".to_string(), format!("{}-bit", seg_data[0]));
                    let components = seg_data.get(4).copied().unwrap_or(0);
                    details.insert("components".to_string(), components.to_string());
                    details.insert("color_mode".to_string(),
                        match components { 1 => "grayscale", 3 => "ycbcr", 4 => "cmyk", _ => "other" }.to_string());
                    dims_shown = true;
                }
            }
            _ => {}
        }
        offset += 2 + seg_len;
    }

    // Try kamadak-exif for richer metadata
    if let Ok(exif_reader) = exif::Reader::new().read_from_container(&mut std::io::Cursor::new(data)) {
        for field in exif_reader.fields() {
            let tag = field.tag;
            let value = field.display_value().to_string();
            if !value.is_empty() && value != "None" {
                let key = format!("exif:{}", tag);
                if !details.contains_key(&key) {
                    details.insert(key, value);
                }
            }
        }
    }

    let summary = if let (Some(w), Some(h)) = (details.get("width"), details.get("height")) {
        format!("JPEG image {}x{}", w, h)
    } else {
        "JPEG image".to_string()
    };

    Some(ArtifactInspection {
        format: "JPEG".to_string(),
        summary,
        details,
    })
}

fn parse_exif_ifd(data: &[u8]) -> Option<BTreeMap<String, String>> {
    // EXIF in TIFF structure: "Exif\0\0" + TIFF header
    if data.len() < 6 || &data[..6] != b"Exif\0\0" {
        return None;
    }
    let tiff = &data[6..];
    Some(parse_tiff_ifd(tiff))
}

fn parse_tiff_ifd(data: &[u8]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if data.len() < 8 { return map; }
    let little_endian = match &data[..4] {
        b"II\x2A\0" => true,
        b"MM\0\x2A" => false,
        _ => return map,
    };
    let ifd_offset = read_u32(data, 4, little_endian).unwrap_or(8) as usize;
    if ifd_offset + 2 > data.len() { return map; }
    let entry_count = read_u16(data, ifd_offset, little_endian).unwrap_or(0) as usize;
    for i in 0..entry_count {
        let entry_off = ifd_offset + 2 + i * 12;
        if entry_off + 12 > data.len() { break; }
        let tag = read_u16(data, entry_off, little_endian).unwrap_or(0);
        let typ = read_u16(data, entry_off + 2, little_endian).unwrap_or(0);
        let count = read_u32(data, entry_off + 4, little_endian).unwrap_or(0) as usize;
        let value_off = read_u32(data, entry_off + 8, little_endian).unwrap_or(0) as usize;
        let tag_name = exif_tag_name(tag);
        let value = if tag == 0x8769 || tag == 0xA005 {
            // SubIFD or Interop IFD - recurse
            continue;
        } else if typ == 2 && value_off + count <= data.len() {
            // ASCII
            let s = String::from_utf8_lossy(&data[value_off..value_off + count])
                .trim_end_matches('\0').to_string();
            s
        } else if typ == 3 && count == 1 {
            read_u16(data, entry_off + 8, little_endian).unwrap_or(0).to_string()
        } else if typ == 4 && count == 1 {
            read_u32(data, entry_off + 8, little_endian).unwrap_or(0).to_string()
        } else {
            format!("<{} values>", count)
        };
        if !value.is_empty() && value != "0" {
            map.insert(tag_name, value);
        }
    }
    map
}

fn exif_tag_name(tag: u16) -> String {
    match tag {
        0x010E => "description".to_string(),
        0x010F => "make".to_string(),
        0x0110 => "model".to_string(),
        0x0112 => "orientation".to_string(),
        0x011A => "x_resolution".to_string(),
        0x011B => "y_resolution".to_string(),
        0x0128 => "resolution_unit".to_string(),
        0x0131 => "software".to_string(),
        0x0132 => "datetime".to_string(),
        0x013B => "artist".to_string(),
        0x0213 => "ycrcb_positioning".to_string(),
        0x8298 => "copyright".to_string(),
        0x8769 => "exif_offset".to_string(),
        0x8822 => "exposure_program".to_string(),
        0x8827 => "iso_speed".to_string(),
        0x9003 => "datetime_original".to_string(),
        0x9004 => "datetime_digitized".to_string(),
        0x9101 => "components_config".to_string(),
        0x9201 => "shutter_speed".to_string(),
        0x9202 => "aperture".to_string(),
        0x9204 => "exposure_bias".to_string(),
        0x9205 => "max_aperture".to_string(),
        0x9207 => "metering_mode".to_string(),
        0x9208 => "light_source".to_string(),
        0x9209 => "flash".to_string(),
        0x920A => "focal_length".to_string(),
        0x9290 => "subsec_time".to_string(),
        0x9291 => "subsec_time_original".to_string(),
        0xA002 => "pixel_x_dimension".to_string(),
        0xA003 => "pixel_y_dimension".to_string(),
        0xA005 => "interop_offset".to_string(),
        0xA20E => "focal_plane_xres".to_string(),
        0xA20F => "focal_plane_yres".to_string(),
        0xA217 => "sensing_method".to_string(),
        0xA300 => "file_source".to_string(),
        0xA301 => "scene_type".to_string(),
        0xA401 => "custom_rendered".to_string(),
        0xA402 => "exposure_mode".to_string(),
        0xA403 => "white_balance".to_string(),
        0xA404 => "digital_zoom".to_string(),
        0xA405 => "focal_length_35mm".to_string(),
        0xA406 => "scene_capture_type".to_string(),
        0xA407 => "gain_control".to_string(),
        0xA408 => "contrast".to_string(),
        0xA409 => "saturation".to_string(),
        0xA40A => "sharpness".to_string(),
        0xA420 => "image_unique_id".to_string(),
        _ => format!("tag_0x{:04X}", tag),
    }
}

// ── PNG ────────────────────────────────────────────────────

fn inspect_png(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 29 || &data[12..16] != b"IHDR" {
        return None;
    }
    let width = be_u32(data, 16)?;
    let height = be_u32(data, 20)?;
    let bit_depth = data.get(24).copied()?;
    let color_type = data.get(25).copied()?;
    let interlace = data.get(28).copied()?;

    let mut details = BTreeMap::new();
    details.insert("width".to_string(), width.to_string());
    details.insert("height".to_string(), height.to_string());
    details.insert("bit_depth".to_string(), bit_depth.to_string());
    details.insert("color_type".to_string(), png_color_type_name(color_type).to_string());
    details.insert("interlace".to_string(), if interlace == 0 { "none" } else { "adam7" }.to_string());

    // Parse chunk metadata
    let mut offset = 33usize; // skip signature (8) + IHDR (25)
    while offset + 12 <= data.len() {
        let chunk_len = be_u32(data, offset).unwrap_or(0) as usize;
        let chunk_type = &data[offset + 4..offset + 8];
        let chunk_data = offset + 8;
        let chunk_end = chunk_data + chunk_len;

        if chunk_end > data.len() { break; }

        match chunk_type {
            b"gAMA" if chunk_len == 4 => {
                let gamma = be_u32(data, chunk_data).unwrap_or(0);
                details.insert("gamma".to_string(), format!("{}", gamma as f64 / 100000.0));
            }
            b"pHYs" if chunk_len == 9 => {
                let ppu_x = be_u32(data, chunk_data).unwrap_or(0);
                let ppu_y = be_u32(data, chunk_data + 4).unwrap_or(0);
                let unit = data.get(chunk_data + 8).copied().unwrap_or(0);
                let unit_s = if unit == 1 { "per meter" } else { "unknown" };
                details.insert("pixels_per_unit_x".to_string(), ppu_x.to_string());
                details.insert("pixels_per_unit_y".to_string(), ppu_y.to_string());
                details.insert("physical_unit".to_string(), unit_s.to_string());
            }
            b"tEXt" | b"zTXt" | b"iTXt" => {
                if let Some(null_pos) = data[chunk_data..chunk_end].iter().position(|&b| b == 0) {
                    let key = String::from_utf8_lossy(&data[chunk_data..chunk_data + null_pos]).to_string();
                    let value_start = chunk_data + null_pos + 1;
                    if value_start < chunk_end {
                        let raw_value = &data[value_start..chunk_end];
                        let value = if chunk_type == b"zTXt" {
                            decompress_zlib_text(raw_value).unwrap_or_else(|| hex::encode(raw_value))
                        } else if chunk_type == b"iTXt" {
                            // Skip compression flag + method (2 bytes)
                            let val_start = value_start + 2;
                            if val_start < chunk_end {
                                let raw = &data[val_start..chunk_end];
                                String::from_utf8_lossy(raw).to_string()
                            } else {
                                String::new()
                            }
                        } else {
                            String::from_utf8_lossy(raw_value).to_string()
                        };
                        let safe_key = key.replace(' ', "_").to_ascii_lowercase();
                        if !value.is_empty() {
                            details.insert(format!("png:{}", safe_key), value);
                        }
                    }
                }
            }
            b"tIME" if chunk_len == 7 => {
                let s = |off: usize| data.get(chunk_data + off).copied().unwrap_or(0);
                details.insert("last_modified".to_string(),
                    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                        be_u16(data, chunk_data).unwrap_or(0), s(2), s(3), s(4), s(5), s(6)));
            }
            b"oFFs" if chunk_len == 9 => {
                let x = be_u32(data, chunk_data).unwrap_or(0);
                let y = be_u32(data, chunk_data + 4).unwrap_or(0);
                let unit_s = match data.get(chunk_data + 8).copied().unwrap_or(0) {
                    0 => "pixels",
                    1 => "micrometers",
                    _ => "unknown",
                };
                details.insert("image_offset_x".to_string(), x.to_string());
                details.insert("image_offset_y".to_string(), y.to_string());
                details.insert("offset_unit".to_string(), unit_s.to_string());
            }
            b"IEND" => break,
            _ => {}
        }
        offset = chunk_end + 4; // +4 for CRC
    }

    Some(ArtifactInspection {
        format: "PNG".to_string(),
        summary: format!("PNG image {}x{} ({}, {}-bit)", width, height, png_color_type_name(color_type), bit_depth),
        details,
    })
}

fn decompress_zlib_text(data: &[u8]) -> Option<String> {
    use std::io::Read;
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut s = String::new();
    decoder.read_to_string(&mut s).ok()?;
    Some(s)
}

fn png_color_type_name(color_type: u8) -> &'static str {
    match color_type {
        0 => "grayscale",
        2 => "rgb",
        3 => "indexed",
        4 => "grayscale+alpha",
        6 => "rgba",
        _ => "unknown",
    }
}

// ── GIF ────────────────────────────────────────────────────

fn inspect_gif(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 14 { return None; }
    let version = if &data[..3] == b"GIF" {
        String::from_utf8_lossy(&data[3..6]).to_string()
    } else { return None; };

    let width = le_u16(data, 6)?;
    let height = le_u16(data, 8)?;
    let packed = data.get(10).copied()?;
    let bg_color = data.get(11).copied()?;
    let aspect = data.get(12).copied()?;

    let has_global_table = (packed & 0x80) != 0;
    let color_resolution = ((packed >> 4) & 0x07) + 1;
    let table_size = 1 << ((packed & 0x07) + 1);

    let mut details = BTreeMap::new();
    details.insert("version".to_string(), version);
    details.insert("width".to_string(), width.to_string());
    details.insert("height".to_string(), height.to_string());
    details.insert("color_resolution".to_string(), format!("{}-bit", color_resolution));
    details.insert("global_color_table".to_string(), if has_global_table {
        format!("yes ({} colors)", table_size)
    } else { "no".to_string() });
    details.insert("background_color_index".to_string(), bg_color.to_string());
    details.insert("pixel_aspect_ratio".to_string(), aspect.to_string());

    // Parse extensions for frame count and comments
    let mut frame_count = 0u32;
    let mut comment = String::new();
    let mut offset = if has_global_table { 13 + table_size * 3 } else { 13 };
    while offset + 2 <= data.len() {
        if data[offset] == 0x3B { break; } // trailer
        if data[offset] == 0x21 {
            // Extension
            let ext_label = data[offset + 1];
            offset += 2;
            if offset >= data.len() { break; }
            if ext_label == 0xF9 {
                // Graphics control extension
                frame_count += 1;
            }
            if ext_label == 0xFE {
                // Comment extension
                let mut comment_parts = Vec::new();
                while offset < data.len() && data[offset] != 0 {
                    let block_size = data[offset] as usize;
                    if offset + 1 + block_size > data.len() { break; }
                    comment_parts.push(String::from_utf8_lossy(&data[offset + 1..offset + 1 + block_size]).to_string());
                    offset += 1 + block_size;
                }
                comment = comment_parts.join("");
            }
            // Skip to next block terminator
            while offset < data.len() && data[offset] != 0 {
                let block_size = data[offset] as usize;
                offset += 1 + block_size;
            }
            offset += 1;
        } else if data[offset] == 0x2C {
            frame_count += 1;
            // Skip image descriptor + local color table
            if offset + 10 > data.len() { break; }
            let local_packed = data[offset + 9];
            let local_table_size = if (local_packed & 0x80) != 0 {
                1 << ((local_packed & 0x07) + 1)
            } else { 0 };
            offset += 10 + local_table_size * 3;
            // Skip image data sub-blocks
            while offset < data.len() && data[offset] != 0 {
                let block_size = data[offset] as usize;
                offset += 1 + block_size;
            }
            offset += 1;
        } else {
            break;
        }
    }

    details.insert("frame_count".to_string(), frame_count.to_string());
    if !comment.is_empty() {
        details.insert("comment".to_string(), comment);
    }

    Some(ArtifactInspection {
        format: "GIF".to_string(),
        summary: format!("GIF image {}x{}, {} frame{}", width, height, frame_count, if frame_count == 1 { "" } else { "s" }),
        details,
    })
}

// ── BMP ────────────────────────────────────────────────────

fn inspect_bmp(data: &[u8]) -> Option<ArtifactInspection> {
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

fn le_i32(data: &[u8], offset: usize) -> Option<i32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn bmp_compression_name(v: u32) -> &'static str {
    match v { 0 => "none (RGB)", 1 => "RLE8", 2 => "RLE4", 3 => "BITFIELDS", 4 => "JPEG", 5 => "PNG", _ => "other" }
}

fn format_bytes(n: u64) -> String {
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

fn inspect_ico(data: &[u8]) -> Option<ArtifactInspection> {
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

fn inspect_tiff(data: &[u8]) -> Option<ArtifactInspection> {
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

fn inspect_riff(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 12 || &data[..4] != b"RIFF" { return None; }
    match &data[8..12] {
        b"WAVE" => inspect_wav(data),
        b"AVI " => inspect_avi(data),
        _ => None,
    }
}

// ── WAV ────────────────────────────────────────────────────

fn inspect_wav(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 44 || &data[..4] != b"RIFF" || &data[8..12] != b"WAVE" { return None; }
    let file_size = le_u32(data, 4)?;
    let audio_format = le_u16(data, 20)?;
    let channels = le_u16(data, 22)?;
    let sample_rate = le_u32(data, 24)?;
    let byte_rate = le_u32(data, 28)?;
    let block_align = le_u16(data, 32)?;
    let bits_per_sample = le_u16(data, 34)?;

    // Find data chunk size
    let mut data_size = 0u32;
    let mut offset = 36usize;
    while offset + 8 <= data.len() {
        let chunk_id = &data[offset..offset + 4];
        let chunk_size = le_u32(data, offset + 4).unwrap_or(0);
        if chunk_id == b"data" {
            data_size = chunk_size;
            break;
        }
        offset += 8 + chunk_size as usize;
    }

    let duration_secs = if sample_rate > 0 && channels > 0 {
        data_size as f64 / (sample_rate as f64 * channels as f64 * (bits_per_sample as f64 / 8.0))
    } else { 0.0 };

    let mut details = BTreeMap::new();
    details.insert("file_size".to_string(), format_bytes(file_size as u64));
    details.insert("audio_format".to_string(), wav_format_name(audio_format).to_string());
    details.insert("channels".to_string(), channels.to_string());
    details.insert("sample_rate".to_string(), format!("{} Hz", sample_rate));
    details.insert("byte_rate".to_string(), format!("{} B/s", byte_rate));
    details.insert("block_align".to_string(), block_align.to_string());
    details.insert("bits_per_sample".to_string(), bits_per_sample.to_string());
    details.insert("data_size".to_string(), format_bytes(data_size as u64));
    details.insert("duration".to_string(), format!("{:.2}s", duration_secs));

    Some(ArtifactInspection {
        format: "WAV".to_string(),
        summary: format!("WAV {} channel {} {:.1}s", channels, wav_format_name(audio_format), duration_secs),
        details,
    })
}

fn wav_format_name(f: u16) -> &'static str {
    match f { 1 => "PCM", 3 => "IEEE_FLOAT", 6 => "ALAW", 7 => "ULAW", 0xFFFE => "EXTENSIBLE", _ => "other" }
}

// ── AVI ────────────────────────────────────────────────────

fn inspect_avi(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 12 || &data[..4] != b"RIFF" || &data[8..12] != b"AVI " { return None; }
    let file_size = le_u32(data, 4)?;
    let mut details = BTreeMap::new();
    details.insert("file_size".to_string(), format_bytes(file_size as u64));

    // Parse main AVI header
    let mut offset = 12usize;
    while offset + 8 <= data.len() {
        let chunk_id = &data[offset..offset + 4];
        let chunk_size = le_u32(data, offset + 4).unwrap_or(0) as usize;
        let chunk_data = offset + 8;
        if chunk_id == b"avih" && chunk_size >= 56 {
            let micro_sec_per_frame = le_u32(data, chunk_data).unwrap_or(0);
            let max_bytes_per_sec = le_u32(data, chunk_data + 4).unwrap_or(0);
            let total_frames = le_u32(data, chunk_data + 16).unwrap_or(0);
            let streams = le_u32(data, chunk_data + 24).unwrap_or(0);
            let width = le_u32(data, chunk_data + 32).unwrap_or(0);
            let height = le_u32(data, chunk_data + 36).unwrap_or(0);
            if width > 0 { details.insert("width".to_string(), width.to_string()); }
            if height > 0 { details.insert("height".to_string(), height.to_string()); }
            details.insert("total_frames".to_string(), total_frames.to_string());
            details.insert("streams".to_string(), streams.to_string());
            details.insert("frame_rate".to_string(), if micro_sec_per_frame > 0 {
                format!("{:.2} fps", 1_000_000.0 / micro_sec_per_frame as f64)
            } else { "unknown".to_string() });
            if max_bytes_per_sec > 0 {
                details.insert("data_rate".to_string(), format_bytes(max_bytes_per_sec as u64).replace("B", "B/s"));
            }
            break;
        }
        offset += 8 + chunk_size + (chunk_size % 2);
    }

    Some(ArtifactInspection {
        format: "AVI".to_string(),
        summary: details.get("width").and_then(|w| details.get("height").map(|h| format!("AVI video {}x{}", w, h)))
            .unwrap_or_else(|| "AVI video".to_string()),
        details,
    })
}

// ── MP4 / QuickTime ────────────────────────────────────────

fn inspect_mp4(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 12 { return None; }
    // Check ftyp box
    let ftyp_len = be_u32(data, 0)?;
    if ftyp_len < 8 { return None; }
    if &data[4..8] != b"ftyp" && &data[4..8] != b"moov" { return None; }

    let mut details = BTreeMap::new();

    // Parse ftyp box for brands
    if &data[4..8] == b"ftyp" && ftyp_len as usize <= data.len() {
        let major_brand = &data[8..12];
        if major_brand.len() == 4 {
            details.insert("major_brand".to_string(), String::from_utf8_lossy(major_brand).to_string());
        }
        let mut minor_version = 0u32;
        if ftyp_len >= 16 {
            minor_version = be_u32(data, 12)?;
        }
        details.insert("minor_version".to_string(), minor_version.to_string());
        let mut brands = Vec::new();
        let mut brand_off = 16usize;
        while brand_off + 4 <= data.len() as usize && brand_off < ftyp_len as usize {
            brands.push(String::from_utf8_lossy(&data[brand_off..brand_off + 4]).to_string());
            brand_off += 4;
        }
        if !brands.is_empty() {
            details.insert("compatible_brands".to_string(), brands.join(", "));
        }
    }

    // Walk boxes for moov/mvhd (duration) and video dimensions
    walk_mp4_boxes(data, 0, data.len(), &mut details);

    let summary = if let (Some(w), Some(h)) = (details.get("width"), details.get("height")) {
        format!("MP4 video {}x{}", w, h)
    } else if let Some(brand) = details.get("major_brand") {
        format!("MP4 container ({})", brand)
    } else {
        "MP4 container".to_string()
    };

    Some(ArtifactInspection { format: "MP4".to_string(), summary, details })
}

fn walk_mp4_boxes(data: &[u8], start: usize, _end: usize, details: &mut BTreeMap<String, String>) {
    let mut offset = start;
    while offset + 8 <= data.len() {
        let box_len = be_u32(data, offset).unwrap_or(0) as usize;
        if box_len < 8 { break; }
        if offset + box_len > data.len() { break; }
        let box_type = &data[offset + 4..offset + 8];
        let content = offset + 8;
        let content_end = offset + box_len;

        match box_type {
            b"moov" => {
                let mut duration_shown = false;
                let mut sub = offset + 8;
                while sub + 8 <= offset + box_len && sub + 8 <= data.len() {
                    let sub_len = be_u32(data, sub).unwrap_or(0) as usize;
                    if sub_len < 8 { break; }
                    if sub + sub_len > data.len() { break; }
                    let sub_type = &data[sub + 4..sub + 8];
                    if sub_type == b"mvhd" && sub_len >= 16 {
                        let version = data[sub + 8];
                        let (scale, duration) = if version == 1 && sub_len >= 32 {
                            (be_u32(data, sub + 20).unwrap_or(0), be_u64(data, sub + 24).unwrap_or(0))
                        } else if sub_len >= 20 {
                            (be_u32(data, sub + 12).unwrap_or(0), be_u32(data, sub + 16).unwrap_or(0) as u64)
                        } else { (0, 0) };
                        if !duration_shown && scale > 0 {
                            details.insert("duration".to_string(), format!("{:.1}s", duration as f64 / scale as f64));
                            duration_shown = true;
                        }
                    }
                    sub += sub_len;
                }
            }
            b"trak" => {
                // Walk track for video dimensions
                let mut sub = content;
                while sub + 8 <= content_end && sub + 8 <= data.len() {
                    let sub_len = be_u32(data, sub).unwrap_or(0) as usize;
                    if sub_len < 8 || sub + sub_len > data.len() { break; }
                    let sub_type = &data[sub + 4..sub + 8];
                    if sub_type == b"tkhd" && sub_len >= 20 {
                        let version = data[sub + 8];
                        let (_tx, _ty, tw, th) = if version == 1 && sub_len >= 104 {
                            let w_fixed = be_u32(data, sub + 96).unwrap_or(0);
                            let h_fixed = be_u32(data, sub + 100).unwrap_or(0);
                            (0u16, 0u16, w_fixed >> 16, h_fixed >> 16)
                        } else if sub_len >= 84 {
                            let w_fixed = be_u32(data, sub + 76).unwrap_or(0);
                            let h_fixed = be_u32(data, sub + 80).unwrap_or(0);
                            (0u16, 0u16, w_fixed >> 16, h_fixed >> 16)
                        } else { (0, 0, 0, 0) };
                        if tw > 0 && !details.contains_key("width") {
                            details.insert("width".to_string(), tw.to_string());
                            details.insert("height".to_string(), th.to_string());
                        }
                    }
                    sub += sub_len;
                }
            }
            b"mdat" => {
                // just skip large media data
            }
            b"udta" => {
                // metadata - skip for now
            }
            b"meta" => {
                // metadata - skip for now
            }
            b"\xA9too" | b"\xA9day" | b"\xA9nam" | b"\xA9ART" | b"\xA9alb" | b"\xA9cmt" | b"\xA9gen" => {
                // QuickTime metadata
                if content + 4 <= content_end && content + 4 <= data.len() {
                    let data_len = be_u32(data, offset + 4).unwrap_or(0) as usize;
                    if data_len > 16 && content + 16 <= content_end {
                        let val = String::from_utf8_lossy(&data[content + 16..content_end]).trim().to_string();
                        if !val.is_empty() {
                            let key = match box_type {
                                b"\xA9too" => "tool",
                                b"\xA9day" => "creation_date",
                                b"\xA9nam" => "title",
                                b"\xA9ART" => "artist",
                                b"\xA9alb" => "album",
                                b"\xA9cmt" => "comment",
                                b"\xA9gen" => "genre",
                                _ => "unknown",
                            };
                            details.insert(key.to_string(), val);
                        }
                    }
                }
            }
            _ => {
                // Recurse into containers
                if box_len > 8 {
                    walk_mp4_boxes(data, offset + 8, offset + box_len, details);
                }
            }
        }
        offset += box_len;
    }
}

// ── ID3 / MP3 ──────────────────────────────────────────────

fn inspect_id3(data: &[u8]) -> Option<ArtifactInspection> {
    // Check for ID3v2 or MPEG sync
    let mut details = BTreeMap::new();

    if data.len() >= 10 && &data[..3] == b"ID3" {
        let major = data[3];
        let revision = data[4];
        let flags = data[5];
        let size = id3_decoded_size(&data[6..10]);
        details.insert("id3_version".to_string(), format!("2.{}.{}", major, revision));
        details.insert("flags".to_string(), format!("0x{:02X}", flags));
        details.insert("tag_size".to_string(), format_bytes(size as u64));

        let mut offset = 10usize;
        let tag_end = 10 + size;
        while offset + 10 <= tag_end.min(data.len()) {
            let frame_id = &data[offset..offset + 4];
            let frame_size = id3_decoded_size2(&data[offset + 4..offset + 8]);
            if frame_id.iter().all(|&b| b == 0) { break; }
            if frame_size == 0 { break; }
            offset += 10;
            if offset + frame_size > tag_end.min(data.len()) { break; }
            let frame_data = &data[offset..offset + frame_size];
            let key = match frame_id {
                b"TIT2" => "title",
                b"TPE1" => "artist",
                b"TALB" => "album",
                b"TRCK" => "track",
                b"TYER" | b"TDRC" => "year",
                b"COMM" => "comment",
                b"TCON" => "genre",
                b"TENC" => "encoder",
                b"TSSE" => "software",
                b"TLEN" => "duration_ms",
                b"TBPM" => "bpm",
                _ => "",
            };
            if !key.is_empty() {
                // Skip encoding byte
                let encoding = if frame_data.is_empty() { 0 } else { frame_data[0] };
                let skip = if encoding == 1 || encoding == 2 { 1 } else { 0 };
                let val = if skip < frame_data.len() {
                    let raw = &frame_data[skip..];
                    if encoding == 1 || encoding == 2 {
                        // UTF-16
                        if raw.len() >= 2 {
                            let bom = &raw[..2];
                            let text = if bom == b"\xFF\xFE" {
                                String::from_utf16_lossy(&raw[2..].chunks(2).filter_map(|c| {
                                    if c.len() == 2 { Some(u16::from_le_bytes([c[0], c[1]])) } else { None }
                                }).collect::<Vec<u16>>())
                            } else {
                                String::from_utf8_lossy(raw).to_string()
                            };
                            text.trim_matches('\0').to_string()
                        } else { String::new() }
                    } else {
                        String::from_utf8_lossy(raw).trim_matches('\0').to_string()
                    }
                } else { String::new() };
                if !val.is_empty() {
                    details.insert(key.to_string(), val);
                }
            }
            offset += frame_size;
        }
    }

    // Check for ID3v1 at end
    if data.len() >= 128 && &data[data.len() - 128..data.len() - 125] == b"TAG" {
        let end = data.len();
        let title = String::from_utf8_lossy(&data[end - 125..end - 95]).trim().to_string();
        let artist = String::from_utf8_lossy(&data[end - 95..end - 65]).trim().to_string();
        let album = String::from_utf8_lossy(&data[end - 65..end - 35]).trim().to_string();
        let year = String::from_utf8_lossy(&data[end - 35..end - 31]).trim().to_string();
        let _comment_raw = &data[end - 31..end - 1];
        let _track = data[end - 1];
        let _genre_byte = data[end - 1];
        if !details.contains_key("id3_version") {
            details.insert("id3_version".to_string(), "1.x".to_string());
        }
        if !title.is_empty() { details.entry("title".to_string()).or_insert(title); }
        if !artist.is_empty() { details.entry("artist".to_string()).or_insert(artist); }
        if !album.is_empty() { details.entry("album".to_string()).or_insert(album); }
        if !year.is_empty() { details.entry("year".to_string()).or_insert(year); }
    }

    // If no ID3 tags, try to detect MPEG frames for basic info
    if details.is_empty() && data.len() > 4 {
        if let Some(hdr) = find_mpeg_sync(data) {
            let bitrate = mpeg_bitrate(hdr);
            let sample_rate = mpeg_sample_rate(hdr);
            let layer = mpeg_layer(hdr);
            details.insert("format".to_string(), "MPEG".to_string());
            if bitrate > 0 { details.insert("bitrate".to_string(), format!("{} kbps", bitrate)); }
            if sample_rate > 0 { details.insert("sample_rate".to_string(), format!("{} Hz", sample_rate)); }
            details.insert("layer".to_string(), format!("Layer {}", layer));
        } else {
            return None;
        }
    }

    if details.is_empty() { return None; }

    let summary = details.get("title")
        .or(details.get("artist"))
        .map(|t| format!("Audio: {}", t))
        .unwrap_or_else(|| "Audio file".to_string());

    Some(ArtifactInspection { format: "MP3".to_string(), summary, details })
}

fn id3_decoded_size(bytes: &[u8]) -> usize {
    if bytes.len() < 4 { return 0; }
    ((bytes[0] as usize) << 21) | ((bytes[1] as usize) << 14) | ((bytes[2] as usize) << 7) | (bytes[3] as usize)
}

fn id3_decoded_size2(bytes: &[u8]) -> usize {
    // For ID3v2.3 frame sizes are 4 bytes big-endian, for 2.4 they're synchsafe
    if bytes.len() < 4 { return 0; }
    (bytes[0] as usize) << 24 | (bytes[1] as usize) << 16 | (bytes[2] as usize) << 8 | (bytes[3] as usize)
}

fn find_mpeg_sync(data: &[u8]) -> Option<u32> {
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0xFF && (data[i + 1] & 0xE0) == 0xE0 {
            let hdr = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            if (hdr >> 19) & 0x03 != 0x01 && (hdr >> 17) & 0x03 != 0 { // valid layer
                return Some(hdr);
            }
        }
    }
    None
}

fn mpeg_bitrate(hdr: u32) -> u32 {
    let idx = (hdr >> 12) & 0x0F;
    match ((hdr >> 19) & 0x03, (hdr >> 17) & 0x03) {
        (3, 3) => [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0][idx as usize],
        (3, 2) => [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0][idx as usize],
        (3, 1) => [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0][idx as usize],
        _ => 0,
    }
}

fn mpeg_sample_rate(hdr: u32) -> u32 {
    let idx = (hdr >> 10) & 0x03;
    match (hdr >> 19) & 0x03 {
        3 => [44100, 48000, 32000, 0][idx as usize],
        2 => [22050, 24000, 16000, 0][idx as usize],
        1 => [11025, 12000, 8000, 0][idx as usize],
        _ => 0,
    }
}

fn mpeg_layer(hdr: u32) -> u32 {
    match (hdr >> 17) & 0x03 {
        3 => 1, 2 => 2, 1 => 3, _ => 0,
    }
}

// ── FLAC ───────────────────────────────────────────────────

fn inspect_flac(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 42 || &data[..4] != b"fLaC" { return None; }
    let mut details = BTreeMap::new();
    let mut offset = 4usize;

    while offset + 4 <= data.len() {
        let is_last = (data[offset] & 0x80) != 0;
        let block_type = data[offset] & 0x7F;
        let block_len = ((data[offset + 1] as usize) << 16) | ((data[offset + 2] as usize) << 8) | (data[offset + 3] as usize);
        offset += 4;
        if offset + block_len > data.len() { break; }

        let block_data = &data[offset..offset + block_len];
        match block_type {
            0 => {
                // STREAMINFO
                if block_len >= 34 {
                    let min_block = be_u16(block_data, 0).unwrap_or(0) as u32;
                    let max_block = be_u16(block_data, 2).unwrap_or(0) as u32;
                    let min_frame = be_u24(block_data, 4).unwrap_or(0);
                    let max_frame = be_u24(block_data, 7).unwrap_or(0);
                    let sample_rate = (be_u32(block_data, 10).unwrap_or(0) >> 12) as u32;
                    let channels = ((be_u32(block_data, 10).unwrap_or(0) >> 9) & 0x07) + 1;
                    let bps = ((be_u32(block_data, 10).unwrap_or(0) >> 4) & 0x1F) + 1;
                    let total_samples = (be_u64(block_data, 10).unwrap_or(0) >> 4) & 0x0F_FFFF_FFFF_FFFF;
                    details.insert("min_block_size".to_string(), min_block.to_string());
                    details.insert("max_block_size".to_string(), max_block.to_string());
                    details.insert("min_frame_size".to_string(), min_frame.to_string());
                    details.insert("max_frame_size".to_string(), max_frame.to_string());
                    details.insert("sample_rate".to_string(), format!("{} Hz", sample_rate));
                    details.insert("channels".to_string(), channels.to_string());
                    details.insert("bits_per_sample".to_string(), bps.to_string());
                    if sample_rate > 0 {
                        let dur_secs = total_samples as f64 / sample_rate as f64;
                        details.insert("duration".to_string(), format!("{:.1}s", dur_secs));
                    }
                }
            }
            1 => {
                // PADDING
            }
            3 => {
                // SEEKTABLE
            }
            4 => {
                // VORBIS_COMMENT
                let raw = String::from_utf8_lossy(block_data);
                for line in raw.split('\0') {
                    if let Some(eq) = line.find('=') {
                        let key = line[..eq].to_string().to_ascii_lowercase();
                        let val = line[eq + 1..].to_string();
                        if !key.is_empty() && !val.is_empty() {
                            details.insert(format!("vorbis:{}", key), val);
                        }
                    }
                }
            }
            _ => {}
        }

        if is_last { break; }
        offset += block_len;
    }

    if details.is_empty() { return None; }

    let summary = details.get("vorbis:title")
        .map(|t| format!("FLAC: {}", t))
        .unwrap_or_else(|| "FLAC audio".to_string());

    Some(ArtifactInspection { format: "FLAC".to_string(), summary, details })
}

fn be_u24(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 3)?;
    Some((bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32)
}

// ── Existing formats ───────────────────────────────────────

fn inspect_pdf(data: &[u8]) -> Option<ArtifactInspection> {
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

fn inspect_zip(data: &[u8]) -> Option<ArtifactInspection> {
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

fn zip_method_name(method: u16) -> &'static str {
    match method {
        0 => "stored", 1 => "shrunk", 8 => "deflate", 12 => "bzip2",
        14 => "lzma", 93 => "zstd", _ => "other",
    }
}

fn inspect_elf(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 0x34 || !data.starts_with(b"\x7FELF") { return None; }
    let class = *data.get(4)?;
    let little_endian = match data.get(5).copied()? { 1 => true, 2 => false, _ => return None };
    let elf_class = match class { 1 => "32-bit", 2 => "64-bit", _ => return None };
    let endian = if little_endian { "LSB" } else { "MSB" };
    let elf_type = read_u16(data, 16, little_endian)?;
    let machine = read_u16(data, 18, little_endian)?;
    let entry_point = if class == 1 { read_u32(data, 24, little_endian)? as u64 } else { read_u64(data, 24, little_endian)? };
    let program_headers = if class == 1 { read_u16(data, 44, little_endian)? } else { read_u16(data, 56, little_endian)? };
    let section_headers = if class == 1 { read_u16(data, 48, little_endian)? } else { read_u16(data, 60, little_endian)? };

    // Read section header string table for section names
    let shstrndx = if class == 1 { read_u16(data, 50, little_endian)? as usize } else { read_u16(data, 62, little_endian)? as usize };
    let shdr_size = if class == 1 { 40 } else { 64 };
    let shdr_offset = if class == 1 { read_u32(data, 32, little_endian)? as usize } else { read_u64(data, 40, little_endian)? as usize };
    let shstrtab_off = shdr_offset.checked_add(shstrndx.checked_mul(shdr_size)?)?;
    let sh_name_offset = if class == 1 { read_u32(data, shstrtab_off + 16, little_endian)? as usize }
                                  else { read_u64(data, shstrtab_off + 24, little_endian)? as usize };
    let _sh_name_size = if class == 1 { read_u32(data, shstrtab_off + 20, little_endian)? as usize }
                                  else { read_u64(data, shstrtab_off + 32, little_endian)? as usize };

    let max_sh_off = shdr_offset.saturating_add((section_headers as usize).saturating_mul(shdr_size));
    let mut section_names = Vec::new();
    if max_sh_off <= data.len() && section_headers < 256 {
        for i in 0..section_headers as usize {
            let sh_off = shdr_offset.saturating_add(i.saturating_mul(shdr_size));
            if sh_off + 8 > data.len() { break; }
            if let Some(name_idx) = read_u32(data, sh_off, little_endian) {
                let name_idx = name_idx as usize;
                if sh_name_offset.saturating_add(name_idx) < data.len() {
                    let end = data[sh_name_offset + name_idx..].iter().position(|&b| b == 0).unwrap_or(0);
                    let name = String::from_utf8_lossy(&data[sh_name_offset + name_idx..sh_name_offset + name_idx + end]).to_string();
                    if !name.is_empty() { section_names.push(name); }
                }
            }
        }
    }

    let mut details = BTreeMap::new();
    details.insert("class".to_string(), elf_class.to_string());
    details.insert("endianness".to_string(), endian.to_string());
    details.insert("type".to_string(), elf_type_name(elf_type).to_string());
    details.insert("machine".to_string(), elf_machine_name(machine).to_string());
    details.insert("entry_point".to_string(), format_hex(entry_point));
    details.insert("program_headers".to_string(), program_headers.to_string());
    details.insert("section_headers".to_string(), section_headers.to_string());
    if !section_names.is_empty() {
        details.insert("sections".to_string(), section_names.join(", "));
    }

    Some(ArtifactInspection {
        format: "ELF".to_string(),
        summary: format!("ELF {} {} {} for {}", elf_class, endian, elf_type_name(elf_type), elf_machine_name(machine)),
        details,
    })
}

fn elf_type_name(value: u16) -> &'static str {
    match value { 1 => "relocatable", 2 => "executable", 3 => "shared object", 4 => "core", _ => "unknown" }
}

fn elf_machine_name(value: u16) -> &'static str {
    match value {
        0x03 => "x86", 0x08 => "MIPS", 0x14 => "PowerPC", 0x28 => "ARM",
        0x3E => "x86-64", 0xB7 => "AArch64", 0xF3 => "RISC-V", _ => "unknown",
    }
}

fn inspect_pe(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 0x40 || !data.starts_with(b"MZ") { return None; }
    let pe_offset = le_u32(data, 0x3c)? as usize;
    if pe_offset + 24 > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\0\0" { return None; }
    let machine = le_u16(data, pe_offset + 4)?;
    let sections = le_u16(data, pe_offset + 6)?;
    let timestamp = le_u32(data, pe_offset + 8)?;
    let size_optional_header = le_u16(data, pe_offset + 20)? as usize;
    let characteristics = le_u16(data, pe_offset + 22)?;
    let optional_offset = pe_offset + 24;
    if optional_offset + size_optional_header > data.len() { return None; }
    let magic = le_u16(data, optional_offset)?;
    let (pe_class, subsystem) = match magic {
        0x10B => ("PE32", le_u16(data, optional_offset + 68)?),
        0x20B => ("PE32+", le_u16(data, optional_offset + 88)?),
        _ => return None,
    };
    let entry_point = le_u32(data, optional_offset + 16)?;
    let image_base = match magic { 0x10B => le_u32(data, optional_offset + 28)? as u64, _ => le_u64(data, optional_offset + 24)? };
    let kind = if characteristics & 0x2000 != 0 { "DLL" } else { "Executable" };

    // Read section table for names
    let section_offset = optional_offset + size_optional_header;
    let mut section_names = Vec::new();
    for i in 0..sections as usize {
        let s_off = section_offset + i * 40;
        if s_off + 40 > data.len() { break; }
        let name_raw = &data[s_off..s_off + 8];
        let name = String::from_utf8_lossy(name_raw).trim_end_matches('\0').to_string();
        if !name.is_empty() { section_names.push(name); }
    }

    let mut details = BTreeMap::new();
    details.insert("class".to_string(), pe_class.to_string());
    details.insert("kind".to_string(), kind.to_string());
    details.insert("machine".to_string(), pe_machine_name(machine).to_string());
    details.insert("sections".to_string(), sections.to_string());
    details.insert("timestamp_unix".to_string(), timestamp.to_string());
    details.insert("entry_point".to_string(), format_hex(entry_point as u64));
    details.insert("image_base".to_string(), format_hex(image_base));
    details.insert("subsystem".to_string(), pe_subsystem_name(subsystem).to_string());
    if !section_names.is_empty() {
        details.insert("section_names".to_string(), section_names.join(", "));
    }
    Some(ArtifactInspection {
        format: "PE".to_string(),
        summary: format!("{} {} for {} with {} section{}", pe_class, kind.to_lowercase(), pe_machine_name(machine), sections, if sections == 1 { "" } else { "s" }),
        details,
    })
}

fn pe_machine_name(value: u16) -> &'static str {
    match value { 0x014C => "x86", 0x8664 => "x86-64", 0x01C0 => "ARM", 0xAA64 => "ARM64", _ => "unknown" }
}

fn pe_subsystem_name(value: u16) -> &'static str {
    match value {
        1 => "native", 2 => "windows-gui", 3 => "windows-cui", 5 => "os2-cui",
        7 => "posix-cui", 9 => "windows-ce-gui", 10 => "efi-application",
        11 => "efi-boot-service", 12 => "efi-runtime", 14 => "xbox",
        16 => "windows-boot-application", _ => "unknown",
    }
}

fn inspect_macho(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 28 { return None; }
    let (class, little_endian) = match &data[..4] {
        [0xFE, 0xED, 0xFA, 0xCE] => ("32-bit", false),
        [0xCE, 0xFA, 0xED, 0xFE] => ("32-bit", true),
        [0xFE, 0xED, 0xFA, 0xCF] => ("64-bit", false),
        [0xCF, 0xFA, 0xED, 0xFE] => ("64-bit", true),
        _ => return None,
    };
    let cpu_type = read_u32(data, 4, little_endian)?;
    let file_type = read_u32(data, 12, little_endian)?;
    let load_commands = read_u32(data, 16, little_endian)?;
    let command_bytes = read_u32(data, 20, little_endian)?;

    let mut details = BTreeMap::new();
    details.insert("class".to_string(), class.to_string());
    details.insert("endianness".to_string(), (if little_endian { "little" } else { "big" }).to_string());
    details.insert("cpu".to_string(), macho_cpu_name(cpu_type).to_string());
    details.insert("file_type".to_string(), macho_file_type_name(file_type).to_string());
    details.insert("load_commands".to_string(), load_commands.to_string());
    details.insert("load_command_bytes".to_string(), command_bytes.to_string());
    Some(ArtifactInspection {
        format: "Mach-O".to_string(),
        summary: format!("Mach-O {} {} with {} load command{}", class, macho_cpu_name(cpu_type), load_commands, if load_commands == 1 { "" } else { "s" }),
        details,
    })
}

fn macho_cpu_name(value: u32) -> &'static str {
    match value { 7 => "x86", 0x0100_0007 => "x86-64", 12 => "arm", 0x0100_000C => "arm64", _ => "unknown" }
}

fn macho_file_type_name(value: u32) -> &'static str {
    match value {
        0x1 => "object", 0x2 => "executable", 0x3 => "fixed-vm-library", 0x4 => "core",
        0x5 => "preloaded-executable", 0x6 => "dylib", 0x7 => "dylinker", 0x8 => "bundle",
        0xA => "dSYM", _ => "unknown",
    }
}

fn inspect_sqlite(data: &[u8]) -> Option<ArtifactInspection> {
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

fn sqlite_journal_name(value: u8) -> &'static str {
    match value { 1 => "rollback", 2 => "wal", _ => "unknown" }
}

fn sqlite_encoding_name(value: u32) -> &'static str {
    match value { 1 => "utf-8", 2 => "utf-16le", 3 => "utf-16be", _ => "unknown" }
}

fn inspect_gzip(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 10 || &data[..3] != b"\x1F\x8B\x08" { return None; }
    let flags = *data.get(3)?;
    let mtime = le_u32(data, 4)?;
    let xfl = *data.get(8)?;
    let os = *data.get(9)?;
    let mut cursor = 10usize;

    if flags & 0x04 != 0 {
        let xlen = le_u16(data, cursor)? as usize;
        cursor = cursor.checked_add(2 + xlen)?;
    }
    let original_name = if flags & 0x08 != 0 {
        let end = data[cursor..].iter().position(|&byte| byte == 0).map(|idx| cursor + idx)?;
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

fn gzip_os_name(value: u8) -> &'static str {
    match value { 0 => "fat", 3 => "unix", 7 => "macintosh", 11 => "ntfs", 255 => "unknown", _ => "other" }
}

// ── OOXML (Office Open XML) ─────────────────────────────────

fn inspect_ooxml(data: &[u8]) -> Option<ArtifactInspection> {
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

fn extract_ooxml_metadata(xml: &str, details: &mut BTreeMap<String, String>, _path: &str) {
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

fn inspect_ole(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 8 || &data[..8] != &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] { return None; }
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

fn inspect_rar(data: &[u8]) -> Option<ArtifactInspection> {
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

fn inspect_7z(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 32 || &data[..6] != &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] { return None; }
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
mod tests {
    use super::*;
    use crate::detectors::stego::identify_file_signature;

    #[test]
    fn inspects_png_dimensions() {
        let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x01\x90\x00\x00\x00\xc8\x08\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00IEND\xAE\x42\x60\x82";
        let inspection = inspect_data(png).unwrap();
        assert_eq!(inspection.format, "PNG");
        assert_eq!(inspection.details.get("width").unwrap(), "400");
        assert_eq!(inspection.details.get("height").unwrap(), "200");
    }

    #[test]
    fn inspects_elf_headers() {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7FELF"); elf[4] = 2; elf[5] = 1;
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        elf[56..58].copy_from_slice(&9u16.to_le_bytes());
        elf[60..62].copy_from_slice(&31u16.to_le_bytes());
        // Set e_shstrndx = SHN_UNDO (0) to skip section name resolution
        let signature = identify_file_signature(&elf).unwrap();
        let inspection = inspect_artifact(&elf, signature).unwrap();
        assert_eq!(inspection.format, "ELF");
        assert_eq!(inspection.details.get("machine").unwrap(), "x86-64");
        assert_eq!(inspection.details.get("entry_point").unwrap(), "0x401000");
    }

    #[test]
    fn inspects_zip_central_directory() {
        let name = b"hello.txt";
        let mut zip = Vec::new();
        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(name);
        let central_offset = zip.len() as u32;
        zip.extend_from_slice(b"PK\x01\x02");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(name);
        let central_size = zip.len() as u32 - central_offset;
        zip.extend_from_slice(b"PK\x05\x06");
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&central_size.to_le_bytes());
        zip.extend_from_slice(&central_offset.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        let inspection = inspect_data(&zip).unwrap();
        assert_eq!(inspection.format, "ZIP");
        assert_eq!(inspection.details.get("entries").unwrap(), "1");
        assert!(inspection.details.get("sample_entries").unwrap().contains("hello.txt"));
    }

    #[test]
    fn inspects_gif_metadata() {
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[0x10, 0x00, 0x08, 0x00]); // 16x8
        gif.extend_from_slice(&[0x00, 0x00, 0x00]); // packed, bg, aspect
        gif.push(0x3B); // trailer
        let inspection = inspect_data(&gif).unwrap();
        assert_eq!(inspection.format, "GIF");
        assert_eq!(inspection.details.get("width").unwrap(), "16");
        assert_eq!(inspection.details.get("height").unwrap(), "8");
    }

    #[test]
    fn inspects_bmp_headers() {
        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&[0x46, 0x00, 0x00, 0x00]); // file size 70 @2
        bmp.extend_from_slice(&[0x00, 0x00]); // reserved1 @6
        bmp.extend_from_slice(&[0x00, 0x00]); // reserved2 @8
        bmp.extend_from_slice(&[0x36, 0x00, 0x00, 0x00]); // data offset 54 @10
        bmp.extend_from_slice(&[0x28, 0x00, 0x00, 0x00]); // header size 40 @14
        bmp.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // width 4 @18
        bmp.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // height 3 @22
        bmp.extend_from_slice(&[0x01, 0x00]); // planes @26
        bmp.extend_from_slice(&[0x18, 0x00]); // bpp 24 @28
        bmp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // compression @30
        let inspection = inspect_data(&bmp).unwrap();
        assert_eq!(inspection.format, "BMP");
        assert_eq!(inspection.details.get("width").unwrap(), "4");
        assert_eq!(inspection.details.get("height").unwrap(), "3");
    }

    #[test]
    fn inspects_wav_header() {
        let mut wav = b"RIFF".to_vec();
        wav.extend_from_slice(&[0x24, 0x00, 0x00, 0x00]); // file size 36
        wav.extend_from_slice(b"WAVE");
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // chunk size 16
        wav.extend_from_slice(&[0x01, 0x00]); // PCM
        wav.extend_from_slice(&[0x01, 0x00]); // mono
        wav.extend_from_slice(&[0x44, 0xAC, 0x00, 0x00]); // 44100 Hz
        wav.extend_from_slice(&[0x88, 0x58, 0x01, 0x00]); // byte rate
        wav.extend_from_slice(&[0x02, 0x00]); // block align
        wav.extend_from_slice(&[0x10, 0x00]); // 16-bit
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // data size
        let inspection = inspect_data(&wav).unwrap();
        assert_eq!(inspection.format, "WAV");
        assert_eq!(inspection.details.get("sample_rate").unwrap(), "44100 Hz");
        assert_eq!(inspection.details.get("channels").unwrap(), "1");
    }

    #[test]
    fn inspects_ico_headers() {
        let mut ico = b"\0\0\x01\0".to_vec();
        ico.extend_from_slice(&[0x01, 0x00]); // 1 icon
        ico.extend_from_slice(&[0x10, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // 16x16 entry
        let inspection = inspect_data(&ico).unwrap();
        assert_eq!(inspection.format, "ICO");
        assert_eq!(inspection.details.get("icon_count").unwrap(), "1");
    }

    #[test]
    fn inspects_rar_archive() {
        let rar = b"Rar!\x1A\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let inspection = inspect_data(rar).unwrap();
        assert_eq!(inspection.format, "RAR");
        assert_eq!(inspection.details.get("format_version").unwrap(), "4.x");
    }

    #[test]
    fn inspects_7z_archive() {
        let mut sz7 = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
        sz7.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
        sz7.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        sz7.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let inspection = inspect_data(&sz7).unwrap();
        assert_eq!(inspection.format, "7z");
    }

    #[test]
    fn inspects_ole_compound_document() {
        let mut ole: Vec<u8> = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        // Need enough room for version and other metadata
        ole.extend_from_slice(&[0x00u8; 32]);
        ole[24..26].copy_from_slice(&[0x3E, 0x00]); // minor version
        ole[26..28].copy_from_slice(&[0x03, 0x00]); // major version
        ole[28..30].copy_from_slice(&[0xFE, 0xFF]); // byte order (LE)
        ole[30] = 9; // sector shift (512 bytes)
        let inspection = inspect_data(&ole).unwrap();
        assert_eq!(inspection.format, "OLE");
        assert_eq!(inspection.details.get("version").unwrap(), "3.62");
        assert_eq!(inspection.details.get("byte_order").unwrap(), "little_endian");
    }
}
