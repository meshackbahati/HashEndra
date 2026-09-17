use super::{be_u16, be_u32, le_u16, read_u16, read_u32, ArtifactInspection};
use std::collections::BTreeMap;

pub(crate) fn inspect_jpeg_exif(data: &[u8]) -> Option<ArtifactInspection> {
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
                if !dims_shown
                    && let Some(density) = seg_data.get(0..5)
                        && density == b"JFIF\0" {
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
            0xC0..=0xC3
                // SOF0-3: dimensions
                if !dims_shown && seg_data.len() >= 5 => {
                    details.insert("width".to_string(), be_u16(seg_data, 3).unwrap_or(0).to_string());
                    details.insert("height".to_string(), be_u16(seg_data, 1).unwrap_or(0).to_string());
                    details.insert("precision".to_string(), format!("{}-bit", seg_data[0]));
                    let components = seg_data.get(4).copied().unwrap_or(0);
                    details.insert("components".to_string(), components.to_string());
                    details.insert("color_mode".to_string(),
                        match components { 1 => "grayscale", 3 => "ycbcr", 4 => "cmyk", _ => "other" }.to_string());
                    dims_shown = true;
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
                details.entry(key).or_insert(value);
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

pub(crate) fn parse_exif_ifd(data: &[u8]) -> Option<BTreeMap<String, String>> {
    // EXIF in TIFF structure: "Exif\0\0" + TIFF header
    if data.len() < 6 || &data[..6] != b"Exif\0\0" {
        return None;
    }
    let tiff = &data[6..];
    Some(parse_tiff_ifd(tiff))
}

pub(crate) fn parse_tiff_ifd(data: &[u8]) -> BTreeMap<String, String> {
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
            
            String::from_utf8_lossy(&data[value_off..value_off + count])
                .trim_end_matches('\0').to_string()
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

pub(crate) fn exif_tag_name(tag: u16) -> String {
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

pub(crate) fn inspect_png(data: &[u8]) -> Option<ArtifactInspection> {
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

pub(crate) fn decompress_zlib_text(data: &[u8]) -> Option<String> {
    use std::io::Read;
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut s = String::new();
    decoder.read_to_string(&mut s).ok()?;
    Some(s)
}

pub(crate) fn png_color_type_name(color_type: u8) -> &'static str {
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

pub(crate) fn inspect_gif(data: &[u8]) -> Option<ArtifactInspection> {
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
