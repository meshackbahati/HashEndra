use super::{be_u32, be_u64, format_bytes, le_u16, le_u32, ArtifactInspection};
use std::collections::BTreeMap;

pub(crate) fn inspect_riff(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 12 || &data[..4] != b"RIFF" { return None; }
    match &data[8..12] {
        b"WAVE" => inspect_wav(data),
        b"AVI " => inspect_avi(data),
        _ => None,
    }
}

// ── WAV ────────────────────────────────────────────────────

pub(crate) fn inspect_wav(data: &[u8]) -> Option<ArtifactInspection> {
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

pub(crate) fn wav_format_name(f: u16) -> &'static str {
    match f { 1 => "PCM", 3 => "IEEE_FLOAT", 6 => "ALAW", 7 => "ULAW", 0xFFFE => "EXTENSIBLE", _ => "other" }
}

// ── AVI ────────────────────────────────────────────────────

pub(crate) fn inspect_avi(data: &[u8]) -> Option<ArtifactInspection> {
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

pub(crate) fn inspect_mp4(data: &[u8]) -> Option<ArtifactInspection> {
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
        while brand_off + 4 <= data.len() && brand_off < ftyp_len as usize {
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

pub(crate) fn walk_mp4_boxes(data: &[u8], start: usize, _end: usize, details: &mut BTreeMap<String, String>) {
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
