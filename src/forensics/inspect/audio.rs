use super::{be_u16, be_u32, be_u64, format_bytes, ArtifactInspection};
use std::collections::BTreeMap;

pub(crate) fn inspect_id3(data: &[u8]) -> Option<ArtifactInspection> {
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
        {
            let hdr = find_mpeg_sync(data)?;
            let bitrate = mpeg_bitrate(hdr);
            let sample_rate = mpeg_sample_rate(hdr);
            let layer = mpeg_layer(hdr);
            details.insert("format".to_string(), "MPEG".to_string());
            if bitrate > 0 { details.insert("bitrate".to_string(), format!("{} kbps", bitrate)); }
            if sample_rate > 0 { details.insert("sample_rate".to_string(), format!("{} Hz", sample_rate)); }
            details.insert("layer".to_string(), format!("Layer {}", layer));
        }
    }

    if details.is_empty() { return None; }

    let summary = details.get("title")
        .or(details.get("artist"))
        .map(|t| format!("Audio: {}", t))
        .unwrap_or_else(|| "Audio file".to_string());

    Some(ArtifactInspection { format: "MP3".to_string(), summary, details })
}

pub(crate) fn id3_decoded_size(bytes: &[u8]) -> usize {
    if bytes.len() < 4 { return 0; }
    ((bytes[0] as usize) << 21) | ((bytes[1] as usize) << 14) | ((bytes[2] as usize) << 7) | (bytes[3] as usize)
}

pub(crate) fn id3_decoded_size2(bytes: &[u8]) -> usize {
    // For ID3v2.3 frame sizes are 4 bytes big-endian, for 2.4 they're synchsafe
    if bytes.len() < 4 { return 0; }
    (bytes[0] as usize) << 24 | (bytes[1] as usize) << 16 | (bytes[2] as usize) << 8 | (bytes[3] as usize)
}

pub(crate) fn find_mpeg_sync(data: &[u8]) -> Option<u32> {
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

pub(crate) fn mpeg_bitrate(hdr: u32) -> u32 {
    let idx = (hdr >> 12) & 0x0F;
    match ((hdr >> 19) & 0x03, (hdr >> 17) & 0x03) {
        (3, 3) => [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0][idx as usize],
        (3, 2) => [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0][idx as usize],
        (3, 1) => [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0][idx as usize],
        _ => 0,
    }
}

pub(crate) fn mpeg_sample_rate(hdr: u32) -> u32 {
    let idx = (hdr >> 10) & 0x03;
    match (hdr >> 19) & 0x03 {
        3 => [44100, 48000, 32000, 0][idx as usize],
        2 => [22050, 24000, 16000, 0][idx as usize],
        1 => [11025, 12000, 8000, 0][idx as usize],
        _ => 0,
    }
}

pub(crate) fn mpeg_layer(hdr: u32) -> u32 {
    match (hdr >> 17) & 0x03 {
        3 => 1, 2 => 2, 1 => 3, _ => 0,
    }
}

// ── FLAC ───────────────────────────────────────────────────

pub(crate) fn inspect_flac(data: &[u8]) -> Option<ArtifactInspection> {
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
                    let sample_rate = be_u32(block_data, 10).unwrap_or(0) >> 12;
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

pub(crate) fn be_u24(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 3)?;
    Some((bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32)
}

// ── Existing formats ───────────────────────────────────────
