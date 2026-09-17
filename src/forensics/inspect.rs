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

pub(crate) fn be_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn be_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn be_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

pub(crate) fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn le_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

pub(crate) fn read_u16(data: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    if little_endian { le_u16(data, offset) } else { be_u16(data, offset) }
}

pub(crate) fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    if little_endian { le_u32(data, offset) } else { be_u32(data, offset) }
}

pub(crate) fn read_u64(data: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
    if little_endian { le_u64(data, offset) } else { be_u64(data, offset) }
}

pub(crate) fn format_hex(value: u64) -> String {
    format!("0x{:X}", value)
}

pub(crate) fn plural_y(count: usize) -> &'static str {
    if count == 1 { "y" } else { "ies" }
}

pub(crate) fn find_zip_eocd(data: &[u8]) -> Option<usize> {
    let search_start = data.len().saturating_sub(22 + 65_535);
    data[search_start..]
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .map(|idx| search_start + idx)
}

// ── JPEG EXIF ──────────────────────────────────────────────

mod audio;
mod data;
mod docs;
mod exec;
mod images;
mod media;
mod raster;

pub(crate) use audio::*;
pub(crate) use data::*;
pub(crate) use docs::*;
pub(crate) use exec::*;
pub(crate) use images::*;
pub(crate) use media::*;
pub(crate) use raster::*;

#[cfg(test)]
#[path = "inspect/inspect_tests.rs"]
mod inspect_tests;
