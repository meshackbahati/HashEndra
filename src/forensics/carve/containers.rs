use super::config::{le_u16, le_u32};
use super::{sanitize_component, ContainerExpansion};
use std::io;
use std::path::{Path, PathBuf};

pub(crate) fn expand_container_members(
    data: &[u8],
    source_path: &Path,
    output_root: &Path,
    overwrite: bool,
) -> io::Result<ContainerExpansion> {
    if looks_like_zip(data) {
        return extract_zip_members(data, source_path, output_root, overwrite);
    }
    if looks_like_tar(data) {
        return extract_tar_members(data, source_path, output_root, overwrite);
    }
    Ok(ContainerExpansion::default())
}

pub(crate) fn looks_like_zip(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04") && find_zip_eocd(data).is_some()
}

pub(crate) fn looks_like_tar(data: &[u8]) -> bool {
    data.get(257..262).is_some_and(|magic| magic == b"ustar")
}

pub(crate) fn extract_zip_members(
    data: &[u8],
    source_path: &Path,
    output_root: &Path,
    overwrite: bool,
) -> io::Result<ContainerExpansion> {
    let Some(eocd_offset) = find_zip_eocd(data) else {
        return Ok(ContainerExpansion::default());
    };

    let total_entries = le_u16(data, eocd_offset + 10).unwrap_or(0) as usize;
    let central_offset = le_u32(data, eocd_offset + 16).unwrap_or(0) as usize;
    if total_entries == 0 || central_offset >= data.len() {
        return Ok(ContainerExpansion::default());
    }

    let container_dir = container_output_dir(output_root, source_path, "zip");
    std::fs::create_dir_all(&container_dir)?;

    let mut expansion = ContainerExpansion {
        expanded: 1,
        ..Default::default()
    };
    let mut cursor = central_offset;

    for _ in 0..total_entries {
        let Some(header) = data.get(cursor..cursor + 46) else {
            expansion.notes.push(format!(
                "ZIP central directory in {} ended unexpectedly",
                source_path.display()
            ));
            break;
        };
        if &header[..4] != b"PK\x01\x02" {
            expansion.notes.push(format!(
                "ZIP central directory entry was malformed in {}",
                source_path.display()
            ));
            break;
        }

        let method = le_u16(header, 10).unwrap_or(0);
        let compressed_size = le_u32(header, 20).unwrap_or(0) as usize;
        let name_len = le_u16(header, 28).unwrap_or(0) as usize;
        let extra_len = le_u16(header, 30).unwrap_or(0) as usize;
        let comment_len = le_u16(header, 32).unwrap_or(0) as usize;
        let local_offset = le_u32(header, 42).unwrap_or(0) as usize;
        let Some(name_bytes) = data.get(cursor + 46..cursor + 46 + name_len) else {
            expansion.notes.push(format!(
                "ZIP member name could not be read in {}",
                source_path.display()
            ));
            break;
        };
        let member_name = String::from_utf8_lossy(name_bytes).to_string();
        cursor = cursor.saturating_add(46 + name_len + extra_len + comment_len);

        if member_name.is_empty() {
            continue;
        }
        if member_name.ends_with('/') {
            let dir = sanitize_member_path(&member_name);
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(container_dir.join(dir))?;
            }
            continue;
        }
        if method != 0 {
            expansion.notes.push(format!(
                "ZIP member {} in {} uses unsupported compression method {} and was skipped",
                member_name,
                source_path.display(),
                method
            ));
            continue;
        }

        let Some(local_header) = data.get(local_offset..local_offset + 30) else {
            expansion.notes.push(format!(
                "ZIP member {} in {} had an invalid local header offset",
                member_name,
                source_path.display()
            ));
            continue;
        };
        if &local_header[..4] != b"PK\x03\x04" {
            expansion.notes.push(format!(
                "ZIP member {} in {} had a malformed local header",
                member_name,
                source_path.display()
            ));
            continue;
        }

        let local_name_len = le_u16(local_header, 26).unwrap_or(0) as usize;
        let local_extra_len = le_u16(local_header, 28).unwrap_or(0) as usize;
        let Some(data_start) = local_offset
            .checked_add(30)
            .and_then(|offset| offset.checked_add(local_name_len))
            .and_then(|offset| offset.checked_add(local_extra_len))
        else {
            expansion.notes.push(format!(
                "ZIP member {} in {} overflowed while locating payload",
                member_name,
                source_path.display()
            ));
            continue;
        };
        let Some(member_bytes) = data.get(data_start..data_start.saturating_add(compressed_size))
        else {
            expansion.notes.push(format!(
                "ZIP member {} in {} fell outside the archive",
                member_name,
                source_path.display()
            ));
            continue;
        };

        let written =
            write_container_member(&container_dir, &member_name, member_bytes, overwrite)?;
        expansion.paths.push(written);
        expansion.written += 1;
    }

    Ok(expansion)
}

pub(crate) fn extract_tar_members(
    data: &[u8],
    source_path: &Path,
    output_root: &Path,
    overwrite: bool,
) -> io::Result<ContainerExpansion> {
    if !looks_like_tar(data) {
        return Ok(ContainerExpansion::default());
    }

    let container_dir = container_output_dir(output_root, source_path, "tar");
    std::fs::create_dir_all(&container_dir)?;
    let mut expansion = ContainerExpansion {
        expanded: 1,
        ..Default::default()
    };
    let mut cursor = 0usize;

    while cursor + 512 <= data.len() {
        let header = &data[cursor..cursor + 512];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }

        let name = decode_tar_path(header);
        let size = parse_tar_size(header).unwrap_or(0);
        let typeflag = header[156];
        let data_start = cursor.saturating_add(512);
        let data_end = data_start.saturating_add(size);
        if data_end > data.len() {
            expansion.notes.push(format!(
                "TAR member {} in {} exceeded archive bounds",
                name,
                source_path.display()
            ));
            break;
        }

        match typeflag {
            0 | b'0' => {
                let written = write_container_member(
                    &container_dir,
                    &name,
                    &data[data_start..data_end],
                    overwrite,
                )?;
                expansion.paths.push(written);
                expansion.written += 1;
            }
            b'5' => {
                let dir = sanitize_member_path(&name);
                if !dir.as_os_str().is_empty() {
                    std::fs::create_dir_all(container_dir.join(dir))?;
                }
            }
            _ => {}
        }

        cursor = data_end;
        let padding = (512 - (size % 512)) % 512;
        cursor = cursor.saturating_add(padding);
    }

    Ok(expansion)
}

pub(crate) fn container_output_dir(output_root: &Path, source_path: &Path, kind: &str) -> PathBuf {
    let source_name = source_path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "buffer".to_string());
    output_root
        .join("_containers")
        .join(format!("{}_{}", sanitize_component(&source_name), kind))
}

pub(crate) fn write_container_member(
    container_dir: &Path,
    member_name: &str,
    bytes: &[u8],
    overwrite: bool,
) -> io::Result<PathBuf> {
    let sanitized = sanitize_member_path(member_name);
    if sanitized.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "container member path was empty after sanitization",
        ));
    }

    let mut candidate = container_dir.join(sanitized);
    if let Some(parent) = candidate.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if !overwrite {
        let parent = candidate
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| container_dir.to_path_buf());
        let stem = candidate
            .file_stem()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "member".to_string());
        let extension = candidate
            .extension()
            .map(|value| value.to_string_lossy().to_string());
        let mut suffix = 1usize;
        while candidate.exists() {
            let file_name = match &extension {
                Some(extension) => format!("{}_{}.{}", stem, suffix, extension),
                None => format!("{}_{}", stem, suffix),
            };
            candidate = parent.join(file_name);
            suffix += 1;
        }
    }

    std::fs::write(&candidate, bytes)?;
    Ok(candidate)
}

pub(crate) fn sanitize_member_path(value: &str) -> PathBuf {
    let mut path = PathBuf::new();
    for component in value.split(['/', '\\']) {
        let trimmed = component.trim();
        if trimmed.is_empty() || matches!(trimmed, "." | "..") {
            continue;
        }
        let sanitized = sanitize_path_component(trimmed);
        if !sanitized.is_empty() {
            path.push(sanitized);
        }
    }
    path
}

pub(crate) fn sanitize_path_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn decode_tar_path(header: &[u8]) -> String {
    let name = decode_tar_string(&header[..100]);
    let prefix = decode_tar_string(&header[345..500]);
    if prefix.is_empty() {
        name
    } else if name.is_empty() {
        prefix
    } else {
        format!("{}/{}", prefix, name)
    }
}

pub(crate) fn decode_tar_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .map(char::from)
        .collect::<String>()
        .trim()
        .to_string()
}

pub(crate) fn parse_tar_size(header: &[u8]) -> Option<usize> {
    let raw = decode_tar_string(&header[124..136]);
    let raw = raw.trim_matches(char::from(0)).trim();
    if raw.is_empty() {
        Some(0)
    } else {
        usize::from_str_radix(raw, 8).ok()
    }
}

pub(crate) fn find_zip_eocd(data: &[u8]) -> Option<usize> {
    let search_start = data.len().saturating_sub(22 + 65_535);
    data[search_start..]
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .map(|offset| search_start + offset)
}
