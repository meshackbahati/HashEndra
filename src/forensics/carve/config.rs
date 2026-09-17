use super::{BytePattern, CarveProfile};
use std::io;

pub(crate) fn parse_profile_line(line_no: usize, line: &str) -> io::Result<CarveProfile> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "config line {} must have: ext case max header footer [description...]",
                line_no
            ),
        ));
    }

    let extension = parts[0].to_ascii_lowercase();
    let max_size = match parts[2] {
        "0" | "-" | "none" | "NONE" => None,
        value => Some(value.parse::<usize>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("config line {} has invalid max size", line_no),
            )
        })?),
    };
    let header = parse_pattern_token(parts[3]).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("config line {} header error: {}", line_no, error),
        )
    })?;
    let footer = if matches!(parts[4], "-" | "none" | "NONE") {
        None
    } else {
        Some(parse_pattern_token(parts[4]).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("config line {} footer error: {}", line_no, error),
            )
        })?)
    };
    let description = if parts.len() > 5 {
        parts[5..].join(" ")
    } else {
        format!("Custom {}", extension.to_uppercase())
    };

    Ok(CarveProfile {
        extension,
        description,
        headers: vec![header],
        footer,
        max_size,
    })
}

pub(crate) fn parse_pattern_token(token: &str) -> Result<BytePattern, String> {
    let mut bytes = Vec::new();
    let mut index = 0usize;
    let raw = token.as_bytes();

    while index < raw.len() {
        match raw[index] {
            b'\\' => {
                index += 1;
                if index >= raw.len() {
                    return Err("trailing escape".to_string());
                }

                match raw[index] {
                    b'x' => {
                        if index + 2 >= raw.len() {
                            return Err("incomplete hex escape".to_string());
                        }
                        let hi = from_hex(raw[index + 1])?;
                        let lo = from_hex(raw[index + 2])?;
                        bytes.push(Some((hi << 4) | lo));
                        index += 3;
                    }
                    b'n' => {
                        bytes.push(Some(b'\n'));
                        index += 1;
                    }
                    b'r' => {
                        bytes.push(Some(b'\r'));
                        index += 1;
                    }
                    b't' => {
                        bytes.push(Some(b'\t'));
                        index += 1;
                    }
                    b'0' => {
                        bytes.push(Some(0));
                        index += 1;
                    }
                    other => {
                        bytes.push(Some(other));
                        index += 1;
                    }
                }
            }
            b'?' => {
                bytes.push(None);
                index += 1;
            }
            byte => {
                bytes.push(Some(byte));
                index += 1;
            }
        }
    }

    Ok(BytePattern::wildcard(bytes))
}

pub(crate) fn from_hex(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex digit".to_string()),
    }
}

pub(crate) fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn sanitize_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}
