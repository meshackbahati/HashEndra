pub fn extract_printable_strings(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
    let mut strings = Vec::new();
    let mut chunk_start: Option<usize> = None;

    for (idx, &byte) in data.iter().enumerate() {
        if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
            if chunk_start.is_none() {
                chunk_start = Some(idx);
            }
        } else if let Some(start) = chunk_start.take() {
            if idx - start >= min_len {
                if let Ok(chunk) = std::str::from_utf8(&data[start..idx]) {
                    strings.push((start, chunk.to_string()));
                }
            }
        }
    }

    if let Some(start) = chunk_start {
        if data.len() - start >= min_len {
            if let Ok(chunk) = std::str::from_utf8(&data[start..]) {
                strings.push((start, chunk.to_string()));
            }
        }
    }

    strings
}

pub fn extract_utf16le_strings(data: &[u8], min_chars: usize) -> Vec<(usize, String)> {
    let mut strings = Vec::new();
    let mut start = 0usize;

    while start + 1 < data.len() {
        let mut cursor = start;
        let mut decoded = String::new();

        while cursor + 1 < data.len() {
            let value = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
            let Some(ch) = char::from_u32(value as u32) else {
                break;
            };

            if ch.is_control() && !ch.is_whitespace() {
                break;
            }

            if !(ch.is_ascii_graphic() || ch.is_ascii_whitespace()) {
                break;
            }

            decoded.push(ch);
            cursor += 2;
        }

        if decoded.len() >= min_chars {
            strings.push((start, decoded));
            start = cursor + 2;
        } else {
            start += 1;
        }
    }

    strings
}

pub fn flatten_string_lines(
    strings: Vec<(usize, String)>,
    min_len: usize,
    encoding: &'static str,
) -> Vec<(usize, &'static str, String)> {
    let mut flattened = Vec::new();

    for (base_offset, value) in strings {
        let mut running_offset = 0usize;
        for line in value.lines() {
            if line.len() >= min_len {
                flattened.push((base_offset + running_offset, encoding, line.to_string()));
            }
            running_offset += line.len() + 1;
        }
    }

    flattened
}

#[cfg(test)]
mod tests {
    use super::{extract_printable_strings, extract_utf16le_strings, flatten_string_lines};

    #[test]
    fn extracts_printable_strings_with_offsets() {
        let data = b"\x00hello world\x00jwt=abc.def.ghi\x00";
        let strings = extract_printable_strings(data, 5);

        assert_eq!(strings[0].0, 1);
        assert_eq!(strings[0].1, "hello world");
        assert_eq!(strings[1].0, 13);
        assert_eq!(strings[1].1, "jwt=abc.def.ghi");
    }

    #[test]
    fn extracts_utf16le_strings_with_offsets() {
        let data = [0xFF, b'H', 0x00, b'i', 0x00, 0x00, 0x00];
        let strings = extract_utf16le_strings(&data, 2);

        assert_eq!(strings[0].0, 1);
        assert_eq!(strings[0].1, "Hi");
    }

    #[test]
    fn flattens_multiline_strings() {
        let flattened = flatten_string_lines(vec![(10, "line1\nline2".to_string())], 4, "ascii");

        assert_eq!(flattened[0], (10, "ascii", "line1".to_string()));
        assert_eq!(flattened[1], (16, "ascii", "line2".to_string()));
    }
}
