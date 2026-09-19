pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    decode_base64_generic(input, false)
}

pub fn decode_base64_url(input: &str) -> Option<Vec<u8>> {
    decode_base64_generic(input, true)
}

fn decode_base64_generic(input: &str, url_safe: bool) -> Option<Vec<u8>> {
    // MIME (RFC 2045) ignores whitespace inside the payload; strip it all.
    let mut normalized: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if normalized.is_empty() {
        return None;
    }

    if url_safe {
        normalized = normalized.replace('-', "+").replace('_', "/");
        match normalized.len() % 4 {
            0 => {}
            2 | 3 => normalized.push_str(&"=".repeat(4 - (normalized.len() % 4))),
            _ => return None,
        }
    } else if !normalized.len().is_multiple_of(4) {
        return None;
    }

    let chunk_count = normalized.len() / 4;
    let mut data = Vec::with_capacity(chunk_count * 3);

    for (chunk_idx, chunk) in normalized.as_bytes().chunks(4).enumerate() {
        let mut values = [0u8; 4];
        let mut padding = 0usize;

        for (i, &b) in chunk.iter().enumerate() {
            values[i] = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => 26 + b - b'a',
                b'0'..=b'9' => 52 + b - b'0',
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    padding += 1;
                    0
                }
                _ => return None,
            };

            if b == b'=' && i < 2 {
                return None;
            }

            if b != b'=' && padding > 0 {
                return None;
            }
        }

        if padding > 0 && chunk_idx + 1 != chunk_count {
            return None;
        }

        let triple = ((values[0] as u32) << 18)
            | ((values[1] as u32) << 12)
            | ((values[2] as u32) << 6)
            | (values[3] as u32);

        data.push(((triple >> 16) & 0xFF) as u8);
        if padding < 2 {
            data.push(((triple >> 8) & 0xFF) as u8);
        }
        if padding == 0 {
            data.push((triple & 0xFF) as u8);
        }
    }

    if data.is_empty() { None } else { Some(data) }
}

/// Attempts to decode Hex safely.
pub fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let normalized = input
        .replace("\\x", " ")
        .replace("\\X", " ")
        .replace("0x", " ")
        .replace("0X", " ");
    if normalized != input || input.chars().any(|c| c.is_ascii_whitespace()) {
        let joined: String = normalized.split_whitespace().collect();
        if joined.is_empty()
            || !joined.len().is_multiple_of(2)
            || !joined.chars().all(|c| c.is_ascii_hexdigit())
        {
            return None;
        }
        return decode_hex(&joined);
    }

    if !input.len().is_multiple_of(2) {
        return None;
    }

    let mut data = Vec::new();
    let mut iter = input.chars().peekable();
    while let Some(c1) = iter.next() {
        if let Some(c2) = iter.next() {
            if let (Some(v1), Some(v2)) = (c1.to_digit(16), c2.to_digit(16)) {
                data.push(((v1 << 4) | v2) as u8);
            } else {
                return None;
            }
        }
    }
    if data.is_empty() { None } else { Some(data) }
}

/// Decodes URL-encoded (percent-encoded) strings.
pub fn decode_url(input: &str) -> Option<String> {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let mut hex = String::new();
            if let Some(h1) = chars.next() {
                hex.push(h1);
            }
            if let Some(h2) = chars.next() {
                hex.push(h2);
            }
            if let Ok(v) = u8::from_str_radix(&hex, 16) {
                result.push(v as char);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    if result == input { None } else { Some(result) }
}

pub fn decode_binary(input: &str) -> Option<Vec<u8>> {
    let normalized = input.replace("0b", " ").replace("0B", " ");
    let bits: String = normalized
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if bits.is_empty() || !bits.len().is_multiple_of(8) || !bits.chars().all(|c| c == '0' || c == '1') {
        return None;
    }

    let mut result = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.as_bytes().chunks(8) {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | u8::from(bit == b'1');
        }
        result.push(byte);
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Decodes decimal byte values ("72 101 108 108 111", commas/newlines also
/// accepted). Every token must be 0-255; anything else returns None.
pub fn decode_decimal(input: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    for token in input.split([',', '\n', '\r', '\t', ' ']) {
        let token = token.trim().trim_end_matches(['.', ';', ':']);
        if token.is_empty() {
            continue;
        }
        match token.parse::<u8>() {
            Ok(byte) => result.push(byte),
            Err(_) => return None,
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

pub fn decode_octal(input: &str) -> Option<Vec<u8>> {
    let normalized = input
        .replace("0o", " ")
        .replace("0O", " ")
        .replace('\\', " ");
    let compact: String = normalized
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    if compact.is_empty() || !compact.chars().all(|c| matches!(c, '0'..='7')) {
        return None;
    }

    let groups: Vec<String> = if normalized.chars().any(|c| c.is_ascii_whitespace()) {
        normalized
            .split_whitespace()
            .map(|group| group.to_string())
            .collect()
    } else if compact.len().is_multiple_of(3) {
        compact
            .as_bytes()
            .chunks(3)
            .map(|chunk| String::from_utf8(chunk.to_vec()).ok())
            .collect::<Option<Vec<_>>>()?
    } else {
        return None;
    };

    let mut decoded = Vec::with_capacity(groups.len());
    for group in groups {
        if group.is_empty() || group.len() > 3 {
            return None;
        }

        let value = u8::from_str_radix(&group, 8).ok()?;
        decoded.push(value);
    }

    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

/// Value of one 5-character Ascii85 group. 85^5 - 1 exceeds u32, so
/// accumulate wide and reject over-range groups (invalid per spec) instead
/// of overflowing.
fn ascii85_group_value(block: &[u32]) -> Option<u32> {
    let value: u64 = block
        .iter()
        .fold(0u64, |acc, digit| acc * 85 + u64::from(*digit));
    u32::try_from(value).ok()
}

pub fn decode_ascii85(input: &str) -> Option<Vec<u8>> {    let trimmed = input.trim();

    // Strip optional Adobe delimiters
    let body = if trimmed.starts_with("<~") && trimmed.ends_with("~>") {
        &trimmed[2..trimmed.len().saturating_sub(2)]
    } else if let Some(rest) = trimmed.strip_prefix("<~") {
        rest
    } else {
        trimmed
    };

    if body.is_empty() {
        return None;
    }

    let mut data = Vec::new();
    let mut block = Vec::with_capacity(5);

    for ch in body.chars().filter(|c| !c.is_ascii_whitespace()) {
        if ch == 'z' {
            if !block.is_empty() {
                return None;
            }
            data.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }

        if !('!'..='u').contains(&ch) {
            return None;
        }

        block.push((ch as u32) - 33);
        if block.len() == 5 {
            let value = ascii85_group_value(&block)?;
            data.extend_from_slice(&value.to_be_bytes());
            block.clear();
        }
    }

    if !block.is_empty() {
        let original_len = block.len();
        block.resize(5, 84);
        let value = ascii85_group_value(&block)?;
        let bytes = value.to_be_bytes();
        data.extend_from_slice(&bytes[..original_len - 1]);
    }

    if data.is_empty() { None } else { Some(data) }
}

pub fn decode_quoted_printable(input: &str) -> Option<Vec<u8>> {
    if !input.contains('=') {
        return None;
    }

    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut changed = false;

    while i < bytes.len() {
        if bytes[i] == b'=' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                changed = true;
                i += 2;
                continue;
            }

            if i + 2 < bytes.len() && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                changed = true;
                i += 3;
                continue;
            }

            if i + 2 < bytes.len() {
                // Slice bytes, not str: multibyte input must fail cleanly here.
                let pair = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(value) = u8::from_str_radix(pair, 16) {
                    decoded.push(value);
                    changed = true;
                    i += 3;
                    continue;
                }
            }
        }

        decoded.push(bytes[i]);
        i += 1;
    }

    if changed { Some(decoded) } else { None }
}

pub fn decode_html_entities(input: &str) -> Option<String> {
    if !input.contains('&') {
        return None;
    }

    let mut result = String::new();
    let mut chars = input.chars().peekable();
    let mut changed = false;

    while let Some(ch) = chars.next() {
        if ch != '&' {
            result.push(ch);
            continue;
        }

        let mut entity = String::new();
        while let Some(&next) = chars.peek() {
            entity.push(next);
            chars.next();
            if next == ';' || entity.len() > 10 {
                break;
            }
        }

        let decoded = if entity.ends_with(';') {
            match &entity[..entity.len() - 1] {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some(' '),
                value if value.starts_with("#x") || value.starts_with("#X") => {
                    u32::from_str_radix(&value[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                value if value.starts_with('#') => {
                    value[1..].parse::<u32>().ok().and_then(char::from_u32)
                }
                _ => None,
            }
        } else {
            None
        };

        if let Some(decoded_char) = decoded {
            result.push(decoded_char);
            changed = true;
        } else {
            result.push('&');
            result.push_str(&entity);
        }
    }

    if changed { Some(result) } else { None }
}

pub fn decode_morse(input: &str) -> Option<String> {
    if !input.contains('.') && !input.contains('-') {
        return None;
    }

    let mut words = Vec::new();
    for word in input.trim().split('/') {
        let word = word.trim();
        if word.is_empty() {
            continue;
        }

        let mut decoded = String::new();
        for symbol in word.split_whitespace() {
            let ch = match symbol {
                ".-" => 'A',
                "-..." => 'B',
                "-.-." => 'C',
                "-.." => 'D',
                "." => 'E',
                "..-." => 'F',
                "--." => 'G',
                "...." => 'H',
                ".." => 'I',
                ".---" => 'J',
                "-.-" => 'K',
                ".-.." => 'L',
                "--" => 'M',
                "-." => 'N',
                "---" => 'O',
                ".--." => 'P',
                "--.-" => 'Q',
                ".-." => 'R',
                "..." => 'S',
                "-" => 'T',
                "..-" => 'U',
                "...-" => 'V',
                ".--" => 'W',
                "-..-" => 'X',
                "-.--" => 'Y',
                "--.." => 'Z',
                "-----" => '0',
                ".----" => '1',
                "..---" => '2',
                "...--" => '3',
                "....-" => '4',
                "....." => '5',
                "-...." => '6',
                "--..." => '7',
                "---.." => '8',
                "----." => '9',
                _ => return None,
            };
            decoded.push(ch);
        }

        if !decoded.is_empty() {
            words.push(decoded);
        }
    }

    if words.is_empty() {
        None
    } else {
        Some(words.join(" "))
    }
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod ascii85_tests;
