use std::fmt::Write;

/// Encodes input bytes to a hexadecimal string (lowercase).
pub fn encode_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Encodes input bytes to a hexadecimal string (uppercase).
pub fn encode_hex_upper(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Encodes input bytes to Base64 (standard).
pub fn encode_base64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Encodes input bytes to Base64 (URL-safe).
pub fn encode_base64url(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Encodes input bytes to Base32 (RFC 4648).
pub fn encode_base32(data: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut bit_count = 0u8;
    let mut output = String::new();

    for &byte in data {
        bits = (bits << 8) | byte as u32;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let index = ((bits >> bit_count) & 0x1F) as usize;
            output.push(alphabet[index] as char);
        }
    }

    if bit_count > 0 {
        bits <<= 5 - bit_count;
        let index = (bits & 0x1F) as usize;
        output.push(alphabet[index] as char);
    }

    // Pad to multiple of 8
    while output.len() % 8 != 0 {
        output.push('=');
    }

    output
}

/// Encodes input bytes to Base58 (Bitcoin alphabet).
pub fn encode_base58(data: &[u8]) -> String {
    use num_bigint::BigUint;

    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let b58_base = BigUint::from(58u32);
    let mut value = BigUint::from_bytes_be(data);
    let mut result = Vec::new();

    while value > BigUint::ZERO {
        let digit = (&value % &b58_base).to_u32_digits();
        let idx = *digit.first().unwrap_or(&0) as usize;
        result.push(alphabet[idx]);
        value /= &b58_base;
    }

    result.reverse();

    // Leading zeros become '1's
    for &b in data {
        if b == 0 {
            result.insert(0, b'1');
        } else {
            break;
        }
    }

    String::from_utf8(result).unwrap_or_default()
}

/// Encodes input text to URL percent-encoding.
pub fn encode_url(input: &str) -> String {
    let mut result = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b' ' => result.push_str("%20"),
            _ => {
                write!(result, "%{:02X}", byte).unwrap();
            }
        }
    }
    result
}

/// Encodes input text to HTML entities.
pub fn encode_html(input: &str) -> String {
    let mut output = String::new();
    for c in input.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(c),
        }
    }
    output
}

/// Encodes input bytes to Quoted-Printable.
pub fn encode_quoted_printable(data: &[u8]) -> String {
    let mut output = String::new();
    let mut line_len = 0usize;

    for &b in data {
        if b == b' ' || b == b'\t' {
            output.push(b as char);
            line_len += 1;
        } else if b.is_ascii_graphic() && b != b'=' {
            output.push(b as char);
            line_len += 1;
        } else if b == b'\n' {
            output.push('\n');
            line_len = 0;
        } else if b == b'\r' {
            // skip, handle as part of \r\n
        } else {
            if line_len >= 73 {
                output.push_str("=\n");
                line_len = 0;
            }
            write!(output, "={:02X}", b).unwrap();
            line_len += 3;
        }
    }
    output
}

/// Encodes input bytes to binary string (8 bits per byte, space-separated).
pub fn encode_binary(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:08b}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Encodes input bytes to octal string (space-separated).
pub fn encode_octal(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:03o}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Encodes input text to Morse code (space-separated, / between words).
pub fn encode_morse(input: &str) -> String {
    let morse_map = [
        ('A', ".-"), ('B', "-..."), ('C', "-.-."), ('D', "-.."),
        ('E', "."), ('F', "..-."), ('G', "--."), ('H', "...."),
        ('I', ".."), ('J', ".---"), ('K', "-.-"), ('L', ".-.."),
        ('M', "--"), ('N', "-."), ('O', "---"), ('P', ".--."),
        ('Q', "--.-"), ('R', ".-."), ('S', "..."), ('T', "-"),
        ('U', "..-"), ('V', "...-"), ('W', ".--"), ('X', "-..-"),
        ('Y', "-.--"), ('Z', "--.."),
        ('0', "-----"), ('1', ".----"), ('2', "..---"), ('3', "...--"),
        ('4', "....-"), ('5', "....."), ('6', "-...."), ('7', "--..."),
        ('8', "---.."), ('9', "----."),
        ('.', ".-.-.-"), (',', "--..--"), ('?', "..--.."),
        ('\'', ".----."), ('!', "-.-.--"), ('/', "-..-."),
        ('(', "-.--."), (')', "-.--.-"), ('&', ".-..."),
        (':', "---..."), (';', "-.-.-."), ('=', "-...-"),
        ('+', ".-.-."), ('-', "-....-"), ('_', "..--.-"),
        ('"', ".-..-."), ('$', "...-..-"), ('@', ".--.-."),
        (' ', "/"),
    ];

    let result: Vec<&str> = input
        .to_uppercase()
        .chars()
        .map(|c| {
            morse_map
                .iter()
                .find(|&&(ch, _)| ch == c)
                .map(|&(_, code)| code)
                .unwrap_or("?")
        })
        .collect();

    result.join(" ")
}

/// Encodes input bytes to Ascii85 (Adobe variant).
pub fn encode_ascii85(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let mut output = String::from("<~");
    let mut i = 0;

    while i < data.len() {
        let chunk_len = std::cmp::min(4, data.len() - i);
        let mut val = 0u32;
        for j in 0..chunk_len {
            val = (val << 8) | data[i + j] as u32;
        }
        if chunk_len < 4 {
            val <<= (4 - chunk_len) * 8;
        }

        if val == 0 && chunk_len == 4 {
            output.push('z');
        } else {
            let mut chars = [0u8; 5];
            for j in (0..5).rev() {
                chars[j] = b'!' + (val % 85) as u8;
                val /= 85;
            }
            // Only take the needed chars for the last chunk
            let take = chunk_len + 1;
            for &c in &chars[..take] {
                output.push(c as char);
            }
        }
        i += chunk_len;
    }

    output.push_str("~>");
    output
}

pub const ENCODING_FORMATS: &[&str] = &[
    "base64", "base64url", "base32", "base58", "hex", "hexupper",
    "url", "html", "qp", "binary", "octal", "morse", "ascii85",
];

/// Encodes input to the specified format. Returns Ok(String) on success.
pub fn encode_to_format(input: &str, format: &str) -> Result<String, String> {
    let data = input.as_bytes();
    match format.to_ascii_lowercase().as_str() {
        "base64" => Ok(encode_base64(data)),
        "base64url" => Ok(encode_base64url(data)),
        "base32" => Ok(encode_base32(data)),
        "base58" => Ok(encode_base58(data)),
        "hex" => Ok(encode_hex(data)),
        "hexupper" | "hex-upper" => Ok(encode_hex_upper(data)),
        "url" => Ok(encode_url(input)),
        "html" => Ok(encode_html(input)),
        "qp" | "quoted-printable" => Ok(encode_quoted_printable(data)),
        "binary" => Ok(encode_binary(data)),
        "octal" => Ok(encode_octal(data)),
        "morse" => Ok(encode_morse(input)),
        "ascii85" | "a85" => Ok(encode_ascii85(data)),
        _ => Err(format!(
            "Unknown encoding format '{}'. Use --list-encodings to see supported formats.",
            format
        )),
    }
}
