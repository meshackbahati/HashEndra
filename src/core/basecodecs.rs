//! Less-common base codecs: base32hex, base58check, base62, base91, Z85,
//! Crockford base32, UUencode, XXencode.
//!
//! All pairs are total on valid input and roundtrip-tested. Decoding is
//! strict (wrong alphabets/padding/checksums return None) so these are safe
//! to call explicitly via `--from`. They are NOT in the auto-detect engine:
//! short-alphabet codecs collide with each other constantly, and guessing
//! between them is luck, not analysis.

use num_bigint::BigUint;

/// Base32Hex (RFC 4648 §7): 0-9A-V, padded to a multiple of 8.
pub fn encode_base32hex(data: &[u8]) -> String {
    encode_base_n(data, b"0123456789ABCDEFGHIJKLMNOPQRSTUV", 5, 8, b'=')
}

/// Base32Hex decode. Rejects bad padding and non-alphabet bytes.
pub fn decode_base32hex(input: &str) -> Option<Vec<u8>> {
    decode_base_n(input, b"0123456789ABCDEFGHIJKLMNOPQRSTUV", 5, b'=')
}

/// Shared bit-group codec core: `bits` per symbol, padded output.
fn encode_base_n(data: &[u8], alphabet: &[u8], bits: u32, block: usize, pad: u8) -> String {
    let mut acc = 0u32;
    let mut acc_bits = 0u32;
    let mut output = String::new();
    let mask = (1u32 << bits) - 1;

    for &byte in data {
        acc = (acc << 8) | byte as u32;
        acc_bits += 8;
        while acc_bits >= bits {
            acc_bits -= bits;
            output.push(alphabet[((acc >> acc_bits) & mask) as usize] as char);
        }
    }

    if acc_bits > 0 {
        acc <<= bits - acc_bits;
        output.push(alphabet[(acc & mask) as usize] as char);
    }

    while !output.len().is_multiple_of(block) {
        output.push(pad as char);
    }
    output
}

fn decode_base_n(input: &str, alphabet: &[u8], bits: u32, pad: u8) -> Option<Vec<u8>> {
    let trimmed = input.trim_end_matches(pad as char);
    if trimmed.is_empty() || !is_valid_base_padding(input, pad) {
        return None;
    }
    let mut acc = 0u32;
    let mut acc_bits = 0u32;
    let mut result = Vec::new();

    for &b in trimmed.as_bytes() {
        let val = alphabet.iter().position(|&x| x == b)? as u32;
        acc = (acc << bits) | val;
        acc_bits += bits;
        while acc_bits >= 8 {
            acc_bits -= 8;
            result.push((acc >> acc_bits) as u8);
            if acc_bits > 0 {
                acc &= (1 << acc_bits) - 1;
            } else {
                acc = 0;
            }
        }
    }

    if acc_bits > 0 && acc != 0 {
        return None;
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn is_valid_base_padding(input: &str, pad: u8) -> bool {
    let body_len = input.trim_end_matches(pad as char).len();
    let pad_len = input.len() - body_len;
    // Padding may only trail, and total length must align to a full quantum.
    pad_len <= 6 && input[body_len..].bytes().all(|b| b == pad)
}

/// Base58Check encode: version byte + payload + 4-byte double-SHA256 checksum.
pub fn encode_base58check(version: u8, payload: &[u8]) -> String {
    use sha2::Digest;
    let mut prefixed = Vec::with_capacity(1 + payload.len() + 4);
    prefixed.push(version);
    prefixed.extend_from_slice(payload);
    let first = sha2::Sha256::digest(&prefixed);
    let second = sha2::Sha256::digest(first);
    prefixed.extend_from_slice(&second[..4]);
    encode_base58_raw(&prefixed)
}

/// Base58Check decode: verifies the checksum, returns (version, payload).
pub fn decode_base58check(input: &str) -> Option<(u8, Vec<u8>)> {
    use sha2::Digest;
    let raw = decode_base58_raw(input.trim())?;
    if raw.len() < 5 {
        return None;
    }
    let (body, checksum) = raw.split_at(raw.len() - 4);
    let first = sha2::Sha256::digest(body);
    let second = sha2::Sha256::digest(first);
    if &second[..4] != checksum {
        return None;
    }
    Some((body[0], body[1..].to_vec()))
}

const B58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn encode_base58_raw(data: &[u8]) -> String {
    let base = BigUint::from(58u32);
    let mut value = BigUint::from_bytes_be(data);
    let mut result = Vec::new();
    while value > BigUint::ZERO {
        let digit = (&value % &base).to_u32_digits();
        result.push(B58_ALPHABET[*digit.first().unwrap_or(&0) as usize]);
        value /= &base;
    }
    result.reverse();
    for &b in data {
        if b == 0 {
            result.insert(0, b'1');
        } else {
            break;
        }
    }
    String::from_utf8(result).unwrap_or_default()
}

fn decode_base58_raw(input: &str) -> Option<Vec<u8>> {
    let base = BigUint::from(58u32);
    let mut value = BigUint::from(0u32);
    for &b in input.as_bytes() {
        let pos = B58_ALPHABET.iter().position(|&x| x == b)?;
        value = value * &base + BigUint::from(pos);
    }
    let mut result = value.to_bytes_be();
    for &b in input.as_bytes() {
        if b == b'1' {
            result.insert(0, 0);
        } else {
            break;
        }
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Base62 encode (0-9A-Za-z), big-number style with leading-zero preservation.
pub fn encode_base62(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    encode_bignum(data, ALPHABET, b'0')
}

/// Base62 decode.
pub fn decode_base62(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    decode_bignum(input.trim(), ALPHABET, b'0')
}

fn encode_bignum(data: &[u8], alphabet: &[u8], zero: u8) -> String {
    let base = BigUint::from(alphabet.len() as u32);
    let mut value = BigUint::from_bytes_be(data);
    let mut result = Vec::new();
    while value > BigUint::ZERO {
        let digit = (&value % &base).to_u32_digits();
        result.push(alphabet[*digit.first().unwrap_or(&0) as usize]);
        value /= &base;
    }
    result.reverse();
    for &b in data {
        if b == 0 {
            result.insert(0, zero);
        } else {
            break;
        }
    }
    if result.is_empty() {
        result.push(zero);
    }
    String::from_utf8(result).unwrap_or_default()
}

fn decode_bignum(input: &str, alphabet: &[u8], zero: u8) -> Option<Vec<u8>> {
    if input.is_empty() || !input.bytes().all(|b| alphabet.contains(&b)) {
        return None;
    }
    let base = BigUint::from(alphabet.len() as u32);
    let mut value = BigUint::from(0u32);
    for &b in input.as_bytes() {
        let pos = alphabet.iter().position(|&x| x == b)?;
        value = value * &base + BigUint::from(pos);
    }
    let mut result = value.to_bytes_be();
    // BigUint drops leading zeros; restore from leading zero-chars, but an
    // all-zero input decodes to empty which then means b"\x00".
    let leading = input.bytes().take_while(|&b| b == zero).count();
    if result.is_empty() && leading > 0 {
        return Some(vec![0u8]);
    }
    for _ in 0..leading {
        result.insert(0, 0);
    }
    // Strip the phantom zero BigUint adds when value is small? No:
    // to_bytes_be is exact. But leading real zeros double-count when the
    // value itself starts with zero bytes — they don't, value has none.
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// basE91 encode (alphabet of 91 printable ASCII chars).
pub fn encode_base91(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";
    // basE91 works on 13/14-bit groups; this is the reference algorithm.
    let mut output = String::new();
    let mut queue = 0u32;
    let mut nqueue = 0u32;
    for &b in data {
        queue |= (b as u32) << nqueue;
        nqueue += 8;
        if nqueue > 13 {
            let mut v = queue & 8191;
            if v > 88 {
                queue >>= 13;
                nqueue -= 13;
            } else {
                v = queue & 16383;
                queue >>= 14;
                nqueue -= 14;
            }
            output.push(ALPHABET[(v % 91) as usize] as char);
            output.push(ALPHABET[(v / 91) as usize] as char);
        }
    }
    if nqueue > 0 {
        output.push(ALPHABET[(queue % 91) as usize] as char);
        if nqueue > 7 || queue > 90 {
            output.push(ALPHABET[(queue / 91) as usize] as char);
        }
    }
    output
}

/// basE91 decode.
pub fn decode_base91(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";
    let mut output = Vec::new();
    let mut queue = 0u32;
    let mut nqueue = 0u32;
    let mut v: i32 = -1;
    for &b in input.as_bytes() {
        if b == b'\n' || b == b'\r' || b == b' ' || b == b'\t' {
            continue;
        }
        let pos = ALPHABET.iter().position(|&x| x == b)? as u32;
        if v < 0 {
            v = pos as i32;
        } else {
            v += (pos * 91) as i32;
            queue |= (v as u32) << nqueue;
            nqueue += if v & 8191 > 88 { 13 } else { 14 };
            while nqueue > 7 {
                output.push((queue & 255) as u8);
                queue >>= 8;
                nqueue -= 8;
            }
            v = -1;
        }
    }
    if v >= 0 {
        queue |= (v as u32) << nqueue;
        nqueue += 7;
        while nqueue > 7 {
            output.push((queue & 255) as u8);
            queue >>= 8;
            nqueue -= 8;
        }
    }
    if output.is_empty() {
        None
    } else {
        Some(output)
    }
}

/// Z85 encode (ZeroMQ RFC 32): input length must be a multiple of 4.
pub fn encode_z85(data: &[u8]) -> Option<String> {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
    if !data.len().is_multiple_of(4) {
        return None;
    }
    let mut out = String::with_capacity(data.len() / 4 * 5);
    for chunk in data.chunks(4) {
        let mut value =
            ((chunk[0] as u32) << 24) | ((chunk[1] as u32) << 16) | ((chunk[2] as u32) << 8) | chunk[3] as u32;
        let mut digits = [0u8; 5];
        for d in digits.iter_mut().rev() {
            *d = ALPHABET[(value % 85) as usize];
            value /= 85;
        }
        out.push_str(std::str::from_utf8(&digits).unwrap_or(""));
    }
    Some(out)
}

/// Z85 decode: input length must be a multiple of 5.
pub fn decode_z85(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(5) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 5 * 4);
    for chunk in bytes.chunks(5) {
        let mut value: u64 = 0;
        for &b in chunk {
            let pos = ALPHABET.iter().position(|&x| x == b)? as u64;
            value = value * 85 + pos;
        }
        if value > u32::MAX as u64 {
            return None;
        }
        out.extend_from_slice(&(value as u32).to_be_bytes());
    }
    Some(out)
}

/// Crockford base32 encode (uppercase, no padding).
pub fn encode_crockford(data: &[u8]) -> String {
    encode_base_n(data, b"0123456789ABCDEFGHJKMNPQRSTVWXYZ", 5, 8, b'=')
        .trim_end_matches('=')
        .to_string()
}

/// Crockford base32 decode: case-insensitive, hyphens ignored,
/// I/L→1 and O→0 aliases accepted.
pub fn decode_crockford(input: &str) -> Option<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| *c != '-')
        .map(|c| match c {
            'i' | 'I' | 'l' | 'L' => '1',
            'o' | 'O' => '0',
            c => c.to_ascii_uppercase(),
        })
        .collect();
    decode_base_n(&cleaned, b"0123456789ABCDEFGHJKMNPQRSTVWXYZ", 5, b'=')
}

/// UUencode one body line (up to 45 bytes): length char + 4-char groups.
/// Full files wrap lines with `begin <mode> <name>` / `end` around these.
pub fn encode_uu(data: &[u8]) -> String {
    uu_encode_with(data, false)
}

/// UUencode body decode (one or more lines).
pub fn decode_uu(input: &str) -> Option<Vec<u8>> {
    uu_decode_with(input, false)
}

/// XXencode one body line (same framing as UUencode, different alphabet).
pub fn encode_xx(data: &[u8]) -> String {
    uu_encode_with(data, true)
}

/// XXencode body decode.
pub fn decode_xx(input: &str) -> Option<Vec<u8>> {
    uu_decode_with(input, true)
}

const XX_ALPHABET: &[u8] = b"+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Shared UU/XX body codec. `is_xx` selects the alphabet; length chars are
/// length+32 in both (max 45 bytes per line).
fn uu_encode_with(data: &[u8], is_xx: bool) -> String {
    let mut out = String::new();
    for line in data.chunks(45) {
        out.push((line.len() as u8 + 32) as char);
        for chunk in line.chunks(3) {
            let mut n = [0u8; 3];
            n[..chunk.len()].copy_from_slice(chunk);
            let val = ((n[0] as u32) << 16) | ((n[1] as u32) << 8) | n[2] as u32;
            for shift in [18, 12, 6, 0] {
                let sextet = ((val >> shift) & 63) as u8;
                let c = if is_xx {
                    XX_ALPHABET[sextet as usize]
                } else if sextet == 0 {
                    b'`'
                } else {
                    sextet + 32
                };
                out.push(c as char);
            }
        }
        out.push('\n');
    }
    out
}

fn uu_decode_with(input: &str, is_xx: bool) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for line in input.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() || line.starts_with("begin") || line == "end" {
            continue;
        }
        let mut bytes = line.bytes();
        let len_char = bytes.next()?;
        let mut declared = len_char.wrapping_sub(32) as usize;
        // Backtick is uuencode's zero-length alias.
        if !is_xx && len_char == b'`' {
            declared = 0;
        }
        if declared > 45 {
            return None;
        }
        let mut line_out = Vec::new();
        let rest: Vec<u8> = bytes.collect();
        if !rest.len().is_multiple_of(4) {
            return None;
        }
        for quad in rest.chunks(4) {
            let mut val = 0u32;
            for &b in quad {
                let sextet = if is_xx {
                    XX_ALPHABET.iter().position(|&x| x == b)? as u32
                } else if b == b'`' {
                    0
                } else if (b'!'..=b'_').contains(&b) {
                    (b - 32) as u32
                } else {
                    return None;
                };
                val = (val << 6) | sextet;
            }
            line_out.push((val >> 16) as u8);
            line_out.push((val >> 8) as u8);
            line_out.push(val as u8);
        }
        line_out.truncate(declared);
        if line_out.len() != declared {
            return None;
        }
        out.extend_from_slice(&line_out);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
#[path = "basecodecs_tests.rs"]
mod basecodecs_tests;
