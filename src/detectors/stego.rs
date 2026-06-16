use crate::core::patterns::{DetectionType, Signature};

pub struct FileSignature {
    pub name: &'static str,
    pub magic: &'static [u8],
    pub extension: &'static str,
    pub description: &'static str,
}

pub const FILE_SIGNATURES: &[FileSignature] = &[
    FileSignature {
        name: "JPEG Image",
        magic: &[0xFF, 0xD8, 0xFF],
        extension: "jpg",
        description: "JPEG Image",
    },
    FileSignature {
        name: "PNG Image",
        magic: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        extension: "png",
        description: "Portable Network Graphics",
    },
    FileSignature {
        name: "GIF Image",
        magic: &[0x47, 0x49, 0x46, 0x38],
        extension: "gif",
        description: "GIF Image",
    },
    FileSignature {
        name: "ZIP Archive",
        magic: &[0x50, 0x4B, 0x03, 0x04],
        extension: "zip",
        description: "ZIP Archive (Standard)",
    },
    FileSignature {
        name: "ZIP Archive (Empty)",
        magic: &[0x50, 0x4B, 0x05, 0x06],
        extension: "zip",
        description: "ZIP Archive (Empty)",
    },
    FileSignature {
        name: "ZIP Archive (Spanned)",
        magic: &[0x50, 0x4B, 0x07, 0x08],
        extension: "zip",
        description: "ZIP Archive (Spanned)",
    },
    FileSignature {
        name: "RAR Archive",
        magic: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00],
        extension: "rar",
        description: "RAR Archive",
    },
    FileSignature {
        name: "RAR Archive v5",
        magic: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00],
        extension: "rar",
        description: "RAR Archive v5",
    },
    FileSignature {
        name: "7z Archive",
        magic: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        extension: "7z",
        description: "7-Zip Archive",
    },
    FileSignature {
        name: "PDF Document",
        magic: &[0x25, 0x50, 0x44, 0x46, 0x2D],
        extension: "pdf",
        description: "PDF Document",
    },
    FileSignature {
        name: "GZIP Archive",
        magic: &[0x1F, 0x8B, 0x08],
        extension: "gz",
        description: "Gzip Compressed Stream",
    },
    FileSignature {
        name: "SQLite Database",
        magic: b"SQLite format 3\x00",
        extension: "sqlite",
        description: "SQLite 3 Database",
    },
    FileSignature {
        name: "ELF Binary",
        magic: &[0x7F, 0x45, 0x4C, 0x46],
        extension: "elf",
        description: "Linux ELF Binary",
    },
    FileSignature {
        name: "PE Executable",
        magic: &[0x4D, 0x5A],
        extension: "exe",
        description: "Windows Portable Executable",
    },
    FileSignature {
        name: "Mach-O Binary",
        magic: &[0xFE, 0xED, 0xFA, 0xCE],
        extension: "macho",
        description: "Mach-O 32-bit Binary (Big Endian)",
    },
    FileSignature {
        name: "Mach-O Binary",
        magic: &[0xCE, 0xFA, 0xED, 0xFE],
        extension: "macho",
        description: "Mach-O 32-bit Binary (Little Endian)",
    },
    FileSignature {
        name: "Mach-O Binary",
        magic: &[0xFE, 0xED, 0xFA, 0xCF],
        extension: "macho",
        description: "Mach-O 64-bit Binary (Big Endian)",
    },
    FileSignature {
        name: "Mach-O Binary",
        magic: &[0xCF, 0xFA, 0xED, 0xFE],
        extension: "macho",
        description: "Mach-O 64-bit Binary (Little Endian)",
    },
    FileSignature {
        name: "BMP Image",
        magic: b"BM",
        extension: "bmp",
        description: "Windows Bitmap",
    },
    FileSignature {
        name: "RIFF Container",
        magic: b"RIFF",
        extension: "riff",
        description: "RIFF Container (WAV/AVI/etc.)",
    },
    FileSignature {
        name: "MP3 Audio with ID3",
        magic: b"ID3",
        extension: "mp3",
        description: "MP3 Audio File with ID3v2 Tag",
    },
    FileSignature {
        name: "FLAC Audio",
        magic: b"fLaC",
        extension: "flac",
        description: "FLAC Lossless Audio",
    },
    FileSignature {
        name: "ISOBMFF Container",
        magic: b"ftyp",
        extension: "mp4",
        description: "ISO Base Media File Format (MP4/MOV)",
    },
    FileSignature {
        name: "OLE2 Compound Document",
        magic: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        extension: "ole",
        description: "OLE2 Compound Document",
    },
    FileSignature {
        name: "TIFF Image",
        magic: b"II\x2A\x00",
        extension: "tiff",
        description: "TIFF Image (Little Endian)",
    },
    FileSignature {
        name: "TIFF Image",
        magic: b"MM\x00\x2A",
        extension: "tiff",
        description: "TIFF Image (Big Endian)",
    },
    FileSignature {
        name: "ICO Icon",
        magic: b"\x00\x00\x01\x00",
        extension: "ico",
        description: "Windows Icon",
    },
];

pub struct FileMatch {
    pub offset: usize,
    pub signature: &'static FileSignature,
}

pub fn locate_file_end(data: &[u8], offset: usize, signature: &FileSignature) -> Option<usize> {
    if offset >= data.len() {
        return None;
    }

    match signature.extension {
        "png" => find_subsequence(data, offset, b"\x00\x00\x00\x00IEND\xAE\x42\x60\x82")
            .map(|end| end + 12),
        "jpg" => {
            find_subsequence(data, offset + signature.magic.len(), &[0xFF, 0xD9]).map(|end| end + 2)
        }
        "gif" => data[offset + signature.magic.len()..]
            .iter()
            .position(|&b| b == 0x3B)
            .map(|pos| offset + signature.magic.len() + pos + 1),
        "pdf" => find_subsequence(data, offset + signature.magic.len(), b"%%EOF").map(|end| {
            let mut cursor = end + 5;
            while cursor < data.len() && matches!(data[cursor], b'\r' | b'\n' | b' ' | b'\t') {
                cursor += 1;
            }
            cursor
        }),
        "zip" => find_subsequence(
            data,
            offset + signature.magic.len(),
            &[0x50, 0x4B, 0x05, 0x06],
        )
        .and_then(|eocd| {
            if eocd + 22 <= data.len() {
                let comment_len = u16::from_le_bytes([data[eocd + 20], data[eocd + 21]]) as usize;
                Some((eocd + 22 + comment_len).min(data.len()))
            } else {
                None
            }
        }),
        _ => None,
    }
}

pub fn identify_file_signature(data: &[u8]) -> Option<&'static FileSignature> {
    FILE_SIGNATURES
        .iter()
        .find(|sig| has_signature_at(data, 0, sig))
        .or_else(|| {
            // Check for ISOBMFF/MP4 at offset 4 (ftyp box)
            if data.len() >= 8 && &data[4..8] == b"ftyp" {
                FILE_SIGNATURES.iter().find(|sig| sig.extension == "mp4")
            } else {
                None
            }
        })
}

pub fn scan_for_signatures(data: &[u8]) -> Vec<FileMatch> {
    let mut matches = Vec::new();
    // Optimization: Aho-Corasick would be better for many signatures, but for now simple iteration is okay given the count
    // or just checking at every byte. Checking every byte against all signatures is O(N*M). N=filesize, M=sigs.
    // M is small (~15). N can be large.

    // We'll use a simple sliding window check for now.

    for i in 0..data.len() {
        for sig in FILE_SIGNATURES {
            if has_signature_at(data, i, sig) {
                matches.push(FileMatch {
                    offset: i,
                    signature: sig,
                });
            }
        }
    }

    // Filter overlaps? Or just return all?
    // User wants hidden stuff.
    matches
}

fn find_subsequence(data: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start >= data.len() || needle.len() > data.len().saturating_sub(start) {
        return None;
    }

    data[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|pos| start + pos)
}

fn has_signature_at(data: &[u8], offset: usize, signature: &FileSignature) -> bool {
    if data.len().saturating_sub(offset) < signature.magic.len()
        || &data[offset..offset + signature.magic.len()] != signature.magic
    {
        return false;
    }

    match signature.extension {
        "exe" => validate_pe_signature(data, offset),
        "sqlite" => data.len().saturating_sub(offset) >= 100,
        _ => true,
    }
}

fn validate_pe_signature(data: &[u8], offset: usize) -> bool {
    if data.len().saturating_sub(offset) < 0x40 {
        return false;
    }

    let pe_pointer = offset + 0x3C;
    let Some(pointer_bytes) = data.get(pe_pointer..pe_pointer + 4) else {
        return false;
    };
    let pe_offset = u32::from_le_bytes([
        pointer_bytes[0],
        pointer_bytes[1],
        pointer_bytes[2],
        pointer_bytes[3],
    ]) as usize;
    let pe_header = match offset.checked_add(pe_offset) {
        Some(value) => value,
        None => return false,
    };

    matches!(data.get(pe_header..pe_header + 4), Some(b"PE\0\0"))
}

pub fn get_stego_signatures() -> Vec<Signature> {
    vec![
        Signature {
            name: "Whitespace Steganography".to_string(),
            description: "Hidden data in trailing spaces/tabs".to_string(),
            pattern: r"[ \t]+$".to_string(),
            detection_type: DetectionType::Stego,
            confidence_weight: 0.8,
            common_name: Some("whitespace_stego".to_string()),
            hashcat_mode: None,
            john_format: None,
            security_rating: None,
            compliance_refs: vec![],
            parameters: vec![],
        },
        Signature {
            name: "Zero-Width Obfuscation".to_string(),
            description: "Hidden data using non-visible Unicode characters".to_string(),
            pattern: r"[\u200B-\u200D\uFEFF]".to_string(),
            detection_type: DetectionType::Stego,
            confidence_weight: 0.9,
            common_name: Some("zwsp".to_string()),
            hashcat_mode: None,
            john_format: None,
            security_rating: None,
            compliance_refs: vec![],
            parameters: vec![],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::{FILE_SIGNATURES, identify_file_signature, locate_file_end, scan_for_signatures};

    #[test]
    fn locates_png_end_marker() {
        let png = b"\x89PNG\r\n\x1a\nabcd\x00\x00\x00\x00IEND\xAE\x42\x60\x82tail";
        let signature = FILE_SIGNATURES
            .iter()
            .find(|sig| sig.extension == "png")
            .unwrap();

        let end = locate_file_end(png, 0, signature).unwrap();
        assert_eq!(end, 24);
    }

    #[test]
    fn validates_pe_headers_before_reporting_executable() {
        let mut pe = vec![0u8; 256];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");

        let identified = identify_file_signature(&pe).unwrap();
        assert_eq!(identified.extension, "exe");

        let matches = scan_for_signatures(&pe);
        assert_eq!(
            matches
                .iter()
                .filter(|m| m.signature.extension == "exe")
                .count(),
            1
        );

        let fake = b"MZnot-a-real-pe";
        assert!(identify_file_signature(fake).is_none());
    }
}
