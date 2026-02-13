use crate::core::patterns::{Signature, DetectionType};

pub struct FileSignature {
    pub name: &'static str,
    pub magic: &'static [u8],
    pub extension: &'static str,
    pub description: &'static str,
}

pub const FILE_SIGNATURES: &[FileSignature] = &[
    FileSignature { name: "JPEG Image", magic: &[0xFF, 0xD8, 0xFF], extension: "jpg", description: "JPEG Image" },
    FileSignature { name: "PNG Image", magic: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], extension: "png", description: "Portable Network Graphics" },
    FileSignature { name: "GIF Image", magic: &[0x47, 0x49, 0x46, 0x38], extension: "gif", description: "GIF Image" },
    FileSignature { name: "ZIP Archive", magic: &[0x50, 0x4B, 0x03, 0x04], extension: "zip", description: "ZIP Archive (Standard)" },
    FileSignature { name: "ZIP Archive (Empty)", magic: &[0x50, 0x4B, 0x05, 0x06], extension: "zip", description: "ZIP Archive (Empty)" },
    FileSignature { name: "ZIP Archive (Spanned)", magic: &[0x50, 0x4B, 0x07, 0x08], extension: "zip", description: "ZIP Archive (Spanned)" },
    FileSignature { name: "RAR Archive", magic: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00], extension: "rar", description: "RAR Archive" },
    FileSignature { name: "RAR Archive v5", magic: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00], extension: "rar", description: "RAR Archive v5" },
    FileSignature { name: "7z Archive", magic: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], extension: "7z", description: "7-Zip Archive" },
    FileSignature { name: "PDF Document", magic: &[0x25, 0x50, 0x44, 0x46, 0x2D], extension: "pdf", description: "PDF Document" },
    FileSignature { name: "ELF Binary", magic: &[0x7F, 0x45, 0x4C, 0x46], extension: "elf", description: "Linux ELF Binary" },
];

pub struct FileMatch {
    pub offset: usize,
    pub signature: &'static FileSignature,
}

pub fn scan_for_signatures(data: &[u8]) -> Vec<FileMatch> {
    let mut matches = Vec::new();
    // Optimization: Aho-Corasick would be better for many signatures, but for now simple iteration is okay given the count
    // or just checking at every byte. Checking every byte against all signatures is O(N*M). N=filesize, M=sigs.
    // M is small (~15). N can be large. 
    
    // We'll use a simple sliding window check for now.
    
    for i in 0..data.len() {
        for sig in FILE_SIGNATURES {
            if data.len() - i >= sig.magic.len() {
                if &data[i..i+sig.magic.len()] == sig.magic {
                     // specific check for EXE since MZ is common in random data, usually followed by other stuff but hard to check without more logic
                     // For now we accept it but maybe we should filter if it's too frequent?
                     // Actually MZ is very short (2 bytes). Might have false positives.
                     if sig.extension == "exe" && i + 0x3c < data.len() {
                         // Check for PE header pointer? Just basic check.
                     }
                     
                    matches.push(FileMatch {
                        offset: i,
                        signature: sig,
                    });
                }
            }
        }
    }
    
    // Filter overlaps? Or just return all?
    // User wants hidden stuff.
    matches
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
