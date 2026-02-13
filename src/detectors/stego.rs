use crate::core::patterns::{Signature, DetectionType};

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
