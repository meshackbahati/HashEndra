use crate::core::patterns::{Signature, DetectionType};

pub fn get_cipher_signatures() -> Vec<Signature> {
    vec![
        Signature {
            name: "Caesar / ROT".to_string(),
            description: "Shift cipher (ROT13/Caesar)".to_string(),
            pattern: r"^[A-Za-z\s.,!?]+$".to_string(),
            detection_type: DetectionType::Cipher,
            confidence_weight: 0.2,
            common_name: Some("caesar".to_string()),
            hashcat_mode: None,
            john_format: None,
            security_rating: None,
            compliance_refs: vec![],
            parameters: vec![],
        },
        Signature {
            name: "Vigenère".to_string(),
            description: "Polyalphabetic substitution cipher".to_string(),
            pattern: r"^[A-Za-z\s.,!?]{15,}$".to_string(),
            detection_type: DetectionType::Cipher,
            confidence_weight: 0.1,
            common_name: Some("vigenere".to_string()),
            hashcat_mode: None,
            john_format: None,
            security_rating: None,
            compliance_refs: vec![],
            parameters: vec![],
        },
    ]
}
