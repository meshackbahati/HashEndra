//! TLS cipher suite lookup (offline knowledge, not negotiation).
//!
//! Covers the suites seen in practice: all five TLS 1.3 suites, common
//! TLS 1.2 ECDHE/DHE/RSA suites, legacy RC4/3DES/DES for identification,
//! the SCSV sentinels, and GREASE values. Source: IANA TLS Parameters
//! registry, curated — unknown codes report as unknown, never guessed.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteRating {
    Secure,
    Weak,
    Broken,
}

pub struct TlsSuite {
    pub code: u16,
    pub name: &'static str,
    pub rating: SuiteRating,
    pub note: &'static str,
}

pub const TLS_SUITES: &[TlsSuite] = &[
    // TLS 1.3 (no key exchange in the suite; PFS always).
    suite(0x1301, "TLS_AES_128_GCM_SHA256", Secure, "TLS 1.3 default"),
    suite(0x1302, "TLS_AES_256_GCM_SHA384", Secure, "TLS 1.3"),
    suite(0x1303, "TLS_CHACHA20_POLY1305_SHA256", Secure, "TLS 1.3, no AES hardware needed"),
    suite(0x1304, "TLS_AES_128_CCM_SHA256", Secure, "TLS 1.3 constrained radios"),
    suite(0x1305, "TLS_AES_128_CCM_8_SHA256", Secure, "TLS 1.3 short tags"),
    // ECDHE + GCM/ChaCha (TLS 1.2, fine with PFS).
    suite(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", Secure, ""),
    suite(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Secure, "most common 1.2 suite"),
    suite(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", Secure, ""),
    suite(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Secure, ""),
    suite(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Secure, ""),
    suite(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", Secure, ""),
    suite(0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Secure, ""),
    suite(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", Secure, ""),
    suite(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", Secure, ""),
    // ECDHE + CBC (lucky13 history; prefer GCM).
    suite(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Weak, "CBC in TLS: lucky13 class"),
    suite(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", Weak, ""),
    // DHE + CBC.
    suite(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", Weak, ""),
    suite(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", Weak, ""),
    suite(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", Weak, ""),
    suite(0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", Weak, ""),
    // Plain RSA key exchange (no forward secrecy).
    suite(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", Weak, "no forward secrecy"),
    suite(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", Weak, "no forward secrecy"),
    suite(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", Weak, "no forward secrecy"),
    suite(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", Weak, "no forward secrecy"),
    suite(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256", Weak, ""),
    suite(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", Weak, ""),
    // Legacy: RC4, 3DES, DES, export.
    suite(0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", Broken, "RC4 is broken"),
    suite(0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", Broken, "RC4 is broken"),
    suite(0x0005, "TLS_RSA_WITH_RC4_128_SHA", Broken, "RC4, no PFS"),
    suite(0x0004, "TLS_RSA_WITH_RC4_128_MD5", Broken, "RC4 + MD5"),
    suite(0x0002, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", Broken, "export-grade, FREAK class"),
    suite(0x0009, "TLS_RSA_WITH_DES40_CBC_SHA", Broken, "export-grade DES"),
    suite(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", Broken, "3DES: Sweet32, 64-bit blocks"),
    suite(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Broken, "Sweet32, no PFS"),
    // Sentinels, not real suites.
    suite(0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", Secure, "secure-renegotiation sentinel"),
    suite(0x5600, "TLS_FALLBACK_SCSV", Secure, "downgrade-protection sentinel"),
];

use SuiteRating::{Broken, Secure, Weak};

const fn suite(code: u16, name: &'static str, rating: SuiteRating, note: &'static str) -> TlsSuite {
    TlsSuite { code, name, rating, note }
}

/// Look up a suite by code. Accepts "1301", "0x1301", "13 01".
pub fn lookup_tls_suite(input: &str) -> Option<&'static TlsSuite> {
    let stripped = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    let hex: String = stripped
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.len() != 4 {
        return None;
    }
    let code = u16::from_str_radix(&hex, 16).ok()?;
    if is_grease(code) {
        return None;
    }
    TLS_SUITES.iter().find(|s| s.code == code)
}

/// GREASE values (RFC 8701): both bytes equal, low nibble 0xA. Not real suites.
pub fn is_grease(code: u16) -> bool {
    code & 0x0F0F == 0x0A0A && code >> 8 == code & 0xFF
}

pub fn rating_name(rating: SuiteRating) -> &'static str {
    match rating {
        SuiteRating::Secure => "secure",
        SuiteRating::Weak => "weak",
        SuiteRating::Broken => "broken",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_suites_resolve() {
        assert_eq!(lookup_tls_suite("0x1301").unwrap().name, "TLS_AES_128_GCM_SHA256");
        assert_eq!(lookup_tls_suite("c02f").unwrap().name, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        assert_eq!(lookup_tls_suite("0005").unwrap().rating, Broken);
        assert_eq!(lookup_tls_suite("00ff").unwrap().name, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
    }

    #[test]
    fn grease_and_unknown_are_not_suites() {
        assert!(is_grease(0x0A0A));
        assert!(is_grease(0xFAFA));
        assert!(!is_grease(0x1301));
        assert!(lookup_tls_suite("0a0a").is_none());
        assert!(lookup_tls_suite("ffff").is_none());
        assert!(lookup_tls_suite("13").is_none());
    }
}
