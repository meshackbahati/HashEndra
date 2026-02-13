#[cfg(test)]
mod tests {
    use hashendra::core::patterns::scan_input;
    use hashendra::core::scanner::{calculate_entropy, detect_charset, Charset};

    #[test]
    fn test_md5_detection() {
        let input = "5f4dcc3b5aa765d61d8327deb882cf99";
        let results = scan_input(input);
        assert!(!results.is_empty());
        assert_eq!(results[0].signature.name, "MD5");
        assert!(results[0].confidence > 0.9);
    }

    #[test]
    fn test_ntlm_detection() {
        // NTLM and MD5 have same length and charset, but NTLM has lower weight in patterns.rs
        // unless heuristics distinguish them.
        let input = "5f4dcc3b5aa765d61d8327deb882cf99";
        let results = scan_input(input);
        assert!(results.iter().any(|r| r.signature.name == "NTLM"));
    }

    #[test]
    fn test_base64_detection() {
        let input = "SGVsbG8gV29ybGQ=";
        let results = scan_input(input);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.signature.name == "Base64"));
    }

    #[test]
    fn test_jwt_detection() {
        let input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoyNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let results = scan_input(input);
        assert!(!results.is_empty());
        assert_eq!(results[0].signature.name, "JWT");
        assert_eq!(results[0].confidence, 1.0);
    }

    #[test]
    fn test_entropy() {
        let input = "aaaaa";
        let ent = calculate_entropy(input.as_bytes());
        assert_eq!(ent, 0.0);

        let input_rand = "5f4dcc3b5aa765d61d8327deb882cf99";
        let ent_rand = calculate_entropy(input_rand.as_bytes());
        assert!(ent_rand > 3.0);
    }

    #[test]
    fn test_charset() {
        assert_eq!(detect_charset("abc123"), Charset::Hex);
        assert_eq!(detect_charset("SGVsbG8="), Charset::Base64);
        assert_eq!(detect_charset("1AbcFgh"), Charset::Base58); // Contains 'G', 'h' which are NOT hex
    }
}
