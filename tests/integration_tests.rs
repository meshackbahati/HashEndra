use hashendra::core::patterns::{ScanningContext, scan_input};
use hashendra::core::scanner::{
    Charset, calculate_entropy, decode_ascii85, decode_base64, decode_base64_url, decode_binary,
    decode_hex, decode_html_entities, decode_morse, decode_octal, decode_quoted_printable,
    detect_charset,
};

#[test]
fn md5_is_ranked_above_other_32_hex_matches() {
    let input = "5f4dcc3b5aa765d61d8327deb882cf99";
    let results = scan_input(input, ScanningContext::Generic);

    assert!(!results.is_empty());
    assert_eq!(results[0].name, "MD5");

    let ntlm_confidence = results
        .iter()
        .find(|result| result.name == "NTLM")
        .map(|result| result.confidence)
        .unwrap_or(0.0);
    assert!(results[0].confidence > ntlm_confidence);
}

#[test]
fn base64_detection_requires_valid_payload() {
    let input = "SGVsbG8gV29ybGQ=";
    let results = scan_input(input, ScanningContext::Generic);

    assert!(results.iter().any(|result| result.name == "Base64"));
    assert_eq!(decode_base64(input), Some(b"Hello World".to_vec()));
}

#[test]
fn jwt_detection_requires_json_header_and_payload() {
    let valid =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.c2ln";
    let invalid = "aaa.bbb.ccc";

    let valid_results = scan_input(valid, ScanningContext::Generic);
    let invalid_results = scan_input(invalid, ScanningContext::Generic);

    assert_eq!(valid_results[0].name, "JWT");
    assert!(invalid_results.iter().all(|result| result.name != "JWT"));
}

#[test]
fn decode_helpers_reject_malformed_inputs() {
    assert_eq!(decode_hex("414243"), Some(b"ABC".to_vec()));
    assert_eq!(decode_hex("41424"), None);
    assert_eq!(decode_base64("QUJD"), Some(b"ABC".to_vec()));
    assert_eq!(decode_base64("QUJD="), None);
    assert_eq!(
        decode_base64_url("eyJmb28iOiJiYXIifQ"),
        Some(br#"{"foo":"bar"}"#.to_vec())
    );
}

#[test]
fn added_encoding_decoders_handle_common_cases() {
    assert_eq!(decode_binary("0b01001000 0b01101001"), Some(b"Hi".to_vec()));
    assert_eq!(decode_hex("\\x48\\x69"), Some(b"Hi".to_vec()));
    assert_eq!(decode_octal("110 151"), Some(b"Hi".to_vec()));
    assert_eq!(
        decode_quoted_printable("Hello=20World"),
        Some(b"Hello World".to_vec())
    );
    assert_eq!(
        decode_html_entities("Tom &amp; Jerry"),
        Some("Tom & Jerry".to_string())
    );
    assert_eq!(
        decode_morse(".... . .-.. .-.. ---"),
        Some("HELLO".to_string())
    );
    assert_eq!(decode_ascii85("<~z~>"), Some(vec![0, 0, 0, 0]));
}

#[test]
fn plaintext_is_not_reported_as_high_confidence_ciphertext() {
    let input = "hello world from hashendra";
    let results = scan_input(input, ScanningContext::Generic);

    assert!(
        results
            .iter()
            .filter(|result| result.name == "Caesar / ROT" || result.name == "Vigenère")
            .all(|result| result.confidence < 0.2)
    );
}

#[test]
fn entropy_still_distinguishes_repetitive_and_randomish_inputs() {
    assert_eq!(calculate_entropy(b"aaaaa"), 0.0);
    assert!(calculate_entropy(b"5f4dcc3b5aa765d61d8327deb882cf99") > 3.0);
}

#[test]
fn charset_detection_prefers_more_specific_matches() {
    assert_eq!(detect_charset("abc123"), Charset::Hex);
    assert_eq!(detect_charset("MFRGGZDFMZTWQ2LK"), Charset::Base32);
    assert_eq!(detect_charset("SGVsbG8="), Charset::Base64);
    assert_eq!(detect_charset("1AbcFgh"), Charset::Base58);
}
