    use super::*;

    #[test]
    fn max_group_is_rejected_not_overflowed() {
        // 85^5 - 1 exceeds u32; must return None, never panic.
        assert_eq!(decode_ascii85("uuuuu"), None);
    }

    #[test]
    fn roundtrip_hello() {
        let encoded = crate::core::encoder::encode_ascii85(b"Hello, world!");
        let decoded = decode_ascii85(&encoded).unwrap();
        assert_eq!(decoded, b"Hello, world!");
    }

    #[test]
    fn decimal_vectors() {
        assert_eq!(
            decode_decimal("72 101 108 108 111").as_deref(),
            Some(b"Hello".as_slice())
        );
        assert_eq!(
            decode_decimal("71,50,52,123").as_deref(),
            Some(b"G24{".as_slice())
        );
        assert_eq!(decode_decimal("72 300 108"), None);
        assert_eq!(decode_decimal("hello"), None);
        assert_eq!(decode_decimal(""), None);
    }

    #[test]
    fn decimal_number_drift_flag() {
        let input = "71 50 52 123 65 53 67 49 49 68 51 67 49 77 65 76 50 48 50 54 125";
        assert_eq!(
            decode_decimal(input).as_deref(),
            Some(b"G24{A5C11D3C1MAL2026}".as_slice())
        );
    }
