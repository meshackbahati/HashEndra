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
