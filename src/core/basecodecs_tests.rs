    use super::*;

    #[test]
    fn base32hex_rfc_vectors() {
        // RFC 4648 §10, verified against Python's base64.b32hexencode.
        assert_eq!(encode_base32hex(b""), "");
        assert_eq!(encode_base32hex(b"f"), "CO======");
        assert_eq!(encode_base32hex(b"fo"), "CPNG====");
        assert_eq!(encode_base32hex(b"foo"), "CPNMU===");
        assert_eq!(encode_base32hex(b"foob"), "CPNMUOG=");
        assert_eq!(encode_base32hex(b"fooba"), "CPNMUOJ1");
        assert_eq!(encode_base32hex(b"foobar"), "CPNMUOJ1E8======");
        for plain in ["f", "fo", "foo", "foob", "fooba", "foobar"] {
            assert_eq!(decode_base32hex(&encode_base32hex(plain.as_bytes())), Some(plain.as_bytes().to_vec()));
        }
        assert_eq!(decode_base32hex("CPNMUOJ1E8======"), Some(b"foobar".to_vec()));
        assert_eq!(decode_base32hex("!!!"), None);
    }

    #[test]
    fn base58check_roundtrip_and_reject() {
        let (ver, payload) = (0u8, b"hello".to_vec());
        let enc = encode_base58check(ver, &payload);
        assert_eq!(decode_base58check(&enc), Some((0u8, b"hello".to_vec())));
        let mut bad = enc.clone();
        bad.pop();
        bad.push(if bad.ends_with('1') { '2' } else { '1' });
        assert_eq!(decode_base58check(&bad), None);
    }

    #[test]
    fn base62_roundtrip() {
        // Empty encodes to "0", which reads back as a single zero byte.
        assert_eq!(encode_base62(b""), "0");
        for plain in [b"f".as_slice(), b"foo", b"Hello, World!", b"\x00\x00abc"] {
            let enc = encode_base62(plain);
            assert_eq!(decode_base62(&enc).as_deref(), Some(plain), "roundtrip {plain:?}");
        }
        assert_eq!(decode_base62("!!!"), None);
    }

    #[test]
    fn base91_roundtrip() {
        assert_eq!(encode_base91(b""), "");
        for plain in [b"A".as_slice(), b"Hello, World!", b"\x00\xff\x00\xff"] {
            let enc = encode_base91(plain);
            assert!(!enc.is_empty() || plain.is_empty());
            assert_eq!(decode_base91(&enc).as_deref(), Some(plain), "roundtrip {plain:?}");
        }
        assert_eq!(decode_base91("~~~ invalid \x01"), None);
    }

    #[test]
    fn z85_roundtrip_and_lengths() {
        assert_eq!(encode_z85(b"123"), None);
        assert_eq!(decode_z85("abcd"), None);
        for plain in [b"1234".as_slice(), b"0123456789ABCDEF", b"\x00\x00\x00\x00\xff\xff\xff\xff"] {
            let enc = encode_z85(plain).unwrap();
            assert_eq!(decode_z85(&enc).as_deref(), Some(plain));
        }
    }

    #[test]
    fn crockford_roundtrip_and_aliases() {
        let enc = encode_crockford(b"foo");
        let dec = decode_crockford(&enc).unwrap();
        assert_eq!(dec, b"foo");
        // Lowercase, hyphens, and I/L/O aliases decode identically.
        let aliased: String = enc.to_lowercase().chars().flat_map(|c| {
            let s: String = match c {
                '1' => "i".to_string(),
                '0' => "o".to_string(),
                c => format!("{c}-"),
            };
            s.chars().collect::<Vec<_>>()
        }).collect();
        assert_eq!(decode_crockford(&aliased).as_deref(), Some(b"foo".as_slice()));
    }

    #[test]
    fn uu_classic_vector() {
        // The textbook example: "Cat" encodes to "#0V%T".
        assert_eq!(encode_uu(b"Cat"), "#0V%T\n");
        assert_eq!(decode_uu("#0V%T\n").as_deref(), Some(b"Cat".as_slice()));
    }

    #[test]
    fn uu_multiline_roundtrip() {
        let data: Vec<u8> = (0..200).collect();
        let enc = encode_uu(&data);
        assert_eq!(decode_uu(&enc).as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn xx_roundtrip() {
        for plain in [b"Cat".as_slice(), b"Hello, World! This is longer than forty-five bytes................"] {
            assert_eq!(decode_xx(&encode_xx(plain)).as_deref(), Some(plain));
        }
    }
