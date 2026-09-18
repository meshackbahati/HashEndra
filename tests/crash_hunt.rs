//! Crash hunt: randomized no-panic property over public decoders, crackers,
//! scanners, and forensic parsers. Deterministic xorshift seed, no new
//! dependencies. Any panic here is a reliability bug — fix the code, keep
//! the input as a regression test.
use hashendra::core::cryptanalysis;
use hashendra::core::encoder;
use hashendra::core::patterns::{scan_input, ScanningContext};
use hashendra::core::recursive_engine::RecursiveEngine;
use hashendra::core::scanner;
use hashendra::detectors::{classic_ciphers, classic_transposition};
use hashendra::forensics::{carve, disk, ext, fat, inspect, ntfs};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const HEX: &[u8] = b"0123456789abcdefABCDEF";
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const PRINTABLE: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;:!?'\"(){}[]<>=+-*/\\|~@#$%^&_";
const BITS: &[u8] = b"01 \t";
const MORSE: &[u8] = b".- /";
const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn gen_string(rng: &mut Rng, max_len: usize) -> String {
    let alphabets: &[&[u8]] = &[HEX, B64, PRINTABLE, BITS, MORSE, B58];
    let alpha = alphabets[rng.below(alphabets.len())];
    let len = rng.below(max_len + 1);
    (0..len).map(|_| alpha[rng.below(alpha.len())] as char).collect()
}

fn gen_bytes(rng: &mut Rng, max_len: usize) -> Vec<u8> {
    let len = rng.below(max_len + 1);
    // Bias toward structured bytes (headers, text) with occasional garbage.
    let structured = rng.below(4) != 0;
    (0..len)
        .map(|_| {
            if structured {
                b"ABCDEFGH0123456789 \x00\xff\x89PNG\r\n\x1a"[rng.below(24)]
            } else {
                rng.below(256) as u8
            }
        })
        .collect()
}

fn exercise_decoders(s: &str) {
    let _ = scanner::decode_base64(s);
    let _ = scanner::decode_base64_url(s);
    let _ = scanner::decode_hex(s);
    let _ = scanner::decode_url(s);
    let _ = scanner::decode_binary(s);
    let _ = scanner::decode_octal(s);
    let _ = scanner::decode_ascii85(s);
    let _ = scanner::decode_quoted_printable(s);
    let _ = scanner::decode_html_entities(s);
    let _ = scanner::decode_morse(s);
    let _ = scanner::decode_base32(s);
    let _ = scanner::decode_base58(s);
    let _ = scanner::rot_brute_force(s);
    let _ = scanner::xor_crack(s.as_bytes());
    let _ = scanner::levenshtein(s, "reference string for distance");
    let _ = scanner::calculate_entropy(s.as_bytes());
    let _ = scanner::detect_charset(s);
    let _ = encoder::encode_quoted_printable(s.as_bytes());
    let _ = encoder::encode_to_format(s, "base64");
    let _ = encoder::encode_to_format(s, "bogus-format");
    let _ = cryptanalysis::chi_squared_score(s);
    let _ = cryptanalysis::calculate_ioc(s);
    let _ = cryptanalysis::contains_english_patterns(s);
}

fn exercise_crackers(s: &str) {
    // Short inputs only: statistical crackers need length floors anyway,
    // and hill-climbing is slow. Correctness under adversarial short input
    // is what we are probing here.
    if s.len() > 48 {
        return;
    }
    let _ = classic_ciphers::caesar_auto_crack(s);
    let _ = classic_ciphers::atbash_decode(s);
    let _ = classic_ciphers::affine_auto_crack(s);
    let _ = classic_ciphers::vigenere_auto_crack(s);
    let _ = classic_ciphers::simple_substitution_auto_crack(s);
    let _ = classic_ciphers::bacon_decode(s, 'A', 'B');
    let _ = classic_ciphers::vigenere_decode(s, "key");
    let _ = classic_transposition::rail_fence_decode(s, 3);
    let _ = classic_transposition::rail_fence_auto_crack(s);
    let _ = classic_transposition::columnar_decode(s, &[0]);
    let _ = classic_transposition::columnar_auto_crack(s);
    let _ = classic_ciphers::simple_substitution_decode(s, &std::collections::HashMap::new());
    exercise_cipher_keyed(s);
}

/// Keyed encrypt/decrypt with hostile keys: empty, non-ASCII, overlong,
/// invalid numbers. Nothing here may panic; garbage in, garbage out.
fn exercise_cipher_keyed(s: &str) {
    use hashendra::core::scanner::codecs;
    use hashendra::detectors::{classic_playfair, classic_squares, classic_vigenere};
    let keys = ["", "K", "a b!", "ünïcodé key 123", "KEYKEYKEYKEYKEYKEYKEYKEY"];
    for key in keys {
        let _ = codecs::caesar_encrypt(s, 0);
        let _ = codecs::caesar_encrypt(s, 255);
        let _ = codecs::vigenere_encrypt(s, key);
        let _ = codecs::affine_encrypt(s, 2, 8);
        let _ = codecs::affine_encrypt(s, 5, 8);
        let _ = classic_ciphers::affine_decrypt(s, 2, 8);
        let _ = classic_ciphers::affine_decrypt(s, 5, 8);
        let _ = codecs::rail_fence_encrypt(s, 0);
        let _ = codecs::rail_fence_encrypt(s, 1);
        let _ = codecs::rail_fence_encrypt(s, 99999);
        let _ = codecs::xor_encrypt(s.as_bytes(), &[]);
        let _ = codecs::xor_encrypt(s.as_bytes(), key.as_bytes());
        let _ = codecs::columnar_encrypt(s, key);
        let _ = classic_transposition::columnar_order(key);
        let _ = classic_vigenere::beaufort_crypt(s, key);
        let _ = classic_vigenere::autokey_encrypt(s, key);
        let _ = classic_vigenere::autokey_decrypt(s, key);
        let _ = classic_vigenere::gronsfeld_encrypt(s, key);
        let _ = classic_vigenere::gronsfeld_decrypt(s, key);
        let _ = classic_vigenere::porta_crypt(s, key);
        let _ = classic_squares::polybius_encrypt(s, key);
        let _ = classic_squares::polybius_decrypt(s, key);
        let _ = classic_squares::tap_encode(s);
        let _ = classic_squares::tap_decode(s);
        let _ = classic_squares::adfgx_encrypt(s, key, key);
        let _ = classic_squares::adfgx_decrypt(s, key, key);
        let _ = classic_squares::adfgvx_encrypt(s, key, key);
        let _ = classic_squares::adfgvx_decrypt(s, key, key);
        let _ = classic_squares::four_square_encrypt(s, key, key);
        let _ = classic_squares::four_square_decrypt(s, key, key);
        let _ = classic_squares::two_square_encrypt(s, key, key);
        let _ = classic_squares::two_square_decrypt(s, key, key);
        let _ = classic_squares::trifid_encrypt(s, key, 5);
        let _ = classic_squares::trifid_decrypt(s, key, 5);
        let _ = classic_squares::trifid_encrypt(s, key, 0);
        let _ = classic_playfair::playfair_encrypt(s, key);
        let _ = classic_playfair::playfair_decode(s, key);
        let _ = classic_playfair::bifid_encrypt(s, key, 5);
        let _ = classic_playfair::bifid_decrypt(s, key, 5);
        let _ = classic_ciphers::bacon_encode(s, 'A', 'B');
        let _ = classic_ciphers::simple_substitution_encrypt(s, &std::collections::HashMap::new());
    }
}

fn exercise_blob(data: &[u8]) {
    let _ = inspect::inspect_data(data);
    let _ = carve::carve_from_bytes(data, None, &carve::CarveOptions::default());
    let _ = disk::inspect_disk_bytes(data, "hunt.bin".to_string(), 512);
    let _ = ntfs::inspect_ntfs_bytes(data, "hunt.bin".to_string(), &ntfs::NtfsOptions::default());
    let _ = ext::inspect_ext_bytes(data, "hunt.bin".to_string(), &ext::ExtOptions::default());
    let _ = fat::inspect_fat_bytes(data, "hunt.bin".to_string(), &fat::FatOptions::default());
}

#[test]
fn hunt_string_inputs() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    // Deliberately modest: the hill-climbing substitution cracker dominates
    // runtime. Coverage comes from alphabet variety, not volume.
    for _ in 0..1200 {
        let s = gen_string(&mut rng, 120);
        exercise_decoders(&s);
        exercise_crackers(&s);
        exercise_cipher_keyed(&s);
        // Non-UTF8-hostile twin: lossy conversion must also survive.
        let lossy = String::from_utf8_lossy(&gen_bytes(&mut rng, 120)).into_owned();
        exercise_decoders(&lossy);
        if lossy.len() <= 48 {
            exercise_crackers(&lossy);
        }
    }
}

#[test]
fn hunt_scan_and_engine() {
    let mut rng = Rng(0xD1B54A32D192ED03);
    let engine = RecursiveEngine::new(10);
    for (i, _) in (0..400).enumerate() {
        let s = gen_string(&mut rng, 60);
        let ctx = match i % 4 {
            0 => ScanningContext::Generic,
            1 => ScanningContext::Network,
            2 => ScanningContext::Database,
            _ => ScanningContext::Filesystem,
        };
        let _ = scan_input(&s, ctx);
        // Engine on a subset: full crack chains are the slowest path.
        if i % 4 == 0 {
            let _ = engine.explore_paths(&s);
        }
    }
}

#[test]
fn hunt_binary_inputs() {
    let mut rng = Rng(0xABC98388FB8FAC03);
    for _ in 0..800 {
        exercise_blob(&gen_bytes(&mut rng, 2048));
    }
    // Edge sizes around sector/record boundaries.
    for &len in &[0, 1, 511, 512, 513, 1023, 1024, 4095, 4096] {
        exercise_blob(&gen_bytes(&mut rng, len));
    }
}
