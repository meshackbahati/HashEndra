use super::{hex_arg, hex_key, hex_key_iv, hex_of, hex_rsa_pair, show_bytes};
use super::{split_key, split_key_or_param, str_key, substitution_map};
use colored::*;
use hashendra::safe_println;

pub(crate) fn handle_decrypt(
    input: &str,
    cipher: &str,
    key: &Option<String>,
    param: &Option<String>,
) -> bool {
    use hashendra::core::scanner::*;
    use hashendra::detectors::classic_ciphers::*;
    use hashendra::detectors::classic_playfair::*;
    use hashendra::detectors::classic_squares::*;
    use hashendra::detectors::classic_transposition::*;
    use hashendra::detectors::classic_vigenere::*;

    safe_println!("{}", "\n── Decrypted Output ──".green().bold());
    let result = match cipher {
        "caesar" | "rot" => {
            let shift = key.as_deref().and_then(|k| k.parse::<u8>().ok()).unwrap_or(3);
            Some(caesar_encrypt(input, (26 - shift % 26) % 26))
        }
        "atbash" => Some(atbash_crypt(input)),
        "vigenere" => {
            let k = str_key(key, "key");
            Some(vigenere_decode(input, &k))
        }
        "beaufort" | "porta" => {
            // Self-reciprocal: same call decrypts.
            let k = str_key(key, "key");
            if cipher == "beaufort" {
                Some(beaufort_crypt(input, &k))
            } else {
                Some(porta_crypt(input, &k))
            }
        }
        "autokey" => {
            let k = str_key(key, "key");
            Some(autokey_decrypt(input, &k))
        }
        "gronsfeld" => {
            let k = str_key(key, "2015");
            Some(gronsfeld_decrypt(input, &k))
        }
        "affine" => {
            let parts: Vec<&str> = key.as_deref().unwrap_or("5,8").split(',').collect();
            let a = parts.first().and_then(|s| s.parse::<u8>().ok()).unwrap_or(5);
            let b = parts.get(1).and_then(|s| s.parse::<u8>().ok()).unwrap_or(8);
            affine_decrypt(input, a, b)
        }
        "rail-fence" | "railfence" => {
            let rails = param
                .as_deref()
                .or(key.as_deref())
                .and_then(|k| k.parse::<usize>().ok())
                .unwrap_or(3);
            Some(rail_fence_decode(input, rails))
        }
        "columnar" => {
            let k = str_key(key, "key");
            Some(columnar_decode(input, &columnar_order(&k)))
        }
        "polybius" => {
            let k = key.clone().unwrap_or_default();
            Some(polybius_decrypt(input, &k))
        }
        "tap" => Some(tap_decode(input)),
        "adfgx" => {
            let (sq, col) = split_key_or_param(key, param, "KEY");
            Some(adfgx_decrypt(input, &sq, &col))
        }
        "adfgvx" => {
            let (sq, col) = split_key_or_param(key, param, "KEY");
            Some(adfgvx_decrypt(input, &sq, &col))
        }
        "four-square" | "foursquare" => {
            let (k1, k2) = split_key(key);
            Some(four_square_decrypt(input, &k1, &k2))
        }
        "two-square" | "twosquare" => {
            let (k1, k2) = split_key(key);
            Some(two_square_decrypt(input, &k1, &k2))
        }
        "trifid" => {
            let k = str_key(key, "key");
            let period = param
                .as_deref()
                .and_then(|p| p.parse::<usize>().ok())
                .unwrap_or(5);
            Some(trifid_decrypt(input, &k, period))
        }
        "playfair" => {
            let k = str_key(key, "key");
            Some(playfair_decode(input, &k))
        }
        "bifid" => {
            let k = str_key(key, "key");
            let period = param
                .as_deref()
                .and_then(|p| p.parse::<usize>().ok())
                .unwrap_or(5);
            Some(bifid_decrypt(input, &k, period))
        }
        "bacon" => {
            let alphabet = str_key(key, "AB");
            let mut chars = alphabet.chars();
            let (a, b) = (chars.next().unwrap_or('A'), chars.next().unwrap_or('B'));
            bacon_decode(input, a, b)
        }
        "substitution" => {
            let alphabet = str_key(key, "QWERTYUIOPASDFGHJKLZXCVBNM");
            match substitution_map(&alphabet) {
                Some(enc_map) => {
                    let dec_map: std::collections::HashMap<char, char> =
                        enc_map.into_iter().map(|(plain, cipher)| (cipher, plain)).collect();
                    Some(simple_substitution_decode(input, &dec_map))
                }
                None => {
                    safe_println!(
                        "{} Substitution key must be 26 unique letters.",
                        "[ERROR]".red().bold()
                    );
                    return false;
                }
            }
        }
        "xor" => {
            let k = key.as_deref().unwrap_or("key").as_bytes().to_vec();
            if k.is_empty() {
                safe_println!("{} Key cannot be empty for XOR cipher.", "[ERROR]".red().bold());
                return false;
            }
            // Accept hex (what --encrypt emits) or raw bytes.
            let data = decode_hex_lossy(input);
            let decrypted = xor_encrypt(&data, &k);
            Some(show_bytes(&decrypted))
        }
        "aes-cbc" => {
            let (k, iv) = match hex_key_iv(key, param) {
                Some(pair) => pair,
                None => return false,
            };
            let data = match hex_arg(input, "Ciphertext") {
                Some(bytes) => bytes,
                None => return false,
            };
            match hashendra::core::symmetric::aes_cbc_decrypt(&k, &iv, &data) {
                Ok(pt) => Some(show_bytes(&pt)),
                Err(e) => {
                    safe_println!("{} {}", "[ERROR]".red().bold(), e);
                    return false;
                }
            }
        }
        "aes-ecb" => {
            let (k, data) = match (hex_key(key), hex_arg(input, "Ciphertext")) {
                (Some(k), Some(data)) => (k, data),
                _ => return false,
            };
            match hashendra::core::symmetric::aes_ecb_decrypt(&k, &data) {
                Ok(pt) => Some(show_bytes(&pt)),
                Err(e) => {
                    safe_println!("{} {}", "[ERROR]".red().bold(), e);
                    return false;
                }
            }
        }
        "rsa" => {
            let (n, d) = match hex_rsa_pair(key, "n-hex,d-hex") {
                Some(pair) => pair,
                None => return false,
            };
            let c = match hex_arg(input, "Ciphertext") {
                Some(bytes) => bytes,
                None => return false,
            };
            match hashendra::core::rsa::rsa_decrypt(&c, &d, &n) {
                Ok(m) => Some(hex_of(&m)),
                Err(e) => {
                    safe_println!("{} {}", "[ERROR]".red().bold(), e);
                    return false;
                }
            }
        }
        _ => {
            safe_println!(
                "{} Unknown cipher '{}'. Use --list-ciphers to see supported ciphers.",
                "[ERROR]".red().bold(),
                cipher
            );
            return false;
        }
    };

    match result {
        Some(output) => {
            safe_println!("{}", output);
            true
        }
        None => {
            safe_println!(
                "{} Decryption failed. Check parameters.",
                "[ERROR]".red().bold()
            );
            false
        }
    }
}

/// Hex-decode if possible, else raw bytes (never fails).
fn decode_hex_lossy(input: &str) -> Vec<u8> {
    let clean: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len().is_multiple_of(2) && !clean.is_empty()
        && let Ok(bytes) = (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
    {
        return bytes;
    }
    input.as_bytes().to_vec()
}
