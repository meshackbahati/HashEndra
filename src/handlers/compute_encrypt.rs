use super::{hex_bytes, hex_key, hex_key_iv, hex_of, hex_rsa_pair};
use colored::*;
use hashendra::safe_println;

pub(crate) fn print_encryption_ciphers() {
    safe_println!("{}", "Supported ciphers (encrypt + decrypt):".blue().bold());
    for cipher in &[
        "caesar", "atbash", "vigenere", "beaufort", "autokey", "gronsfeld", "porta",
        "rail-fence", "columnar", "polybius", "tap", "adfgx", "adfgvx",
        "four-square", "two-square", "trifid", "playfair", "bifid",
        "bacon", "substitution", "xor", "aes-cbc", "aes-ecb", "rsa", "rsa-keygen",
    ] {
        safe_println!("  - {}", cipher);
    }
    safe_println!("Key formats: --key SHIFT | keyword | a,b | K1,K2 | 2-char alphabet; --cipher-param for rails/period/column key.");
}

use super::{split_key, split_key_or_param, str_key, substitution_map};

pub(crate) fn handle_encrypt(
    input: &str,
    cipher: &str,
    key: &Option<String>,
    param: &Option<String>,
) -> bool {
    use hashendra::core::scanner::*;
    use hashendra::detectors::classic_ciphers::*;
    use hashendra::detectors::classic_playfair::*;
    use hashendra::detectors::classic_squares::*;
    use hashendra::detectors::classic_vigenere::*;

    safe_println!("{}", "\n── Encrypted Output ──".green().bold());
    let result = match cipher {
        "caesar" | "rot" => {
            let shift = key.as_deref().and_then(|k| k.parse::<u8>().ok()).unwrap_or(3);
            Some(caesar_encrypt(input, shift))
        }
        "atbash" => Some(atbash_crypt(input)),
        "vigenere" => {
            let k = str_key(key, "key");
            Some(vigenere_encrypt(input, &k))
        }
        "beaufort" => {
            let k = str_key(key, "key");
            Some(beaufort_crypt(input, &k))
        }
        "autokey" => {
            let k = str_key(key, "key");
            Some(autokey_encrypt(input, &k))
        }
        "gronsfeld" => {
            let k = str_key(key, "2015");
            Some(gronsfeld_encrypt(input, &k))
        }
        "porta" => {
            let k = str_key(key, "key");
            Some(porta_crypt(input, &k))
        }
        "affine" => {
            let parts: Vec<&str> = key.as_deref().unwrap_or("5,8").split(',').collect();
            let a = parts.first().and_then(|s| s.parse::<u8>().ok()).unwrap_or(5);
            let b = parts.get(1).and_then(|s| s.parse::<u8>().ok()).unwrap_or(8);
            affine_encrypt(input, a, b)
        }
        "rail-fence" | "railfence" => {
            let rails = param
                .as_deref()
                .or(key.as_deref())
                .and_then(|k| k.parse::<usize>().ok())
                .unwrap_or(3);
            Some(rail_fence_encrypt(input, rails))
        }
        "columnar" => {
            let k = str_key(key, "key");
            Some(columnar_encrypt(input, &k))
        }
        "polybius" => {
            let k = key.clone().unwrap_or_default();
            Some(polybius_encrypt(input, &k))
        }
        "tap" => Some(tap_encode(input)),
        "adfgx" => {
            let (sq, col) = split_key_or_param(key, param, "KEY");
            Some(adfgx_encrypt(input, &sq, &col))
        }
        "adfgvx" => {
            let (sq, col) = split_key_or_param(key, param, "KEY");
            Some(adfgvx_encrypt(input, &sq, &col))
        }
        "four-square" | "foursquare" => {
            let (k1, k2) = split_key(key);
            Some(four_square_encrypt(input, &k1, &k2))
        }
        "two-square" | "twosquare" => {
            let (k1, k2) = split_key(key);
            Some(two_square_encrypt(input, &k1, &k2))
        }
        "trifid" => {
            let k = str_key(key, "key");
            let period = param
                .as_deref()
                .and_then(|p| p.parse::<usize>().ok())
                .unwrap_or(5);
            Some(trifid_encrypt(input, &k, period))
        }
        "playfair" => {
            let k = str_key(key, "key");
            Some(playfair_encrypt(input, &k))
        }
        "bifid" => {
            let k = str_key(key, "key");
            let period = param
                .as_deref()
                .and_then(|p| p.parse::<usize>().ok())
                .unwrap_or(5);
            Some(bifid_encrypt(input, &k, period))
        }
        "bacon" => {
            let alphabet = str_key(key, "AB");
            let mut chars = alphabet.chars();
            let (a, b) = (chars.next().unwrap_or('A'), chars.next().unwrap_or('B'));
            Some(bacon_encode(input, a, b))
        }
        "substitution" => {
            let alphabet = str_key(key, "QWERTYUIOPASDFGHJKLZXCVBNM");
            match substitution_map(&alphabet) {
                Some(map) => Some(simple_substitution_encrypt(input, &map)),
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
            let encrypted = xor_encrypt(input.as_bytes(), &k);
            let hex = encrypted.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            Some(hex)
        }
        "aes-cbc" => {
            let (k, iv) = match hex_key_iv(key, param) {
                Some(pair) => pair,
                None => return false,
            };
            match hashendra::core::symmetric::aes_cbc_encrypt(&k, &iv, input.as_bytes()) {
                Ok(ct) => Some(hex_of(&ct)),
                Err(e) => {
                    safe_println!("{} {}", "[ERROR]".red().bold(), e);
                    return false;
                }
            }
        }
        "aes-ecb" => {
            let k = match hex_key(key) {
                Some(k) => k,
                None => return false,
            };
            match hashendra::core::symmetric::aes_ecb_encrypt(&k, input.as_bytes()) {
                Ok(ct) => Some(hex_of(&ct)),
                Err(e) => {
                    safe_println!("{} {}", "[ERROR]".red().bold(), e);
                    return false;
                }
            }
        }
        "rsa" => {
            let (n, e) = match hex_rsa_pair(key, "n-hex,e-hex") {
                Some(pair) => pair,
                None => return false,
            };
            let m = match hex_bytes(input, "message hex") {
                Some(bytes) => bytes,
                None => return false,
            };
            match hashendra::core::rsa::rsa_encrypt(&m, &e, &n) {
                Ok(c) => Some(hex_of(&c)),
                Err(e) => {
                    safe_println!("{} {}", "[ERROR]".red().bold(), e);
                    return false;
                }
            }
        }
        "rsa-keygen" => {
            let bits = param
                .as_deref()
                .or(key.as_deref())
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(512);
            match hashendra::core::rsa::rsa_keygen(bits, 12) {
                Ok((n, e, d)) => Some(format!(
                    "n={}\ne={}\nd={}",
                    hex_of(&n.to_bytes_be()),
                    hex_of(&e.to_bytes_be()),
                    hex_of(&d.to_bytes_be())
                )),
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
                "{} Encryption failed. Check parameters.",
                "[ERROR]".red().bold()
            );
            false
        }
    }
}
