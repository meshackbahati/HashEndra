use super::workshop::workshop_set_current;
use hashendra::safe_println;

/// Cipher decode commands (`/vigenere` … `/substitution`).
/// Returns true when `cmd` is one of ours.
pub(crate) fn run_cipher_command(
    cmd: &str,
    parts: &[&str],
    current: &mut String,
    history: &mut Vec<String>,
) -> bool {
    match cmd {
        "/vigenere" => {
            use hashendra::detectors::classic_ciphers::vigenere_decode;
            if parts.len() > 1 {
                workshop_set_current(
                    "Vigenere decoded",
                    vigenere_decode(current, parts[1]),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /vigenere <key>");
            }
        }
        "/beaufort" => {
            use hashendra::detectors::classic_vigenere::beaufort_crypt;
            if parts.len() > 1 {
                workshop_set_current(
                    "Beaufort decoded",
                    beaufort_crypt(current, parts[1]),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /beaufort <key>");
            }
        }
        "/autokey" => {
            use hashendra::detectors::classic_vigenere::autokey_decrypt;
            if parts.len() > 1 {
                workshop_set_current(
                    "Autokey decoded",
                    autokey_decrypt(current, parts[1]),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /autokey <key>");
            }
        }
        "/gronsfeld" => {
            use hashendra::detectors::classic_vigenere::gronsfeld_decrypt;
            if parts.len() > 1 {
                workshop_set_current(
                    "Gronsfeld decoded",
                    gronsfeld_decrypt(current, parts[1]),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /gronsfeld <digits>");
            }
        }
        "/porta" => {
            use hashendra::detectors::classic_vigenere::porta_crypt;
            if parts.len() > 1 {
                workshop_set_current(
                    "Porta decoded",
                    porta_crypt(current, parts[1]),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /porta <key>");
            }
        }
        "/affine" => {
            use hashendra::detectors::classic_ciphers::affine_decrypt;
            if parts.len() > 2 {
                match (
                    parts[1].parse::<u8>(),
                    parts[2].parse::<u8>(),
                ) {
                    (Ok(a), Ok(b)) => match affine_decrypt(current, a, b) {
                        Some(text) => workshop_set_current(
                            "Affine decoded",
                            text,
                            &mut *current,
                            &mut *history,
                        ),
                        None => safe_println!("  [FAIL] Invalid 'a' (needs inverse mod 26)."),
                    },
                    _ => safe_println!("  [FAIL] Usage: /affine <a> <b>"),
                }
            } else {
                safe_println!("  [FAIL] Usage: /affine <a> <b>");
            }
        }
        "/atbash" => {
            use hashendra::detectors::classic_ciphers::atbash_crypt;
            workshop_set_current(
                "Atbash decoded",
                atbash_crypt(current),
                &mut *current,
                &mut *history,
            );
        }
        "/rail" => {
            use hashendra::detectors::classic_transposition::rail_fence_decode;
            if parts.len() > 1 {
                match parts[1].parse::<usize>() {
                    Ok(rails) => workshop_set_current(
                        "Rail Fence decoded",
                        rail_fence_decode(current, rails),
                        &mut *current,
                        &mut *history,
                    ),
                    Err(_) => safe_println!("  [FAIL] Usage: /rail <n>"),
                }
            } else {
                safe_println!("  [FAIL] Usage: /rail <n>");
            }
        }
        "/columnar" => {
            use hashendra::detectors::classic_transposition::{columnar_decode, columnar_order};
            if parts.len() > 1 {
                workshop_set_current(
                    "Columnar decoded",
                    columnar_decode(current, &columnar_order(parts[1])),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /columnar <key>");
            }
        }
        "/polybius" => {
            use hashendra::detectors::classic_squares::polybius_decrypt;
            let key = parts.get(1).copied().unwrap_or("");
            workshop_set_current(
                "Polybius decoded",
                polybius_decrypt(current, key),
                &mut *current,
                &mut *history,
            );
        }
        "/tap" => {
            use hashendra::detectors::classic_squares::tap_decode;
            workshop_set_current(
                "Tap decoded",
                tap_decode(current),
                &mut *current,
                &mut *history,
            );
        }
        "/adfgx" => {
            use hashendra::detectors::classic_squares::adfgx_decrypt;
            if parts.len() > 2 {
                workshop_set_current(
                    "ADFGX decoded",
                    adfgx_decrypt(current, parts[1], parts[2]),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /adfgx <square-key> <column-key>");
            }
        }
        "/adfgvx" => {
            use hashendra::detectors::classic_squares::adfgvx_decrypt;
            if parts.len() > 2 {
                workshop_set_current(
                    "ADFGVX decoded",
                    adfgvx_decrypt(current, parts[1], parts[2]),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /adfgvx <square-key> <column-key>");
            }
        }
        "/foursquare" => {
            use hashendra::detectors::classic_squares::four_square_decrypt;
            if parts.len() > 2 {
                workshop_set_current(
                    "Four-Square decoded",
                    four_square_decrypt(current, parts[1], parts[2]),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /foursquare <k1> <k2>");
            }
        }
        "/twosquare" => {
            use hashendra::detectors::classic_squares::two_square_decrypt;
            if parts.len() > 2 {
                workshop_set_current(
                    "Two-Square decoded",
                    two_square_decrypt(current, parts[1], parts[2]),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /twosquare <k1> <k2>");
            }
        }
        "/trifid" => {
            use hashendra::detectors::classic_squares::trifid_decrypt;
            if parts.len() > 1 {
                let period = parts
                    .get(2)
                    .and_then(|p| p.parse::<usize>().ok())
                    .unwrap_or(5);
                workshop_set_current(
                    "Trifid decoded",
                    trifid_decrypt(current, parts[1], period),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /trifid <key> [period]");
            }
        }
        "/playfair" => {
            use hashendra::detectors::classic_playfair::playfair_decode;
            if parts.len() > 1 {
                workshop_set_current(
                    "Playfair decoded",
                    playfair_decode(current, parts[1]),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /playfair <key>");
            }
        }
        "/bifid" => {
            use hashendra::detectors::classic_playfair::bifid_decrypt;
            if parts.len() > 1 {
                let period = parts
                    .get(2)
                    .and_then(|p| p.parse::<usize>().ok())
                    .unwrap_or(5);
                workshop_set_current(
                    "Bifid decoded",
                    bifid_decrypt(current, parts[1], period),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /bifid <key> [period]");
            }
        }
        "/bacon" => {
            use hashendra::detectors::classic_ciphers::bacon_decode;
            let alphabet = parts.get(1).copied().unwrap_or("AB");
            let mut chars = alphabet.chars();
            let (a, b) = (chars.next().unwrap_or('A'), chars.next().unwrap_or('B'));
            match bacon_decode(current, a, b) {
                Some(text) => workshop_set_current(
                    "Bacon decoded",
                    text,
                    &mut *current,
                    &mut *history,
                ),
                None => safe_println!("  [FAIL] Not valid Baconian text."),
            }
        }
        "/substitution" => {
            use hashendra::detectors::classic_ciphers::simple_substitution_decode;
            if parts.len() > 1 && parts[1].len() == 26 {
                let map: std::collections::HashMap<char, char> = parts[1]
                    .to_ascii_uppercase()
                    .chars()
                    .enumerate()
                    .map(|(i, cipher)| (cipher, (b'A' + i as u8) as char))
                    .collect();
                workshop_set_current(
                    "Substitution decoded",
                    simple_substitution_decode(current, &map),
                    &mut *current,
                    &mut *history,
                );
            } else {
                safe_println!("  [FAIL] Usage: /substitution <26-letter cipher alphabet>");
            }
        }
        _ => return false,
    }
    true
}
