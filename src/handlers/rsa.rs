use colored::*;
use hashendra::core::rsa_attacks::{common_factor, fermat_factor, hastad_broadcast, wiener_attack};
use hashendra::safe_println;
use num_bigint::BigUint;

fn parse_hex_component(s: &str, what: &str) -> Option<BigUint> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    match BigUint::parse_bytes(clean.as_bytes(), 16) {
        Some(v) if v != BigUint::from(0u32) => Some(v),
        _ => {
            safe_println!("{} {} must be non-empty hex.", "[ERROR]".red().bold(), what);
            None
        }
    }
}

fn hex_of(n: &BigUint) -> String {
    let mut h = n.to_str_radix(16);
    if !h.len().is_multiple_of(2) {
        h.insert(0, '0');
    }
    h
}

/// Dispatch an `rsa` subcommand. Returns true only on success.
pub(crate) fn run_rsa_command(cmd: &crate::cli::RsaCommands, json: bool) -> bool {
    use crate::cli::RsaCommands;
    match cmd {
        RsaCommands::Gcd { n1, n2 } => {
            let (Some(a), Some(b)) = (parse_hex_component(n1, "n1"), parse_hex_component(n2, "n2"))
            else {
                return false;
            };
            match common_factor(&a, &b) {
                Some((q1, q2, p)) => {
                    if json {
                        safe_println!(
                            "{}",
                            serde_json::json!({"shared_prime": hex_of(&p),
                                "cofactor_n1": hex_of(&q1), "cofactor_n2": hex_of(&q2)})
                        );
                    } else {
                        safe_println!("[OK] Shared prime found:");
                        safe_println!("  p  = {}", hex_of(&p).green());
                        safe_println!("  n1 = p * {}", hex_of(&q1));
                        safe_println!("  n2 = p * {}", hex_of(&q2));
                    }
                    true
                }
                None => {
                    report_miss(json, "no shared prime factor");
                    false
                }
            }
        }
        RsaCommands::Wiener { n, e } => {
            let (Some(n), Some(e)) = (parse_hex_component(n, "n"), parse_hex_component(e, "e"))
            else {
                return false;
            };
            match wiener_attack(&n, &e) {
                Some(d) => {
                    if json {
                        safe_println!("{}", serde_json::json!({"d": hex_of(&d)}));
                    } else {
                        safe_println!("[OK] Wiener recovered d = {}", hex_of(&d).green());
                    }
                    true
                }
                None => {
                    report_miss(json, "wiener failed (d is not small enough)");
                    false
                }
            }
        }
        RsaCommands::Hastad { c1, n1, c2, n2, c3, n3 } => {
            let parts = [
                parse_hex_component(c1, "c1"),
                parse_hex_component(n1, "n1"),
                parse_hex_component(c2, "c2"),
                parse_hex_component(n2, "n2"),
                parse_hex_component(c3, "c3"),
                parse_hex_component(n3, "n3"),
            ];
            let mut vs = Vec::with_capacity(6);
            for part in parts {
                match part {
                    Some(v) => vs.push(v),
                    None => return false,
                }
            }
            let cs = vec![vs[0].clone(), vs[2].clone(), vs[4].clone()];
            let ns = vec![vs[1].clone(), vs[3].clone(), vs[5].clone()];
            match hastad_broadcast(&cs, &ns) {
                Ok(m) => {
                    let hex = m.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    let text = String::from_utf8_lossy(&m).into_owned();
                    if json {
                        safe_println!(
                            "{}",
                            serde_json::json!({"message_hex": hex, "message": text})
                        );
                    } else {
                        safe_println!("[OK] Hastad recovered message: {}", text.green().bold());
                    }
                    true
                }
                Err(e) => {
                    report_miss(json, &e);
                    false
                }
            }
        }
        RsaCommands::Fermat { n, max_iter } => {
            let Some(n) = parse_hex_component(n, "n") else {
                return false;
            };
            match fermat_factor(&n, *max_iter) {
                Some((p, q)) => {
                    if json {
                        safe_println!(
                            "{}",
                            serde_json::json!({"p": hex_of(&p), "q": hex_of(&q)})
                        );
                    } else {
                        safe_println!("[OK] Fermat factored n:");
                        safe_println!("  p = {}", hex_of(&p).green());
                        safe_println!("  q = {}", hex_of(&q).green());
                    }
                    true
                }
                None => {
                    report_miss(json, "no close factors within iteration budget");
                    false
                }
            }
        }
    }
}

fn report_miss(json: bool, why: &str) {
    if json {
        safe_println!("{}", serde_json::json!({"found": false, "reason": why}));
    } else {
        safe_println!("[FAIL] {}", why);
    }
}
