use colored::*;
use hashendra::core::evm::lookup_evm_selector;
use hashendra::core::tls::{is_grease, lookup_tls_suite, rating_name};
use hashendra::safe_println;

/// Look up a TLS cipher suite by hex code: `tls 1301`, `tls 0xC02F`.
/// Returns true when the code is identified (suite or GREASE sentinel).
pub(crate) fn run_tls_lookup(code: &str, json: bool) -> bool {
    if let Some(suite) = lookup_tls_suite(code) {
        if json {
            safe_println!(
                "{}",
                serde_json::json!({
                    "code": format!("0x{:04X}", suite.code),
                    "name": suite.name,
                    "rating": rating_name(suite.rating),
                    "note": suite.note,
                })
            );
        } else {
            safe_println!("TLS suite 0x{:04X}: {}", suite.code, suite.name.cyan().bold());
            safe_println!("  rating: {}", rating_name(suite.rating));
            if !suite.note.is_empty() {
                safe_println!("  note: {}", suite.note);
            }
        }
        return true;
    }
    // GREASE values are handshake noise, not suites — still an answer.
    let stripped = code
        .strip_prefix("0x")
        .or_else(|| code.strip_prefix("0X"))
        .unwrap_or(code);
    let hex: String = stripped.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() == 4
        && let Ok(raw) = u16::from_str_radix(&hex, 16)
        && is_grease(raw) {
            if json {
                safe_println!(
                    "{}",
                    serde_json::json!({"code": format!("0x{raw:04X}"), "grease": true})
                );
            } else {
                safe_println!("0x{raw:04X} is a GREASE value (RFC 8701), not a real suite.");
            }
            return true;
        }
    if json {
        safe_println!("{}", serde_json::json!({"code": code, "known": false}));
    } else {
        safe_println!("[FAIL] Unknown TLS suite code '{}'. Expected 4 hex digits like 1301.", code);
    }
    false
}

/// Look up an EVM function selector: `evm a9059cbb` or pasted calldata.
pub(crate) fn run_evm_lookup(selector: &str, json: bool) -> bool {
    match lookup_evm_selector(selector) {
        Some(entry) => {
            if json {
                safe_println!(
                    "{}",
                    serde_json::json!({
                        "selector": entry.selector,
                        "signature": entry.signature,
                        "area": entry.area,
                    })
                );
            } else {
                safe_println!("0x{}: {}", entry.selector, entry.signature.cyan().bold());
                safe_println!("  area: {}", entry.area);
            }
            true
        }
        None => {
            if json {
                safe_println!("{}", serde_json::json!({"selector": selector, "known": false}));
            } else {
                safe_println!("[FAIL] Unknown selector '{}'. Expected 4 bytes hex like a9059cbb.", selector);
            }
            false
        }
    }
}
