pub mod analyze;
pub mod carve;
pub mod compute;
pub mod decode;
pub mod disk;
pub mod inspect;
pub mod scan;
pub mod workshop;

pub(crate) use analyze::{analyze_file, analyze_single_input};
pub(crate) use carve::run_carve;
pub(crate) use compute::{
    handle_encode, handle_encrypt, handle_hash, print_encoding_formats, print_encryption_ciphers,
    print_hash_algorithms,
};
pub(crate) use decode::{handle_decode, handle_deep_decrypt, handle_rot, handle_xor};
pub(crate) use disk::run_forensic_disk;
pub(crate) use scan::run_forensic_scan;
pub(crate) use workshop::run_workshop;

use colored::*;
use hashendra::safe_println;

pub(crate) fn print_banner() {
    let eagle = r#"
   / \
  / _ \
 | (_) |
  \___/   HashEndra v2.0
"#;

    safe_println!("{}", eagle.cyan());
    safe_println!(
        "{}",
        "------------------------------------------------------------------".cyan()
    );
    safe_println!(
        "{}",
        "          identify hashes - decode strings - carve files          ".cyan()
    );
    safe_println!(
        "{}",
        "------------------------------------------------------------------".cyan()
    );
}
