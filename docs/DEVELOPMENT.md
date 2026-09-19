# Development Guide

## Architecture

HashEndra follows a modular architecture with four public crates:

```
src/
├── main.rs              # Binary entry, dispatch (see cli.rs, handlers/)
├── cli.rs               # Clap structs + dispatch option structs
├── handlers/            # One module per command group
│   ├── decode.rs        # deep-decrypt, decode, rot, xor
│   ├── analyze.rs       # Single-input and batch analysis
│   ├── scan.rs          # forensic scan
│   ├── disk.rs          # forensic disk dispatcher
│   ├── inspect.rs       # Filesystem-specific inspection
│   ├── carve.rs         # forensic carve dispatcher
│   ├── workshop.rs      # Interactive REPL
│   └── compute.rs       # hash, encode, encrypt
├── lib.rs               # Re-exports four modules
├── core/                # Core detection/decoding engine
│   ├── scanner/         # mod (entropy/charset) + score, decode, codecs
│   ├── patterns.rs      # Signature scanning, lazy_static compilation
│   ├── encoder.rs       # 13 encoding functions
│   ├── basecodecs.rs    # base32hex/58check/62/91, Z85, Crockford, UU, XX
│   ├── symmetric.rs     # AES-CBC/ECB, HMAC-SHA-256/512
│   ├── rsa.rs           # Textbook RSA, Miller-Rabin, keygen
│   ├── hasher.rs        # 6 hash algorithms
│   ├── entropy.rs       # Rolling entropy, boundary detection
│   ├── cryptanalysis.rs # Chi-squared, frequency analysis
│   ├── recursive_engine.rs  # Multi-layer unwrapping (+ engine_rules.rs)
│   └── engine_rules.rs  # Plaintext heuristics, crack acceptance rules
├── detectors/           # Detection signatures
│   ├── hashes/          # 85 signatures: digests, kdf, apps, keys
│   ├── encodings.rs     # 28 encoding signatures
│   ├── ciphers.rs       # Cipher signatures
│   ├── classic_ciphers.rs   # Auto-crack ciphers (+ classic_transposition.rs)
│   └── stego.rs         # File magic byte signatures
├── forensics/           # Forensic analysis
│   ├── carve/           # profiles, scan, containers, config (+ engine)
│   ├── disk/            # layout, fingerprint
│   ├── ntfs/            # parse, recover, report
│   ├── fat/             # parse, recover
│   ├── ext/             # parse
│   ├── inspect/         # images, media, audio, docs, exec, data, raster
│   ├── report.rs        # Forensic report builder
│   ├── directory.rs     # Recursive directory scanner
│   ├── filetypes.rs     # File type detection
│   └── strings.rs       # String extraction
└── utils/               # Utilities
    ├── io.rs            # safe_println! thread-safe macros
    └── io_manager.rs    # Memory-mapped I/O
```

Rule: no source file over 500 lines. Test-only code lives in
`<module>_tests.rs` next to its module, wired with `#[path]` so unit tests
keep access to private items.

## Releases

Pushing a `v*` tag runs `.github/workflows/release.yml`: clippy + tests,
then release builds for Linux (x86_64, aarch64), macOS (Intel, Apple
Silicon), and Windows (x86_64), published as a GitHub Release with
SHA256SUMS. `install.sh` downloads these assets; keep its asset-name
mapping in sync with the workflow matrix.

```bash
# Cut a release (update version in Cargo.toml first, then):
git tag v2.1.0 && git push origin v2.1.0
```

## Building

```bash
# Build release
cargo build --release

# Run tests
cargo test

# Run with warnings as errors
RUSTFLAGS="-D warnings" cargo build

# Check for warnings
cargo clippy -- -D warnings

# Run specific tests
cargo test analyze_single_input
cargo test parses_custom_config_profiles
```

## Adding a New Hash Signature

1. **Add the signature** in `src/detectors/hashes.rs`:

```rust
Signature {
    name: "MyHash".to_string(),
    description: "My custom hash algorithm".to_string(),
    pattern: r"^[a-fA-F0-9]{48}$".to_string(),
    detection_type: DetectionType::Hash,
    confidence_weight: 0.8,
    common_name: Some("myhash".to_string()),
    hashcat_mode: Some(99999),
    john_format: Some("myhash".to_string()),
    security_rating: Some(SecurityRating::Weak),
    compliance_refs: vec![],
    parameters: vec![],
}
```

2. **Add a test** for detection

3. **Optionally add a hashing function** in `src/core/hasher.rs`

4. **Register the algorithm** in the `HASH_ALGORITHMS` list

## Adding a New Encoding Format

1. **Add the encoding function** in `src/core/encoder.rs`:

```rust
pub fn encode_myfmt(input: &str) -> String {
    // implementation
}
```

2. **Register** in the `ENCODING_FORMATS` list:

```rust
("myfmt", "My Format Description", encode_myfmt as fn(&str) -> String)
```

3. **Add decoding logic** in `src/core/scanner.rs` for detection validation

4. **Add a signature** in `src/detectors/encodings.rs`

## Adding a New File Format for Carving

1. **Add magic bytes** in `src/detectors/stego.rs`:

```rust
FileSignature {
    extension: "myfmt",
    description: "My Format",
    signatures: vec![&[0xDE, 0xAD, 0xBE, 0xEF]],
    footer: Some(&[0xCA, 0xFE, 0xBA, 0xBE]),
    min_offset: 0,
}
```

2. **Add carve profile** in `src/forensics/carve.rs` `builtin_profiles()`

3. **Add metadata inspector** in `src/forensics/inspect.rs`

## Adding a New Metadata Inspector

1. **Add the inspector function** in `src/forensics/inspect.rs`:

```rust
fn inspect_myfmt(data: &[u8]) -> Option<ArtifactInspection> {
    let mut details = BTreeMap::new();
    details.insert("Field".to_string(), "value".to_string());
    Some(ArtifactInspection {
        format: "My Format".to_string(),
        details,
    })
}
```

2. **Register** in `inspect_artifact()` dispatch

3. **Match the extension** exactly to `stego.rs` file signatures

## Testing Guidelines

- All tests must pass with zero warnings (`RUSTFLAGS="-D warnings" cargo test`)
- New features must include unit tests
- Integration tests live in `src/` files (test modules at end of file)
- Carving tests use `temp_dir()` for output isolation
- Use `#[cfg(test)] mod tests { ... }` for inline tests

## Code Style

- No comments in code (except doc comments on public items)
- Follow existing naming conventions (snake_case for functions, CamelCase for types)
- Use `safe_println!` / `safe_print!` for all output
- All public items must have doc comments
- Keep functions focused and under 100 lines where possible

## Performance Considerations

- **Memory-mapped I/O** for large file reads (carving, inspection)
- **Rayon parallelism** for concurrent signature scanning
- **lazy_static** for compiled regex patterns (compiled once at startup)
- **Deduplication** via BLAKE3 hashing to avoid redundant processing
- **Entropy windowing** uses stride of window/4 for overlapping windows

## Security

- Hard 10 GiB extraction quota cannot be bypassed
- No `unsafe` code (except memory-mapped I/O which requires it)
- All regex patterns are compiled; malformed patterns logged as warnings
- Input preprocessing normalizes whitespace/control chars before scanning
