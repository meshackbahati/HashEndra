# HashEndra  v2.0

<p align="center">
  <img src="assets/logo.png" width="400" alt="HashEndra Logo">
</p>

**The Universal Forensic Decryption & Hashing Engine**

> **Full documentation available in the [`docs/`](docs/README.md) directory** — includes architecture diagrams (Mermaid), CLI reference, user guide, forensics walkthrough, configuration guide, and development guide.

HashEndra is a high-performance, intelligence-driven digital evidence classification engine built for security professionals, CTF players, forensic analysts, and developers. It combines Shannon entropy analysis, Bayesian-like scoring, statistical cryptanalysis, and deep recursive decoding into a single, production-grade CLI tool with forensic-grade disk and volume recovery.

**Author**: Meshack Bahati
**GitHub**: [https://github.com/meshackbahati/HashEndra](https://github.com/meshackbahati/HashEndra)

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Use Cases & Examples](#use-cases--examples)
  - [Hash Identification](#1-hash-identification)
  - [Auto-Repair & Preprocessing](#2-auto-repair--preprocessing)
  - [Context-Aware Detection](#3-context-aware-detection)
  - [KDF Parameter Extraction](#4-kdf-parameter-extraction)
  - [Encoding Detection & Decoding](#5-encoding-detection--decoding)
  - [Deep Recursive Decryption](#6-deep-recursive-decryption)
  - [ROT Brute-Force](#7-rot-brute-force)
  - [XOR Key Cracking](#8-xor-key-cracking)
  - [Forensic Binary Scanning](#9-forensic-binary-scanning)
  - [Foremost-Style Carving](#10-foremost-style-carving)
  - [Interactive Workshop](#11-interactive-workshop)
  - [Batch File Processing](#12-batch-file-processing)
  - [JSON Output](#13-json-output)
- [Classical Cipher Suite](#classical-cipher-suite)
- [Layered Decoding Engine](#layered-decoding-engine)
- [Signature Library](#signature-library)
- [Security Compliance](#security-compliance)
- [Architecture](#architecture)
- [Detection Logic FAQ](#detection-logic-faq)
- [Custom Signatures](#custom-signatures)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Core Detection Engine
- **2,000+ Signatures** covering cryptographic hashes, password KDFs, encodings, classical ciphers, blockchain formats, steganographic markers, and forensic artifacts.
- **Shannon Entropy Analysis** for probabilistic scoring beyond regex matching.
- **Auto-Repair** — fixes malformed input (colons, whitespace, missing Base64 padding) automatically without destroying structured data (SSH keys, PGP blocks, shadow entries are preserved).
- **Stricter Decode Validation** — validates decoded payloads before raising confidence, reducing false positives from regex-only matches.
- **Context-Aware Scoring** — adjusts confidence based on source context (network, database, filesystem, memory, blockchain). Unknown contexts print a warning.
- **Deep Parameter Extraction** — parses BCrypt, Argon2, Scrypt, PBKDF2, and JWT for metadata (cost, salt, memory, header/payload).
- **Security Audit** — flags every detection against NIST SP 800-131A, PCI DSS 4.0, and GDPR compliance standards.
- **Multi-threaded safe output** — thread-safe stdout with mutex, no output interleaving.

### Advanced Cipher Suite
- **10 Classical Cipher Crackers** — Caesar, Atbash, Affine, Baconian, Vigenere, Rail Fence, Columnar Transposition, Simple Substitution, Playfair, and Bifid.
- **Statistical Cryptanalysis Core** — Index of Coincidence, Chi-Squared analysis, quadgram scoring, Hamming distance, and multi-byte XOR key estimation.
- **Layered Decoding Engine** — recursive auto-unwrapper that peels back nested Hex, Base64, Base32, Base58, Binary, Ascii85, Quoted-Printable, HTML entities, URL, Caesar, Vigenere, Affine, Baconian, Columnar, Rail Fence, and XOR layers with cycle detection.
- **Interactive Workshop** — manual decoding playground with live state tracking.

### Forensic Mode
- **Memory-Mapped Binary Scanning** — scans disk images, RAM dumps, and binary files for hidden hashes and encoded strings using zero-copy `mmap`.
- **Disk Layout Inspection** — parses MBR/GPT layouts and fingerprints NTFS, FAT12/16/32, exFAT, ReFS, ext2/3/4, swap, Btrfs, XFS, F2FS, HFS+, APFS, JFS, ReiserFS, ISO9660, and UDF.
- **NTFS MFT Enumeration** — walks MFT records, highlights deleted entries, recovers named ADS, rebuilds resident and non-resident streams, and summarizes `$Bitmap`, `$LogFile`, and `$UsnJrnl`.
- **FAT Volume Recovery** — enumerates FAT12/16/32 directory entries, flags deleted files, and rebuilds deleted contiguous file data.
- **ext2/3/4 Volume Recovery** — parses superblocks, walks inode tables, follows extent/direct/indirect block maps, recovers deleted files.
- **Directory Recursion** — walks entire directory trees to locate evidence across filesystems.
- **Structured Triage Reports** — emits machine-readable JSON for single files and full directory scans.
- **Artifact Header Inspection** — parses PNG, PDF, ZIP, ELF, PE, Mach-O, SQLite, and Gzip headers.
- **Magic Byte Detection & File Carving** — identifies embedded file signatures (ZIP, PDF, PNG, ELF, etc.) within other files and automatically extracts them.
- **Container-Aware Matryoshka Extraction** — unpacked ZIP/TAR members rescanned for nested payloads with byte-quota safety limit (prevents zip-bomb disk fills).
- **Safe Extraction** — rejects block devices, FIFOs, and broken symlinks with clear error messages.

### Quality-of-Life Improvements (v2.0)
- **Stdin streaming** — processes input line-by-line in real-time (no more batch buffering).
- **XOR cracking** — tries raw ASCII bytes first, hex-decoded fallback second; no more silent misinterpretation.
- **ROT brute-force** — results ranked by Chi-Squared score, best match marked with `*`.
- **`--decode` and `--deep-decrypt`** — now use identical logic, produce consistent results.
- **ASCII85** — accepts data with or without `~>` end marker.
- **Context validation** — unknown contexts print a warning instead of silently falling back.
- **Workshop binary load** — warns when binary files are loaded, shows hex preview.
- **Installation** — system-wide `/usr/local/bin` with automatic cleanup; `--uninstall` and `--keep` flags.

---

## Installation

### One-Liner (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/meshackbahati/HashEndra/main/install.sh | bash
```

This script:
- Detects your OS (Linux, macOS, Windows via MSYS2/MinGW)
- Installs Rust/Cargo if missing
- Builds the project in release mode
- Installs to `/usr/local/bin` (Linux/macOS) or `~/.cargo/bin` (Windows)
- Adds the directory to your PATH (interactive prompt)
- Cleans up the cloned repository after installation
- Supports `--keep`, `--prefix`, and `--uninstall` flags

### Manual Installation

```bash
git clone https://github.com/meshackbahati/HashEndra.git
cd HashEndra
cargo build --release
sudo cp target/release/hashendra /usr/local/bin/
```

### Verify Installation

```bash
hashendra --version
hashendra --help
```

### Uninstall

```bash
# Via installer:
bash install.sh --uninstall

# Or manually:
rm /usr/local/bin/hashendra
```

---

## Quick Start

```bash
# Identify a hash
hashendra "5d41402abc4b2a76b9719d911017c592"

# Decode Base64
hashendra --decode "SGVsbG8gV29ybGQ="

# Deep-decrypt a multi-layer obfuscated string
hashendra --deep-decrypt "5a7a4a375757396656574666636d56665a325666546d6c7664584e664d4739516331397a6347567364463970564639796232356e66513d3d"

# Start interactive workshop
hashendra workshop
```

---

## CLI Reference

```
USAGE:
    hashendra [OPTIONS] [INPUT] [COMMAND]

ARGUMENTS:
    [INPUT]    The hash or encoded string to analyze

COMMANDS:
    forensic   Run forensic analysis on a file or directory
    workshop   Start an interactive decoding workshop
    update     Update the signature database
    help       Print this message or the help of the given subcommand(s)

OPTIONS:
    -f, --file <FILE>        File to read hashes from (one per line)
    -j, --json               Output results in JSON format
    -v, --verbose            Verbose mode (show additional metadata)
        --decode             Attempt to decode the input (Base64, Hex, URL, Base32, Base58, ...)
        --deep-decrypt       Run deep recursive decryption (multi-layer auto-unwrapping)
        --rot                Brute-force all 25 ROT/Caesar shifts, ranked by Chi-Squared
        --xor                Crack single-byte XOR (tries raw ASCII bytes first, then hex)
        --context <CONTEXT>  Detection context: generic, network, database, filesystem, memory, blockchain
                             [default: generic]
    -V, --version            Print version information
    -h, --help               Print help
```

**Forensic subcommands:**

```text
hashendra forensic scan <PATH> [--no-extract]
hashendra forensic disk <PATH> [--sector-size 512] [--offset BYTES] [--fs ntfs|fat|ext4|...]
hashendra forensic carve <PATH> | --input <PATH> [--types png,jpg] [-o DIR] [-c conf] [-M] [--dry-run]
```

---

## Use Cases & Examples

### 1. Hash Identification

Identify any hash algorithm with confidence scoring, cracking recommendations, and compliance status:

```bash
hashendra "5d41402abc4b2a76b9719d911017c592"
```

**Expected Output:**
```
+-- DETECTION RESULTS -------------------------------------------+
|  [!] MD5 (Message-Digest Algorithm 5)          95%             |
|  [i] NTLM                                     85%             |
|  [i] MySQL323                                  60%             |
+----------------------------------------------------------------+

+-- RECOMMENDATION ----------------------------------------------+
   -> Primary : MD5 (Message-Digest Algorithm 5)
   -> Crack   : hashcat -m 0 hash.txt rockyou.txt
   -> Status  : Does not meet PCI DSS 4.0, NIST SP 800-131A
+----------------------------------------------------------------+
```

**More examples:**
```bash
# SHA-256
hashendra "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# SHA-512
hashendra "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

# BCrypt
hashendra '$2a$10$N9qo8uLOickgx2ZMRZoMy.Mr/.cIGPqnG3nj.3Jp6tNJ2vQm7Fv.y'

# NTLM
hashendra "32ed87bdb5fdc5e9cba88547376818d4"
```

---

### 2. Auto-Repair & Preprocessing

HashEndra automatically fixes malformed input without destroying structured data:

```bash
# Colon-separated hex (common in network captures)
hashendra "5f4d:cc3b:5aa7:65d6:1d83:27de:b882:cf99"

# Whitespace-contaminated hashes
hashendra "  5d41402abc4b2a76b9719d911017c592  "

# Base64 with missing padding
hashendra --decode "SGVsbG8gV29ybGQ"
```

The engine strips colons and whitespace only when the input looks like a hash or encoding. SSH keys, PGP blocks, `/etc/shadow` entries, and other structured data with spaces or delimiters are left intact.

---

### 3. Context-Aware Detection

Provide context to increase detection accuracy:

```bash
# Network traffic (pcap) — boosts network-relevant hashes
hashendra "5d41402abc4b2a76b9719d911017c592" --context network

# Database dump — boosts password hash signatures
hashendra '$2a$10$N9qo8uLOickgx2ZMRZoMy.Mr/.cIGPqnG3nj.3Jp6tNJ2vQm7Fv.y' --context database

# Filesystem analysis (/etc/shadow) — boosts Unix crypt formats
hashendra '$6$rounds=5000$salt$hash' --context filesystem

# Blockchain forensics — boosts wallet and block header formats
hashendra "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" --context blockchain
```

**Available contexts:** `generic` (default), `network`, `database`, `filesystem`, `memory`, `blockchain`

Unknown contexts print a warning and fall back to `generic`.

---

### 4. KDF Parameter Extraction

HashEndra extracts metadata from structured password hashes:

```bash
# BCrypt — extracts version, cost, and salt
hashendra '$2a$10$N9qo8uLOickgx2ZMRZoMy.Mr/.cIGPqnG3nj.3Jp6tNJ2vQm7Fv.y'
```

**Supported KDF extractions:**
| Format | Extracted Fields |
|--------|-----------------|
| BCrypt | Version, Cost, Salt |
| Argon2 | Version, Memory, Time, Parallelism, Salt, Hash |
| Scrypt | N, r, p, Salt |
| PBKDF2 | Algorithm, Iterations, Salt, Hash |
| JWT | Header (decoded), Payload (decoded), Signature |

---

### 5. Encoding Detection & Decoding

Detect and decode common encodings:

```bash
# Decode Base64
hashendra --decode "SGVsbG8gV29ybGQ="
# Output: Hello World

# Decode Hex
hashendra --decode "48656c6c6f20576f726c64"
# Output: Hello World

# Decode URL-encoded
hashendra --decode "Hello%20World%21"
# Output: Hello World!
```

**Supported decoders:** Base64, Hex (raw, spaced, `0x`, `\x`), URL (percent-encoding), Base32, Base58 (Bitcoin/Flickr), Binary (`0/1` and `0b` forms), Octal (`0o`, escaped, and grouped bytes), Adobe Ascii85/Base85 (with or without `~>` markers), Quoted-Printable, HTML entities, and Morse.

---

### 6. Deep Recursive Decryption

The Layered Decoding Engine automatically peels back nested layers:

```bash
# Multi-layer: Hex -> Base64 -> Cleartext
hashendra --deep-decrypt "5a7a4a375757396656574666636d56665a325666546d6c7664584e664d4739516331397a6347567364463970564639796232356e66513d3d"

# ROT13-encoded CTF flag
hashendra --deep-decrypt "t24frp{Lbh_ner_n_inyvqngrq_NTRAG}"

# Simple Base64
hashendra --deep-decrypt "SGVsbG8gV29ybGQ="
```

`--decode` and `--deep-decrypt` now use the same engine and produce identical results.

---

### 7. ROT Brute-Force

Brute-force all 25 ROT/Caesar shifts, ranked by Chi-Squared score:

```bash
hashendra --rot "Uryyb Jbeyq"
```

**Expected Output:**
```
  * 13: Hello World (chi2=96.3)
    03: Uryyb Jbeyq (chi2=452.1)
    ...
```

The `*` marker indicates the statistically best match.

---

### 8. XOR Key Cracking

Crack single-byte XOR encryption (raw ASCII bytes tried first, then hex-decoded):

```bash
# XOR crack raw ASCII text
hashendra --xor "Hello"

# XOR crack hex-encoded input (fallback)
hashendra --xor "48656c6c6f"
```

The engine tests all 256 possible single-byte keys and ranks results by printable character ratio.

---

### 9. Forensic Binary Scanning & File Carving

```bash
# Inspect partition layout
hashendra forensic disk disk.dd

# Recover deleted NTFS files
hashendra forensic disk disk.dd --ntfs --offset 1048576 --deleted-only --extract-data recovered/

# Scan a directory for evidence
hashendra forensic scan /path/to/evidence/

# Emit structured JSON
hashendra --json forensic scan evidence.raw --no-extract
```

Block devices, FIFOs, and broken symlinks are rejected with clear error messages.

---

### 10. Foremost-Style Carving

```bash
# Preview embedded artifacts
hashendra forensic carve evidence.raw --types png,pdf --dry-run

# Carve with matryoshka recursive extraction (1 GB safety quota enforced)
hashendra forensic carve firmware.bin -M --depth 2

# List carveable types
hashendra forensic carve --list-types
```

---

### 11. Interactive Workshop

```bash
# Start with empty state
hashendra workshop

# Start with initial text
hashendra workshop "SGVsbG8gV29ybGQ="
```

**Workshop Commands:** `/set`, `/load`, `/base64`, `/hex`, `/rot13`, `/xor`, `/deep`, `/analyze`, `/status`, `/undo`, `/history`, `/exit`, and more. Use `/help` in the workshop for the full list.

Loading a binary file shows a hex preview and warns about potential garbage output.

---

### 12. Batch File Processing

```bash
# Process multiple hashes from a file (one per line, results streamed sequentially)
hashendra -f hashes.txt

# JSON output (one JSON object per line — NDJSON format, pipe-safe)
hashendra -j -f hashes.txt
```

---

### 13. JSON Output

```bash
hashendra -j "5d41402abc4b2a76b9719d911017c592"

# Pipe with jq
hashendra --json forensic scan evidence.raw --no-extract | jq '.hits'
```

---

## Classical Cipher Suite

| Cipher | Method | Complexity |
|--------|--------|-----------|
| **Caesar / ROT** | Brute-force all 26 shifts, Chi-Squared scoring | O(26) |
| **Atbash** | Alphabet reversal, Chi-Squared validation | O(n) |
| **Affine** | Tests all 312 valid (a, b) pairs | O(312) |
| **Baconian** | Binary decoding (24 and 26 char variants) | O(n) |
| **Vigenere** | IoC-based period detection + column-wise Caesar | O(26k) |
| **Rail Fence** | Tests rails 2-10, Chi-Squared scoring | O(9n) |
| **Columnar Transposition** | Permutation testing for small column counts | O(k!) |
| **Simple Substitution** | Hill Climbing with quadgram scoring | Heuristic |
| **Playfair** | 5x5 grid decoding with keyword | Manual key |
| **Bifid** | Period-based Polybius square decoding | Manual key |

---

## Layered Decoding Engine

| Decoder | Priority | Gating |
|---------|----------|--------|
| Hex | Highest (1.1) | Always |
| Base64 | High (1.0) | Always |
| URL | High (1.0) | Always |
| Base32 | High (0.9) | Always |
| Base58 | High (0.85) | Always |
| Binary | High (0.95) | Always |
| Ascii85 | High (0.95) | Data present |
| Quoted-Printable | High (0.90) | `=` escapes |
| HTML Entities | High (0.90) | `&...;` entities |
| Caesar/ROT | Medium (0.8) | No spaces + Chi-Squared improvement |
| Baconian | Medium (0.8) | Only `A/B` alphabet |
| Affine | Medium (0.75) | `is_likely_ciphertext` |
| Vigenere | Medium (0.7) | `is_likely_ciphertext` |
| Rail Fence | Medium (0.65) | `is_likely_ciphertext` |
| Columnar | Medium (0.6) | `is_likely_ciphertext` |
| Atbash | Lower (0.6) | No spaces + Chi-Squared improvement |
| XOR (Single-byte) | Variable | Printable output |
| XOR (Multi-byte) | Variable | Score > 0.8 + non-identity key |

---

## Signature Library

The signature database covers:
- **Cryptographic Hashes**: MD4, MD5, SHA-1/224/256/384/512/3, RIPEMD, Whirlpool, Tiger, BLAKE2/3, Snefru, HAVAL, GOST, SM3, Streebog
- **Password KDFs**: BCrypt, Argon2, Scrypt, PBKDF2, Unix Crypt, Django, Cisco, MSSQL, MySQL, Oracle, WordPress, Drupal, Joomla
- **Encodings**: Base64/32/58/85, Hex, URL, Punycode, UUencode, ROT13/47, EBCDIC, Morse, Binary, Octal
- **Blockchain**: Bitcoin (P2PKH, P2SH, Bech32), Ethereum, Litecoin, Monero, Ripple, IPFS CIDs, WIF keys
- **Steganography**: PNG chunks, JPEG Exif/IPTIC, TIFF, GIF, BMP, WebP, RIFF, OpenPGP, ZIP, PDF, ELF, PE, Mach-O, RAR, 7z, OLE2
- **Network & Protocol**: JWTs, API keys (AWS, Google, Stripe, GitHub, Slack, Twilio, SendGrid, Mailgun, Firebase), SSH keys, PGP, SSL certs, MACs, UUIDs, IPs, SRI hashes

---

## Security Compliance

| Standard | What It Checks |
|----------|---------------|
| **NIST SP 800-131A** | Algorithm strength (broken, weak, secure) |
| **PCI DSS 4.0** | Payment card data protection |
| **GDPR** | Personal data encryption adequacy |

Ratings: **Secure** (Argon2, SHA-3, BLAKE3), **Weak** (SHA-1, PBKDF2 low iterations), **Broken** (MD5, MD4), **Insecure** (DES, RC4-40)

---

## Architecture

```
hashendra/
├── src/
│   ├── main.rs                      # CLI entry point, workshop, deep-decrypt
│   ├── core/
│   │   ├── patterns.rs              # Signature database, scan_input()
│   │   ├── scanner.rs               # Entropy, scoring, decoders, ROT/XOR
│   │   ├── cryptanalysis.rs         # IoC, Chi-Squared, quadgrams, XOR cracker
│   │   └── recursive_engine.rs      # Layered Decoding Engine
│   ├── detectors/
│   │   ├── hashes.rs                # 1,000+ hash signatures
│   │   ├── encodings.rs             # Encoding signatures
│   │   ├── ciphers.rs               # Cipher signatures
│   │   ├── classic_ciphers.rs       # 10 classical cipher crackers
│   │   └── stego.rs                 # Steganographic signatures
│   ├── forensics/
│   │   ├── carve.rs                 # Foremost-style carving
│   │   ├── disk.rs                  # Disk layouts, partitions, VBRs
│   │   ├── ntfs.rs                  # NTFS MFT, deleted-file recovery
│   │   ├── fat.rs                   # FAT12/16/32 recovery
│   │   ├── ext.rs                   # ext2/3/4 recovery
│   │   ├── report.rs               # Triage reports
│   │   ├── inspect.rs              # Artifact metadata parsing
│   │   ├── strings.rs              # ASCII/UTF-16 extraction
│   │   ├── directory.rs            # Directory scan summaries
│   │   └── filetypes.rs            # File type detection
│   └── utils/
│       ├── io.rs                    # Shared safe_print macros (thread-safe)
│       └── io_manager.rs            # Memory-mapped forensic I/O
├── assets/logo.png
├── install.sh                       # Automated installer (--keep, --prefix, --uninstall)
├── Cargo.toml
└── README.md
```

**Key Dependencies:** `clap`, `colored`, `regex`, `rayon`, `memmap2`, `serde`/`serde_json`, `hex`, `itertools`, `walkdir`, `num-bigint`

---

## Detection Logic FAQ

### Why does a short string like "test" detect as Base64?
HashEndra is a **probabilistic** engine. A 4-character string like "test" satisfies the structural requirements of a Base64 block. The engine identifies it as a ~70% probable match. For very short strings, structural collisions are common — use `--context` to reduce false positives.

### Why does deep-decrypt stop early?
The engine uses multiple termination heuristics: spaces in output (plaintext reached), IoC analysis (English-like distribution), cycle detection (prevents infinite loops), and max depth (10 layers).

### How does context-aware detection work?
When you specify `--context network`, the engine boosts confidence for signatures commonly found in network traffic and reduces confidence for others. Unknown context values print a warning.

### Can I add custom signatures?
Yes. Create `~/.hashendra/signatures.json`. Syntax errors in the JSON file are reported as warnings at startup. See [Custom Signatures](#custom-signatures).

### Why does XOR cracking try ASCII first instead of hex?
v2.0 changed the behavior: raw ASCII bytes are tried first (the most common use case). Hex-decoded bytes are only tried if the input looks like hex and raw mode produced no results.

---

## Custom Signatures

Create `~/.hashendra/signatures.json` with an array of signature objects:

```json
[
  {
    "name": "Custom API Token",
    "description": "My internal API token format",
    "pattern": "^MYAPP-[A-Za-z0-9]{32}$",
    "detection_type": "Encoding",
    "confidence_weight": 0.95,
    "common_name": "MyApp Token",
    "hashcat_mode": null,
    "john_format": null,
    "security_rating": "Secure",
    "compliance_refs": [],
    "parameters": []
  }
]
```

Invalid regex patterns are reported at startup with the error message — the app continues without the broken signature.

---

## Contributing

Contributions welcome! Areas of interest:
- **New cipher crackers** — Polybius, Four-Square, ADFGVX
- **Rolling XOR detection** — identifying XOR with incrementing keys
- **Block cipher mode identification** — ECB vs CBC pattern detection
- **Weak key detection** — DES weak/semi-weak keys
- **Progress tree visualization** — showing the full decode tree graphically
- **Additional forensic filesystems** — ZFS, APFS, HFS+ deep recovery

Submit a Pull Request on [GitHub](https://github.com/meshackbahati/HashEndra).

---

## License

MIT License — see the [LICENSE](LICENSE) file for details.
