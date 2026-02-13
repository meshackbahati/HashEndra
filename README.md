# HashEndra 

<p align="center">
  <img src="assets/logo.png" width="400" alt="HashEndra Logo">
</p>

**The Universal Forensic Decryption & Hashing Engine**

HashEndra is a high-performance, intelligence-driven digital evidence classification engine built for security professionals, CTF players, forensic analysts, and developers. It goes far beyond simple regex matching — combining Shannon entropy analysis, Bayesian-like scoring, statistical cryptanalysis, and deep recursive decoding into a single, production-grade CLI tool.

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
  - [Interactive Workshop](#10-interactive-workshop)
  - [Batch File Processing](#11-batch-file-processing)
  - [JSON Output](#12-json-output)
- [Classical Cipher Suite](#classical-cipher-suite)
- [Layered Decoding Engine](#layered-decoding-engine)
- [Signature Library](#signature-library)
- [Security Compliance](#security-compliance)
- [Architecture](#architecture)
- [Detection Logic FAQ](#detection-logic-faq)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Core Detection Engine
- **2,000+ Signatures** covering cryptographic hashes, password KDFs, encodings, classical ciphers, blockchain formats, steganographic markers, and forensic artifacts.
- **Shannon Entropy Analysis** for probabilistic scoring beyond regex matching.
- **Auto-Repair** — fixes malformed input (colons, whitespace, missing Base64 padding) automatically.
- **Context-Aware Scoring** — adjusts confidence based on source context (network, database, filesystem, memory, blockchain).
- **Deep Parameter Extraction** — parses BCrypt, Argon2, Scrypt, PBKDF2, and JWT for metadata (cost, salt, memory, header/payload).
- **Security Audit** — flags every detection against NIST SP 800-131A, PCI DSS 4.0, and GDPR compliance standards.

### Advanced Cipher Suite
- **10 Classical Cipher Crackers** — Caesar, Atbash, Affine, Baconian, Vigenere, Rail Fence, Columnar Transposition, Simple Substitution, Playfair, and Bifid.
- **Statistical Cryptanalysis Core** — Index of Coincidence, Chi-Squared analysis, quadgram scoring, Hamming distance, and multi-byte XOR key estimation.
- **Layered Decoding Engine** — recursive auto-unwrapper that peels back nested Hex, Base64, Base32, URL, Caesar, Vigenere, Affine, Atbash, Rail Fence, and XOR layers with cycle detection.
- **Interactive Workshop** — manual decoding playground with live state tracking.

### Forensic Mode
- **Memory-Mapped Binary Scanning** — scans disk images, RAM dumps, and binary files for hidden hashes and encoded strings using zero-copy `mmap`.
- **Directory Recursion** — walks entire directory trees to locate evidence across filesystems.
- **Magic Byte Detection & File Carving** — identifies embedded file signatures (ZIP, PDF, PNG, ELF, etc.) within other files and automatically extracts them to dedicated folders.

---

## Installation

### One-Liner (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/meshackbahati/HashEndra/main/install.sh | bash
```

This script automatically detects your OS, installs Rust/Cargo if needed, builds the project, and copies the binary to `/usr/local/bin/`.

### Manual Installation

Ensure you have Rust installed (1.75+ recommended):

```bash
git clone https://github.com/meshackbahati/HashEndra.git
cd HashEndra
cargo build --release
sudo cp target/release/hashendra /usr/local/bin/
```

### Verify Installation

```bash
hashendra --help
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
        --decode             Attempt to decode the input (Base64, Hex, URL, Base32, Base58)
        --deep-decrypt       Run deep recursive decryption (multi-layer auto-unwrapping)
        --rot                Brute-force all 25 ROT/Caesar shifts
        --xor                Crack single-byte XOR with frequency analysis
        --context <CONTEXT>  Detection context: generic, network, database, filesystem, memory, blockchain
                             [default: generic]
    -h, --help               Print help
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

HashEndra automatically fixes malformed input before analysis:

```bash
# Colon-separated hex (common in network captures)
hashendra "5f4d:cc3b:5aa7:65d6:1d83:27de:b882:cf99"

# Whitespace-contaminated hashes
hashendra "  5d41402abc4b2a76b9719d911017c592  "

# Base64 with missing padding
hashendra --decode "SGVsbG8gV29ybGQ"
```

The engine strips colons, whitespace, normalizes case, and repairs Base64 padding before matching.

---

### 3. Context-Aware Detection

Provide context to increase detection accuracy. Context adjusts confidence scores for signatures that are more probable in specific environments:

```bash
# Network traffic (pcap) — boosts network-relevant hashes
hashendra "5d41402abc4b2a76b9719d911017c592" --context network

# Database dump — boosts password hash signatures
hashendra '$2a$10$N9qo8uLOickgx2ZMRZoMy.Mr/.cIGPqnG3nj.3Jp6tNJ2vQm7Fv.y' --context database

# Filesystem analysis (/etc/shadow) — boosts Unix crypt formats
hashendra '$6$rounds=5000$salt$hash' --context filesystem

# Memory dump analysis
hashendra "some_hash" --context memory

# Blockchain forensics — boosts wallet and block header formats
hashendra "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" --context blockchain
```

**Available contexts:** `generic` (default), `network`, `database`, `filesystem`, `memory`, `blockchain`

---

### 4. KDF Parameter Extraction

HashEndra extracts metadata from structured password hashes:

```bash
# BCrypt — extracts version, cost, and salt
hashendra '$2a$10$N9qo8uLOickgx2ZMRZoMy.Mr/.cIGPqnG3nj.3Jp6tNJ2vQm7Fv.y'
```

**Expected Output (includes):**
```
+-- PARAMETERS --------------------------------------------------+
   Version : 2a
   Cost    : 10
   Salt    : N9qo8uLOickgx2ZMRZoMy.
+----------------------------------------------------------------+
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

# Detect encoding type (without decoding)
hashendra "SGVsbG8gV29ybGQ="
```

**Supported decoders:** Base64, Hex, URL (percent-encoding), Base32, Base58 (Bitcoin/Flickr)

---

### 6. Deep Recursive Decryption

The Layered Decoding Engine automatically peels back nested layers of encoding and encryption:

```bash
# Multi-layer: Hex -> Base64 -> Cleartext
hashendra --deep-decrypt "5a7a4a375757396656574666636d56665a325666546d6c7664584e664d4739516331397a6347567364463970564639796232356e66513d3d"
```

**Expected Output:**
```
[SCAN] Starting deep recursive unwrapping for: 5a7a4a37...
  [LAYER 1] Detected: Hex -> ZzJ7WW9fVWFfcmVfZ2VfTmlvdXNfMG9Qc19zcGVsdF9pVF9yb25nfQ==
  [LAYER 2] Detected: Base64 -> g2{Yo_Ua_re_ge_Nious_0oPs_spelt_iT_rong}

[OK] Fully decrypted in 2 layers
[FINISH] Final Payload: g2{Yo_Ua_re_ge_Nious_0oPs_spelt_iT_rong}
```

```bash
# ROT13-encoded CTF flag
hashendra --deep-decrypt "t24frp{Lbh_ner_n_inyvqngrq_NTRAG}"
```

**Expected Output:**
```
  [LAYER 1] Detected: Caesar/ROT -> g24sec{You_are_a_validated_AGENT}
[OK] Fully decrypted in 1 layers
```

```bash
# Simple Base64
hashendra --deep-decrypt "SGVsbG8gV29ybGQ="
```

**Expected Output:**
```
  [LAYER 1] Detected: Base64 -> Hello World
[OK] Fully decrypted in 1 layers
```

**How it works:**
1. At each layer, the engine generates all plausible decoding candidates (Hex, Base64, Base32, URL, Caesar, Vigenere, Affine, Atbash, Rail Fence, XOR).
2. The highest-confidence candidate is selected.
3. The engine checks for cycles (prevents infinite loops) and validates plaintext (JSON, XML, Gzip, PE, ELF magic bytes).
4. Statistical crackers are gated by an IoC heuristic — they only fire when the input looks like ciphertext, preventing mangling of already-decoded text.
5. Maximum depth: 10 layers.

---

### 7. ROT Brute-Force

Brute-force all 25 ROT/Caesar shifts:

```bash
hashendra --rot "Uryyb Jbeyq"
```

**Expected Output:**
```
ROT-1:  Vszzc Kcfme
ROT-2:  Wtaad Ldgnf
...
ROT-13: Hello World
...
ROT-25: Tqxxn Inqkc
```

Every shift is shown so you can visually identify the correct plaintext.

---

### 8. XOR Key Cracking

Crack single-byte XOR encryption using frequency analysis:

```bash
hashendra --xor "48656c6c6f"
```

**Expected Output:**
```
+-- XOR CRACK RESULTS ------------------------------------------+
   Key: 0x00 -> Hello    Score: 1.00
   Key: 0x20 -> hELLO    Score: 0.85
   ...
+----------------------------------------------------------------+
```

The engine tests all 256 possible single-byte keys and ranks results by printable character ratio.

---

### 9. Forensic Binary Scanning & File Carving

Scan binary files (disk images, memory dumps, firmware) for hidden hashes, encoded strings, and embedded files:

```bash
# Scan a single file
hashendra forensic evidence.raw

# Scan an entire directory recursively
hashendra forensic /path/to/evidence/
```

**How it works:**
- **Recursive Scanning**: Walks through all subdirectories to analyze every file.
- **Strings & Hashes**: Identifies readable strings (URLs, IPs, Emails, Hashes) using regex and entropy.
- **Embedded File Detection**: Scans for magic bytes of common file formats (ZIP, RAR, 7z, PDF, ELF, etc.).
- **Automatic Extraction**: When a hidden file is detected, it is extracted to a dedicated folder `extracted_<filename>/`.

---

### 10. Interactive Workshop

A manual decoding playground for forensic analysts and CTF players:

```bash
# Start with empty state
hashendra workshop

# Start with initial text
hashendra workshop "SGVsbG8gV29ybGQ="
```

**Workshop Commands:**

| Command | Description |
|---------|-------------|
| `/set <text>` | Set the current working text |
| `/analyze`, `/detect` | Run full forensic analysis on current text |
| `/base64` | Decode current text as Base64 |
| `/base32` | Decode current text as Base32 |
| `/base58` | Decode current text as Base58 |
| `/hex` | Decode current text as Hex |
| `/url` | Decode current text as URL-encoding |
| `/rot13` | Apply ROT13 to current text |
| `/xor <key>` | XOR current text with a string key |
| `/deep` | Run the deep auto-unwrapper on current text |
| `/history` | Show the history of changes |
| `/undo` | Revert to the previous text state |
| `/status` | Show current working text |
| `/help` | Show all available commands |
| `/exit` | Exit the workshop |

**Example Session:**
```
hashendra> /set SGVsbG8gV29ybGQ=
  [OK] Current text set.
hashendra> /base64
  [OK] Decoded: Hello World
hashendra> /rot13
  [OK] Applied ROT13: Uryyb Jbeyq
hashendra> /status
  Current: Uryyb Jbeyq
hashendra> /undo
  [OK] Undone. Current: Hello World
hashendra> /exit
```

You can also type raw text (without a `/` prefix) to set it as the current working text directly.

---

### 11. Batch File Processing

Process multiple hashes from a file (one per line):

```bash
hashendra -f hashes.txt
```

Each line is analyzed independently, and results are printed sequentially.

---

### 12. JSON Output

Get machine-readable JSON output for integration with other tools:

```bash
hashendra -j "5d41402abc4b2a76b9719d911017c592"
```

**Expected Output:**
```json
[
  {
    "name": "MD5",
    "description": "Message-Digest Algorithm 5",
    "confidence": 0.95,
    "security_rating": "Broken",
    "compliance_refs": ["PCI DSS 4.0", "NIST SP 800-131A"],
    "hashcat_mode": 0,
    "john_format": "raw-md5"
  }
]
```

Combine with `jq` for scriptable workflows:
```bash
hashendra -j "5d41402abc4b2a76b9719d911017c592" | jq '.[0].name'
```

---

## Classical Cipher Suite

HashEndra includes automated crackers for 10 classical cipher families:

| Cipher | Method | Complexity |
|--------|--------|-----------|
| **Caesar / ROT** | Brute-force all 26 shifts, Chi-Squared scoring | O(26) |
| **Atbash** | Alphabet reversal, Chi-Squared validation | O(n) |
| **Affine** | Tests all 312 valid (a, b) pairs | O(312) |
| **Baconian** | Binary decoding (both 24 and 26 char variants) | O(n) |
| **Vigenere** | IoC-based period detection + column-wise Caesar | O(26k) |
| **Rail Fence** | Tests rails 2-10, Chi-Squared scoring | O(9n) |
| **Columnar Transposition** | Permutation testing for small column counts | O(k!) |
| **Simple Substitution** | Hill Climbing with quadgram scoring | Heuristic |
| **Playfair** | 5x5 grid decoding with keyword | Manual key |
| **Bifid** | Period-based Polybius square decoding | Manual key |

---

## Layered Decoding Engine

The recursive engine supports the following transform stack at each layer:

| Decoder | Priority | Gating |
|---------|----------|--------|
| Hex | Highest (1.1) | Always |
| Base64 | High (1.0) | Always |
| URL | High (1.0) | Always |
| Base32 | High (0.9) | Always |
| Caesar/ROT | Medium (0.8) | No spaces + 20% Chi-Squared improvement |
| Affine | Medium (0.75) | `is_likely_ciphertext` (IoC < 0.055) |
| Vigenere | Medium (0.7) | `is_likely_ciphertext` |
| Rail Fence | Medium (0.65) | `is_likely_ciphertext` |
| Atbash | Lower (0.6) | No spaces + 20% Chi-Squared improvement |
| XOR (Multi-byte) | Variable | Score > 0.8 + non-identity key + result differs |

**Termination Heuristics:**
- **Spaces detected** in output → plaintext reached, stop.
- **Common English words** found → plaintext reached, stop.
- **IoC > 0.055** on alphabetic characters → English-like distribution, stop expensive crackers.
- **Cycle detection** → previous output repeated, stop.
- **Max depth** → 10 layers.

---

## Signature Library

The signature database covers the following categories:

### Cryptographic Hashes
MD4, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-3 (all variants), RIPEMD-128/160/256/320, Whirlpool, Tiger, BLAKE2b/2s, BLAKE3, Snefru, HAVAL, GOST R 34.11, SM3, Streebog, and more.

### Password KDFs
BCrypt, Argon2 (id/i/d), Scrypt, PBKDF2 (SHA-1/256/512), Unix Crypt (DES, MD5, SHA-256, SHA-512), Django (PBKDF2, BCrypt, Argon2), Cisco Type 5/7/8/9, MSSQL, MySQL, Oracle, WordPress (phpass), Drupal, Joomla.

### Encodings
Base64 (standard, URL-safe), Base32, Base58, Base85, Hex, URL encoding, Punycode, UUencode, ROT13/ROT47, Ascii85, EBCDIC, Morse Code, Binary.

### Blockchain & Cryptocurrency
Bitcoin (P2PKH, P2SH, Bech32), Ethereum addresses, Litecoin, Monero, Ripple, IPFS CIDs, Bitcoin WIF keys.

### Steganography Markers
PNG chunks (IHDR, IDAT, tEXt, iTXt, zTXt), JPEG (JFIF, Exif, IPTC), TIFF, GIF, BMP, WebP, RIFF, OpenPGP, ZIP/PKZIP, PDF, ELF, PE/MZ, Mach-O, RAR, 7z, OLE2.

### Network & Protocol
JWTs, API keys (AWS, Google, Stripe, GitHub, Slack, Twilio, SendGrid, Mailgun, Firebase), SSH keys, PGP signatures, SSL certificates, MAC addresses, UUIDs, IP addresses, SRI hashes.

---

## Security Compliance

Every detection is audited against industry standards:

| Standard | What It Checks |
|----------|---------------|
| **NIST SP 800-131A** | Algorithm strength (broken, weak, secure) |
| **PCI DSS 4.0** | Payment card data protection requirements |
| **GDPR** | Personal data encryption adequacy |

Ratings are displayed alongside every detection:
- **Secure** — Modern, strong algorithms (Argon2, SHA-3, BLAKE3)
- **Weak** — Not broken but aging or fast (SHA-1, PBKDF2 with low iterations)
- **Broken** — Known collision attacks (MD5, MD4)
- **Insecure** — Trivially crackable (DES, RC4-40)

---

## Architecture

```
hashendra/
├── src/
│   ├── main.rs                      # CLI entry point, workshop, deep-decrypt
│   ├── core/
│   │   ├── mod.rs                   # Module declarations
│   │   ├── patterns.rs              # Signature database, scan_input()
│   │   ├── scanner.rs               # Entropy, scoring, decoders, ROT/XOR
│   │   ├── cryptanalysis.rs         # IoC, Chi-Squared, quadgrams, XOR cracker
│   │   └── recursive_engine.rs      # Layered Decoding Engine
│   ├── detectors/
│   │   ├── mod.rs
│   │   ├── hashes.rs                # 1,000+ hash signatures
│   │   ├── encodings.rs             # Encoding signatures
│   │   ├── ciphers.rs               # Cipher signatures
│   │   ├── classic_ciphers.rs       # 10 classical cipher crackers
│   │   └── stego.rs                 # Steganographic signatures
│   └── utils/
│       ├── mod.rs
│       └── io_manager.rs            # Memory-mapped forensic I/O
├── assets/
│   └── logo.png                     # Project logo
├── install.sh                       # Automated installer
├── Cargo.toml                       # Dependencies
└── README.md                        # This file
```

**Key Dependencies:**

| Crate | Purpose |
|-------|---------|
| `clap` | CLI argument parsing |
| `colored` | Terminal color output |
| `regex` | Pattern matching for 2,000+ signatures |
| `rayon` | Parallel processing |
| `memmap2` | Memory-mapped file I/O for forensic scanning |
| `serde` / `serde_json` | JSON serialization |
| `hex` | Hex encoding/decoding |
| `itertools` | Permutation generation for cipher crackers |
| `walkdir` | Recursive directory traversal |
| `num-bigint` | Large number arithmetic (Base58) |

---

## Detection Logic FAQ

### Why does a short string like "test" detect as Base64?
HashEndra is a **probabilistic** engine. A 4-character string like "test" perfectly satisfies the structural requirements of a Base64 block (valid characters, correct length quantum). The engine identifies it as a 70% probable match. For very short strings, structural collisions are common — this is by design. Use `--context` to reduce false positives.

### When are KDF parameters (cost/salt) shown?
Parameters like **Cost** and **Salt** are only extracted when a string matches a specific **Key Derivation Function** signature (BCrypt, Argon2, Scrypt, PBKDF2). Regular strings will not show parameters.

### Why does deep-decrypt stop early?
The engine uses multiple termination heuristics:
- **Spaces in output** indicate plaintext was reached.
- **IoC analysis** detects English-like letter distributions.
- **Cycle detection** prevents infinite loops.
- If no decoder produces a valid candidate, the engine stops.

### How does context-aware detection work?
When you specify `--context network`, the engine boosts confidence for signatures that are commonly found in network traffic (e.g., NTLM, Kerberos tickets) and reduces confidence for signatures more common in other contexts. This reduces false positives for the specific analysis scenario.

### Can I add custom signatures?
Yes. Create a file at `~/.hashendra/signatures.json` with an array of signature objects. HashEndra automatically loads these at startup.

**Signature Structure:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` | Yes | Unique identifier (e.g., `"My Custom Hash"`) |
| `description` | `string` | Yes | Human-readable description |
| `pattern` | `string` | Yes | Regex pattern to match against input |
| `detection_type` | `string` | Yes | One of: `"Hash"`, `"Encoding"`, `"Cipher"`, `"Stego"` |
| `confidence_weight` | `number` | Yes | Base confidence (0.0 – 1.0) |
| `common_name` | `string\|null` | No | Friendly name (e.g., `"MD5"`) |
| `hashcat_mode` | `number\|null` | No | Hashcat mode number for cracking |
| `john_format` | `string\|null` | No | John the Ripper format string |
| `security_rating` | `string\|null` | No | One of: `"Secure"`, `"Weak"`, `"Broken"`, `"Insecure"` |
| `compliance_refs` | `string[]` | Yes | Compliance standards (e.g., `["PCI DSS 4.0"]`) |
| `parameters` | `string[]` | Yes | Named capture groups in the regex pattern |

**Example `~/.hashendra/signatures.json`:**
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
  },
  {
    "name": "Internal Hash v2",
    "description": "Custom salted hash used by internal systems",
    "pattern": "^\\$INT\\$(?P<salt>[a-f0-9]{16})\\$(?P<hash>[a-f0-9]{64})$",
    "detection_type": "Hash",
    "confidence_weight": 0.90,
    "common_name": "Internal Salted SHA-256",
    "hashcat_mode": null,
    "john_format": null,
    "security_rating": "Weak",
    "compliance_refs": ["NIST SP 800-131A"],
    "parameters": ["salt", "hash"]
  }
]
```

Named capture groups in `pattern` (e.g., `(?P<salt>...)`) are automatically extracted and displayed as parameters in the output.

---

## Contributing

Contributions are welcome! Areas where help is especially appreciated:

- **New cipher crackers** — Polybius, Four-Square, ADFGVX
- **Rolling XOR detection** — identifying XOR with incrementing keys
- **Block cipher mode identification** — ECB vs CBC pattern detection
- **Weak key detection** — identifying DES weak/semi-weak keys
- **Progress tree visualization** — showing the full decode tree graphically

Please feel free to submit a Pull Request.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
