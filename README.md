# HashEndra v2.0

Identify hashes. Decode strings. Carve files. One CLI.

HashEndra takes an unknown string — a hash, some Base64, a disk image — and
tells you what it thinks it is, with a confidence score and what to try next.
It also scans binaries, inspects NTFS/FAT/ext volumes, and carves embedded
files. Built for CTF players and forensic triage, where the first question is
always "what is this thing".

Full docs live in [`docs/`](docs/README.md): CLI reference, user guide,
architecture, detectors, forensics, configuration, development.

**Author**: Meshack Bahati
**GitHub**: [https://github.com/meshackbahati/HashEndra](https://github.com/meshackbahati/HashEndra)

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Use Cases & Examples](#use-cases--examples)
- [Classical Cipher Suite](#classical-cipher-suite)
- [Layered Decoding Engine](#layered-decoding-engine)
- [Signature Library](#signature-library)
- [Security Labels](#security-labels)
- [Architecture](#architecture)
- [Detection Logic FAQ](#detection-logic-faq)
- [Custom Signatures](#custom-signatures)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Detection
- **140+ built-in signatures** for hashes, KDFs, encodings, ciphers,
  blockchain formats, key material, and file markers — each with hashcat/john mode hints
  where one exists.
- **Confidence scoring** from structure matching plus Shannon entropy. Scores
  are heuristics, printed as-is. Short inputs collide; that's expected.
- **Auto-repair** — strips colons/whitespace and fixes missing Base64 padding
  when the input looks like a hash or encoding. SSH keys, PGP blocks, and
  `/etc/shadow` lines are left alone.
- **Context flag** (`--context network|database|filesystem|memory|blockchain`)
  re-weights scores toward formats common in that setting. Unknown values warn
  and fall back to `generic`.
- **KDF parsing** — pulls cost/salt/params out of BCrypt, Argon2, Scrypt,
  PBKDF2, and decodes JWT header/payload.

### Decoding
- **10 classical cipher crackers** — Caesar, Atbash, Affine, Baconian,
  Vigenere, Rail Fence, Columnar, Simple Substitution, Playfair, Bifid —
  scored with Index of Coincidence, Chi-Squared, and quadgrams.
- **Recursive unwrapping** (`--deep-decrypt`) peels nested Hex/Base64/cipher
  layers with cycle detection, max 10 layers deep.
- **ROT and single-byte XOR crackers**, ranked by Chi-Squared. On short text
  the ranking is noisy — the top hit is a suggestion, not a verdict.
- **Interactive workshop** — a small REPL for trying decodings by hand, with
  history and undo.

### Forensics
- **Binary scanning** (`forensic scan`) with memory-mapped I/O for hashes and
  encoded strings inside disk images and dumps.
- **Volume inspection** (`forensic disk`) for NTFS (MFT walk, deleted files,
  ADS, `$Bitmap`/`$LogFile`/`$UsnJrnl` summaries), FAT12/16/32, and ext2/3/4
  (superblock, inode walk, extents). Partition auto-detect or `--offset`.
- **Carving** (`forensic carve`) by header/footer signatures, `--dry-run` to
  preview, matryoshka mode (`-M`) for nested archives with a 1 GB extraction
  quota so zip bombs can't fill your disk.
- **JSON output** (`-j`) on every command. One object per line for batch mode,
  so pipes work.

---

## Installation

### One-liner

```bash
curl -sSL https://raw.githubusercontent.com/meshackbahati/HashEndra/main/install.sh | bash
```

This downloads a prebuilt binary for your platform when one exists
(Linux x86_64/aarch64, macOS Intel/Apple Silicon, Windows x86_64),
otherwise it clones the repo and builds from source (needs Rust).
Flags: `--version 2.0.0` (pin a release), `--prefix DIR`,
`--from-source` (always build), `--keep`, `--uninstall`.

### Manual

```bash
git clone https://github.com/meshackbahati/HashEndra.git
cd HashEndra
cargo build --release
sudo cp target/release/hashendra /usr/local/bin/
```

### Verify

```bash
hashendra --version
hashendra --help
```

### Uninstall

```bash
bash install.sh --uninstall
# or: rm /usr/local/bin/hashendra
```

---

## Quick Start

```bash
# Identify a hash
hashendra "5d41402abc4b2a76b9719d911017c592"

# Decode Base64
hashendra --decode "SGVsbG8gV29ybGQ="

# Unwrap something encoded three times
hashendra --deep-decrypt "5a7a4a375757396656574666636d56665a325666546d6c7664584e664d4739516331397a6347567364463970564639796232356e66513d3d"

# Open the interactive workshop
hashendra workshop
```

---

## CLI Reference

```
Usage: hashendra [OPTIONS] [INPUT] [COMMAND]

Commands:
  update    Signature info (signatures ship with the binary)
  forensic  Scan files, inspect disks, and carve artifacts
  workshop  Start an interactive decoding workshop
  crack     Crack a hash against a wordlist (streaming, low memory)
  tls       Look up a TLS cipher suite by hex code (offline table)
  evm       Look up an EVM function selector (offline table)

Arguments:
  [INPUT]   The hash or encoded string to analyze

Options:
  -f, --file <FILE>        Read inputs from a file, one per line
  -j, --json               JSON output (NDJSON in batch mode)
  -v, --verbose            Extra metadata
      --decode             Decode one layer (Base64, Hex, URL, …)
      --deep-decrypt       Recursively unwrap up to 10 layers
      --rot                Brute-force all 25 ROT shifts
      --xor                Crack single-byte XOR
      --context <CTX>      generic (default), network, database,
                           filesystem, memory, blockchain
      --hash [<ALGO>]      Hash the input (md5, sha256, blake3, …)
      --list-hashes        List hash algorithms and exit
      --to <FORMAT>        Encode: base64, hex, url, binary, morse, …
      --list-encodings     List encoding formats and exit
      --encrypt <CIPHER>   Encrypt: caesar, vigenere, affine, rail-fence,
                           xor, columnar, atbash (with --key)
      --key <KEY>          Cipher key
      --cipher-param <N>   Extra param (e.g. rail count)
      --list-ciphers       List encryption ciphers and exit
      --custom-signatures <FILE>  Extra signatures JSON
```

**Forensics:**

```text
hashendra forensic scan <PATH> [--no-extract]
hashendra forensic disk <PATH> [--sector-size 512] [--offset BYTES]
    [--max-records N] [--deleted-only] [--include-directories]
    [--extract-data DIR] [--overwrite] [--fs ntfs|fat|ext4|…]
hashendra forensic carve ([PATH] | --input PATH) [-o DIR] [-t png,pdf]
    [-c profiles.conf] [-M --depth N] [--dry-run] [--list-types]
```

Run `hashendra --help` or `hashendra forensic <cmd> --help` — the binary is
the authority if this page drifts.

---

## Use Cases & Examples

### 1. Hash identification

```bash
hashendra "5d41402abc4b2a76b9719d911017c592"
```

Real output (abbreviated):

```
[INPUT]        : 5d41402abc4b2a76b9719d911017c592
[ENTROPY]      : 3.4803 bits/char
[CHARSET]      : Hex
[CONFIDENCE]   : [#######---] 72%

+-- DETECTION RESULTS -------------------------------------------+
|  [i] MD5                72%  [hashcat: 0] [john: raw-md5] |
|  [i] Base64 (MIME)      60%                            |
|  [i] RIPEMD-128         56%  [hashcat: 9000]            |
|  [i] NTLM               48%  [hashcat: 1000]            |
+----------------------------------------------------------------+

+-- RECOMMENDATION ----------------------------------------------+
   -> Primary : MD5 (Message-Digest Algorithm 5)
   -> Crack   : hashcat -m 0 hash.txt rockyou.txt
   -> Status  : Does not meet PCI DSS 4.0, NIST SP 800-131A
+----------------------------------------------------------------+
```

More:

```bash
hashendra "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA-256
hashendra '$2a$10$N9qo8uLOickgx2ZMRZoMy.Mr/.cIGPqnG3nj.3Jp6tNJ2vQm7Fv.y'      # BCrypt
hashendra "32ed87bdb5fdc5e9cba88547376818d4"                                 # NTLM
```

### 2. Messy input

Colons, stray whitespace, missing padding — cleaned up when the shape still
reads as a hash or encoding:

```bash
hashendra "5f4d:cc3b:5aa7:65d6:1d83:27de:b882:cf99"
hashendra "  5d41402abc4b2a76b9719d911017c592  "
hashendra --decode "SGVsbG8gV29ybGQ"
```

### 3. Contexts

```bash
hashendra "5d41402abc4b2a76b9719d911017c592" --context network
hashendra '$2a$10$N9qo8uLOickgx2ZMRZoMy.Mr/.cIGPqnG3nj.3Jp6tNJ2vQm7Fv.y' --context database
hashendra '$6$rounds=5000$salt$hash' --context filesystem
hashendra "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" --context blockchain
```

### 4. KDF and JWT details

```bash
hashendra '$2a$10$N9qo8uLOickgx2ZMRZoMy.Mr/.cIGPqnG3nj.3Jp6tNJ2vQm7Fv.y'
```

Pulls version/cost/salt from BCrypt; memory/time/parallelism from Argon2;
N/r/p from Scrypt; iterations from PBKDF2; header and payload from JWT.

### 5. Decoding

```bash
hashendra --decode "SGVsbG8gV29ybGQ="        # Base64 -> Hello World
hashendra --decode "48656c6c6f20576f726c64"  # Hex    -> Hello World
hashendra --decode "Hello%20World%21"        # URL    -> Hello World!
```

Handled: Base64, Hex (raw/spaced/`0x`/`\x`), URL, Base32, Base58
(Bitcoin/Flickr), Binary, Octal, Ascii85 (with or without `~>`),
Quoted-Printable, HTML entities, Morse.

### 6. Recursive unwrapping

```bash
hashendra --deep-decrypt "5a7a4a375757396656574666636d56665a325666546d6c7664584e664d4739516331397a6347567364463970564639796232356e66513d3d"
hashendra --deep-decrypt "t24frp{Lbh_ner_n_inyvqngrq_NTRAG}"   # ROT13 flag
hashendra --deep-decrypt "SGVsbG8gV29ybGQ="
```

`--decode` and `--deep-decrypt` share the same engine, so single-layer input
gives the same answer either way.

### 7. ROT brute-force

```bash
hashendra --rot "Uryyb Jbeyq"
```

```
[ROT] Brute-forcing ROT for: Uryyb Jbeyq
  * 16: Ebiil Tloia (chi2=24.0)
  + 24: Wtaad Ldgas (chi2=24.8)
  + 13: Hello World (chi2=28.4)
  + 09: Lipps Asvph (chi2=60.0)
  ...
```

`*` is the lowest Chi-Squared score, `+` marks the other plausible ones.
Note the honest wart above: on a 10-character input, gibberish outscores the
right answer. Chi-squared needs text to work with — short strings, check the
`+` rows yourself.

### 8. XOR cracking

```bash
hashendra --xor "Hello"        # raw ASCII bytes first
hashendra --xor "48656c6c6f"   # hex-decoded fallback
```

All 256 single-byte keys, ranked by printable ratio.

### 9. Forensics

```bash
hashendra forensic disk disk.dd
hashendra forensic disk disk.dd --ntfs --offset 1048576 --deleted-only --extract-data recovered/
hashendra forensic scan /path/to/evidence/
hashendra -j forensic scan evidence.raw --no-extract | jq '.hits'
```

Block devices, FIFOs, and broken symlinks are refused with an error, not
scanned.

### 10. Carving

```bash
hashendra forensic carve evidence.raw --types png,pdf --dry-run
hashendra forensic carve firmware.bin -M --depth 2
hashendra forensic carve --list-types
```

### 11. Workshop

```bash
hashendra workshop
hashendra workshop "SGVsbG8gV29ybGQ="
```

Commands include `/set`, `/load`, `/base64`, `/hex`, `/rot13`, `/xor`,
`/deep`, `/analyze`, `/status`, `/undo`, `/history`, `/exit` — `/help`
inside lists them all. Loading a binary file shows a hex preview first.

### 12. Batch and JSON

```bash
hashendra -f hashes.txt       # one input per line, streamed
hashendra -j -f hashes.txt    # NDJSON — one object per line, pipe-safe
hashendra -j "5d41402abc4b2a76b9719d911017c592"
```

Exit code is 0 even when nothing is found — check output content, not `$?`.

---

### 13. Password cracking

Dictionary cracker for raw hashes (MD5, SHA-1/224/256/384/512, BLAKE3).
The wordlist is memory-mapped and streamed — never loaded — so a 500K-line
wordlist costs ~17 MB RSS. Candidates are hashed as raw bytes (no hex
formatting in the hot loop) across an explicit rayon pool.

```bash
hashendra crack 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt
hashendra crack <hash> -w rockyou.txt --rules            # extended mutations
hashendra crack <hash> -w rockyou.txt --speed eco        # quarter cores, laptop mode
hashendra crack <hash> -w rockyou.txt --speed turbo -j   # all cores, JSON out
```

Light mutations (default): case variants plus 0-9 affixes. `--rules` adds
two-digit affixes, years, and common suffixes. Exit 0 only when cracked.

---

### 14. TLS and EVM lookups

Offline tables, no network:

```bash
hashendra tls 1301        # TLS_AES_128_GCM_SHA256, secure
hashendra tls 0x0005      # TLS_RSA_WITH_RC4_128_SHA, broken
hashendra evm a9059cbb    # transfer(address,uint256), ERC20
hashendra evm 0xa9059cbb0000...   # pasted calldata works, first 4 bytes used
```

---

## Classical Cipher Suite

| Cipher | Method |
|--------|--------|
| Caesar / ROT | All 26 shifts, Chi-Squared ranking |
| Atbash | Alphabet reversal |
| Affine | All 312 valid (a, b) pairs |
| Baconian | A/B decoding, 24- and 26-letter variants |
| Vigenere | IoC period guess + per-column Caesar |
| Rail Fence | Rails 2–10, Chi-Squared ranking |
| Columnar Transposition | Permutation search, small column counts |
| Simple Substitution | Hill climbing, quadgram scoring |
| Playfair | 5×5 grid, needs the keyword |
| Bifid | Polybius square, needs the period |

Playfair and Bifid decode with a key you supply; the rest attempt cracks.

---

## Layered Decoding Engine

Each layer tries its decoders in confidence order and follows the best one,
up to 10 layers, stopping on cycles or plaintext-looking output.

| Decoder | Confidence | Tried when |
|---------|-----------|------------|
| Hex | 1.1 | Always |
| Base64 / URL / Base32 / Base58 / Binary | 0.85–1.0 | Always |
| Ascii85 | 0.95 | Data present |
| Quoted-Printable | 0.9 | `=` escapes present |
| HTML entities | 0.9 | `&...;` present |
| Caesar / Atbash | 0.6–0.8 | No spaces, Chi-Squared improves |
| Baconian | 0.8 | A/B-only alphabet |
| Affine / Vigenere / Rail Fence / Columnar | 0.6–0.75 | Ciphertext heuristics |
| Single/multi-byte XOR | Varies | Printable output |

---

## Signature Library

~170 built-in signatures across:

- **Hashes**: MD4/MD5, SHA-1/224/256/384/512/3, RIPEMD, Whirlpool, Tiger,
  BLAKE2/3, Snefru, HAVAL, GOST, SM3, Streebog
- **Password KDFs**: BCrypt, Argon2, Scrypt, PBKDF2, Unix crypt, Django,
  Cisco, MSSQL, MySQL, Oracle, WordPress, Drupal, Joomla
- **Encodings**: Base64/32/58/85, Hex, URL, Punycode, UUencode, ROT13/47,
  EBCDIC, Morse, Binary, Octal
- **Blockchain**: Bitcoin (P2PKH, P2SH, Bech32), Ethereum, Litecoin (Base58 + Bech32),
  Monero, Ripple, Solana, IPFS CIDs, WIF keys
- **Key material**: PEM blocks (RSA/EC/OpenSSH/PKCS#8/X.509/CSR/PGP), SSH public
  keys, JWK, age recipients, Ansible Vault, PHC Scrypt, PQC OIDs (ML-KEM/ML-DSA/SLH-DSA)
- **File markers**: PNG chunks, JPEG Exif, TIFF, GIF, BMP, WebP, RIFF,
  OpenPGP, ZIP, PDF, ELF, PE, Mach-O, RAR, 7z, OLE2
- **Tokens & keys**: JWTs, AWS/Google/Stripe/GitHub/Slack/Twilio/SendGrid
  keys, SSH keys, PGP blocks, certs, UUIDs, IPs

---

## Security Labels

Detections carry an advisory rating and, where applicable, the standard it
fails:

| Rating | Meaning | Examples |
|--------|---------|----------|
| Secure | Fine to use | Argon2, SHA-3, BLAKE3 |
| Weak | Deploy carefully | SHA-1, low-iteration PBKDF2 |
| Broken | Don't use for security | MD5, MD4 |
| Insecure | Historically broken | DES, RC4-40 |

This is labeling, not an audit. It tells you MD5 is broken; it doesn't make
your system compliant with anything.

---

## Architecture

```
hashendra/
├── src/
│   ├── main.rs                      # CLI, workshop, run_* dispatch
│   ├── core/
│   │   ├── patterns.rs              # Signatures, scan_input()
│   │   ├── scanner.rs               # Entropy, scoring, decoders, ROT/XOR
│   │   ├── cryptanalysis.rs         # IoC, Chi-Squared, quadgrams
│   │   ├── recursive_engine.rs      # Layered decoding
│   │   ├── encoder.rs               # Encode/decode primitives
│   │   ├── hasher.rs                # Hash computation
│   │   └── entropy.rs               # Entropy helpers
│   ├── detectors/
│   │   ├── hashes.rs                # Hash signatures
│   │   ├── encodings.rs             # Encoding signatures
│   │   ├── ciphers.rs               # Cipher signatures
│   │   ├── classic_ciphers.rs       # 10 classical cipher crackers
│   │   └── stego.rs                 # File-marker signatures
│   ├── forensics/
│   │   ├── carve.rs                 # Carving (+ profiles, quota)
│   │   ├── disk.rs                  # Partition layouts, VBRs
│   │   ├── ntfs.rs                  # MFT walk, deleted-file recovery
│   │   ├── fat.rs                   # FAT12/16/32 recovery
│   │   ├── ext.rs                   # ext2/3/4 recovery
│   │   ├── report.rs                # Triage reports
│   │   ├── inspect.rs               # Header/metadata parsing
│   │   ├── strings.rs               # ASCII/UTF-16 extraction
│   │   ├── directory.rs             # Directory scan summaries
│   │   └── filetypes.rs             # File type detection
│   └── utils/
│       ├── io.rs                    # safe_print macros (mutex, broken-pipe safe)
│       └── io_manager.rs            # Memory-mapped forensic I/O
├── assets/logo.png
├── install.sh
├── Cargo.toml
└── README.md
```

Dependencies: `clap`, `colored`, `regex`, `rayon`, `memmap2`,
`serde`/`serde_json`, `hex`, `itertools`, `walkdir`, `num-bigint`.
Makes no network calls.

---

## Detection Logic FAQ

### Why does "test" detect as Base64?
Four characters satisfy Base64's structure, so it scores ~70%. Short
strings collide with everything — that's structural, not a bug. Add
`--context` or more input.

### Why does deep-decrypt stop early — or keep going?
It stops when the result reads as finished plaintext (spaces, English
markers like `flag`/`hello`, JSON shapes), on revisit (cycle), or at 10
layers. If it stops with `[i] ... without reaching clear plaintext`, it ran
out of confident moves — that message means "I don't know", not "decoded".
Input that already reads as plaintext gains no layers at all.

Two deliberate limits: statistical crackers (Vigenere/Affine need 30+
characters, Rail/Columnar 20+) sit out on short strings, because below that
Chi-Squared picks winners by luck. And `--rot`/`--xor` show every candidate
ranked — for short inputs, read the whole list instead of trusting layer 1.

### How do contexts work?
`--context network` raises weights for network-common formats and lowers
others. Unknown values warn and use `generic`.

### Can I add signatures?
Yes: `~/.hashendra/signatures.json` (array — see Custom Signatures below).
A bad regex prints a warning at startup and that entry is skipped.

### Why does XOR try ASCII first?
Raw bytes are the common case. Hex decoding runs only if the input looks
like hex and raw mode found nothing.

---

## Custom Signatures

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

---

## Contributing

Useful directions:

- More cipher crackers (ADFGVX, Four-Square, Polybius)
- Rolling/incrementing-key XOR detection
- ECB-vs-CBC block mode heuristics
- DES weak-key detection
- Decode-tree visualization
- More filesystems (ZFS, APFS/HFS+ recovery depth)

Tests are required: `cargo test` must stay green and `cargo clippy
--all-targets` warning-free. See [Development](docs/DEVELOPMENT.md).

---

## License

MIT — see [LICENSE](LICENSE).
