# HashEndra CLI Reference

## Usage

```
hashendra [OPTIONS] [INPUT] [COMMAND]
```

## Commands

### `update`
Update the signature database.

```
hashendra update
```

### `forensic scan`
Run forensic analysis on a file or directory.

```
hashendra forensic scan ./malware.bin
hashendra forensic scan --json ./disk_image.dd
```

Options:

| Flag | Description |
|---|---|
| `-j, --json` | JSON output |
| `-v, --verbose` | Verbose output |
| `--strings` | Extract strings |
| `--no-entropy` | Skip entropy calculation |

### `forensic disk`
Inspect a disk image or volume.

```
hashendra forensic disk disk_image.dd
hashendra forensic disk --fs ntfs --offset 1048576 --deleted-only disk.dd
hashendra forensic disk --extract-data recovered/ --ntfs disk.dd
```

Options:

| Flag | Description |
|---|---|
| `--sector-size <SIZE>` | Sector size (default: 512) |
| `--offset <BYTES>` | Byte offset to the filesystem volume |
| `--max-records <N>` | Max records to inspect (default: 256) |
| `--deleted-only` | Show only deleted entries |
| `--include-directories` | Include directory records |
| `--extract-data <DIR>` | Recover filesystem data streams |
| `--ntfs` | Force NTFS handling |
| `--fs <NAME>` | Explicit filesystem type (ntfs, fat, ext4, btrfs) |

### `forensic carve`
Carve embedded files from a binary.

```
hashendra forensic carve image.dd -o carved/
hashendra forensic carve -t jpg -t png -t zip file.bin
hashendra forensic carve --quick --dry-run disk.dd
hashendra forensic carve --matryoshka --depth 5 malware.bin
```

Options:

| Flag | Description |
|---|---|
| `-i, --input <FILE>` | Input file or directory |
| `-o, --output <DIR>` | Output directory |
| `-t, --types <TYPES>` | File types to carve (jpg, png, zip, ...) |
| `-c, --config <FILE>` | Foremost-style config file |
| `-Q, --quick` | First hit per profile (fast mode) |
| `--min-size <BYTES>` | Minimum carve size (default: 1) |
| `--max-size <BYTES>` | Max size for formats without known footer |
| `--offset <BYTES>` | Starting byte offset |
| `--length <BYTES>` | Length limit |
| `-M, --matryoshka` | Recursive extraction (carve inside carved) |
| `--depth <N>` | Max recursion depth |
| `--dry-run` | Report without writing |
| `-w, --audit-only` | Write audit log only |
| `--list-types` | List all supported carve types |

### `workshop`
Start an interactive decoding workshop.

```
hashendra workshop
```

## Options

| Flag | Description | Example |
|---|---|---|
| `<INPUT>` | The hash, encoded string, or text to analyze | `hashendra "5d41402abc4b2a76b9719d911017c592"` |
| `-f, --file <FILE>` | Process hashes/strings from a file | `hashendra -f hashes.txt` |
| `-j, --json` | JSON output format | `hashendra -j "d2Vi"` |
| `-v, --verbose` | Verbose technical details | `hashendra -v "Uryyb"` |
| `--decode` | Decode the input | `hashendra --decode "aGVsbG8="` |
| `--deep-decrypt` | Deep recursive unwrapping | `hashendra --deep-decrypt "NzIzNjg2OTZkNjk2ZQ=="` |
| `--rot` | Brute-force ROT cipher | `hashendra --rot "Uryyb Jbeyq"` |
| `--xor` | Crack single-byte XOR | `hashendra --xor "1b37373331363f78151b7f2b783431333d"` |
| `--context <CTX>` | Detection context | `--context network` |
| `--hash [<ALGO>]` | Compute hash of input | `hashendra --hash sha256 hello` |
| `--list-hashes` | List all hash algorithms | `hashendra --list-hashes` |
| `--to <FORMAT>` | Encode input to format | `hashendra --to base64 hello` |
| `--list-encodings` | List all encoding formats | `hashendra --list-encodings` |
| `--encrypt <CIPHER>` | Encrypt with cipher | `hashendra --encrypt caesar --key 13 hello` |
| `--key <KEY>` | Key for encryption | See examples below |
| `--list-ciphers` | List all encryption ciphers | `hashendra --list-ciphers` |
| `-h, --help` | Print help | |
| `-V, --version` | Print version | |

## Examples

### Hash Identification
```bash
# Identify a hash type
hashendra "5d41402abc4b2a76b9719d911017c592"
# → Identifies as MD5 (95% confidence)

# Hash from file
hashendra -f password_hashes.txt

# JSON output for scripting
hashendra -j '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
```

### Encoding Detection & Decoding
```bash
# Detect encoding
hashendra "aGVsbG8gd29ybGQ="
# → Identifies as Base64 (98% confidence)

# Decode (one layer)
hashendra --decode "NzIzNjg2OTZkNjk2ZQ=="
# → "hex:726c696e65"

# Deep recursive decode (unwrap all layers)
hashendra --deep-decrypt "NzIzNjg2OTZkNjk2ZQ=="
# → Layer 1: Decoded Base64 → "726c696e65"
# → Layer 2: Decoded Hex → "rline"
```

### Encoding / Hashing / Encryption
```bash
# Compute hashes
hashendra --hash md5 "hello world"
hashendra --hash sha256 "hello world"
hashendra --hash blake3 "hello world"

# Encode to format
hashendra --to base64 "hello"
hashendra --to hexupper "hello"
hashendra --to morse "SOS"
hashendra --to binary "hello"

# Encrypt with ciphers
hashendra --encrypt caesar --key 13 "hello world"
hashendra --encrypt vigenere --key "secret" "attack at dawn"
hashendra --encrypt affine --key "5,8" "hello"
hashendra --encrypt rail-fence --key 3 --cipher-param 3 "hello world"
hashendra --encrypt xor --key "key" "secret message"
```

### Cipher Cracking
```bash
# ROT brute-force
hashendra --rot "Uryyb Jbeyq"

# Single-byte XOR crack
hashendra --xor "1b37373331363f78151b7f2b783431333d"
```

### Context-Aware Detection
```bash
hashendra --context network "GET /index.html HTTP/1.1"
hashendra --context database "SELECT * FROM users"
hashendra --context blockchain "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
```

### File Carving
```bash
# Basic carve all types
hashendra forensic carve disk_image.dd -o carved/

# Carve specific types only
hashendra forensic carve -t jpg -t png -t zip file.bin -o images/

# Quick mode (first match per type)
hashendra forensic carve --quick disk.dd -o output/

# Recursive carving (carve inside carved files)
hashendra forensic carve -M --depth 3 malware.bin -o extracted/

# Dry run (see what would be carved)
hashendra forensic carve --dry-run disk.dd

# List supported types
hashendra forensic carve --list-types
```

### Forensic Inspection
```bash
# Scan a file with metadata extraction
hashendra forensic scan image.jpg
hashendra forensic scan document.docx
hashendra forensic scan malware.elf

# Inspect a disk image
hashendra forensic disk disk_image.dd

# NTFS-specific with deleted file recovery
hashendra forensic disk --fs ntfs --deleted-only --extract-data recovered/ disk.dd
```

### Interactive Workshop
```bash
hashendra workshop
```

Workshop commands:

| Command | Description |
|---|---|
| `scan <input>` | Scan a string |
| `decode <input>` | Decode a string |
| `rot <input>` | ROT brute-force |
| `xor <hex>` | XOR crack |
| `hash <algo> <input>` | Compute hash |
| `encode <format> <input>` | Encode string |
| `context <ctx>` | Set detection context |
| `json` | Toggle JSON output |
| `help` | Show help |
| `exit` | Exit workshop |

### Batch Processing
```bash
# Process multiple hashes from a file
hashendra -f hashes.txt

# With JSON output for parsing
hashendra -j -f hashes.txt
```
