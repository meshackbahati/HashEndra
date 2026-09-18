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
| `--no-extract` | Don't carve embedded artifacts to disk |
| `-j, --json` | Global flag, goes before `forensic`: `hashendra -j forensic scan …` |

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
hashendra forensic carve -t jpg,png file.bin
hashendra forensic carve --quick --dry-run disk.dd
hashendra forensic carve --matryoshka --depth 5 malware.bin
```

Options:

| Flag | Description |
|---|---|
| `-i, --input <FILE>` | Input file or directory |
| `-o, --output <DIR>` | Output directory |
| `-t, --types <TYPES>` | Only these extensions, comma-separated (`-t jpg,png`) |
| `-a, --include-root` | Also match signatures at offset 0 |
| `-c, --config <FILE>` | Foremost-style config file |
| `-Q, --quick` | First hit per profile (fast mode) |
| `--min-size <BYTES>` | Minimum carve size (default: 1) |
| `--max-size <BYTES>` | Max size for formats without known footer |
| `--offset <BYTES>` | Starting byte offset |
| `--length <BYTES>` | Length limit from offset |
| `--sector-size <SIZE>` | Sector numbers in reports |
| `-M, --matryoshka` | Recursive extraction (carve inside carved) |
| `--depth <N>` | Max recursion depth |
| `--dry-run` | Report without writing |
| `-w, --audit-only` | Write audit log only |
| `--no-recursive` | Don't recurse into directories |
| `--overwrite` | Allow overwriting existing files |
| `--list-types` | List all supported carve types |

### `workshop`
Start an interactive decoding workshop.

```
hashendra workshop
```

### `crack`
Dictionary-crack a raw hash against a wordlist. Streams the file via mmap;
memory stays flat regardless of wordlist size.

```
hashendra crack 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt
hashendra crack <hash> -w rockyou.txt --format sha256 --rules --speed turbo
hashendra crack <hash> -w rockyou.txt --jobs 2 --max-candidates 1000000 -j
```

| Flag | Description |
|---|---|
| `--wordlist, -w` | Wordlist file (required) |
| `--format` | md5, sha1, sha256, … (default: auto-detect by length; 64-hex assumes SHA-256, use `--format blake3` to override) |
| `--rules` | Extended mutations (default: light case/digit set) |
| `--jobs` | Worker threads (default: from `--speed`) |
| `--speed` | `eco` (quarter cores), `normal` (half), `turbo` (all) |
| `--max-candidates` | Stop after N candidates |

Exit 0 only when the password is found.

### `tls`
Look up a TLS cipher suite (offline table, IANA-based).

```
hashendra tls 1301
hashendra tls 0xC02F
```

### `evm`
Look up an EVM function selector (offline table, accepts full calldata).

```
hashendra evm a9059cbb
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
| `--decrypt <CIPHER>` | Decrypt with cipher (same names/keys) | `hashendra --decrypt vigenere --key secret LXFOPV...` |
| `--key <KEY>` | Key for ciphers | See examples below, full table in CIPHERS.md |
| `--list-ciphers` | List all encryption ciphers | `hashendra --list-ciphers` |
| `-h, --help` | Print help | |
| `-V, --version` | Print version | |

## Examples

### Hash Identification
```bash
# Identify a hash type
hashendra "5d41402abc4b2a76b9719d911017c592"
# → MD5 at 72%, with hashcat/john modes and a crack recommendation

# Hash from file
hashendra -f password_hashes.txt

# JSON output for scripting
hashendra -j '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
```

### Encoding Detection & Decoding
```bash
# Detect encoding
hashendra "aGVsbG8gd29ybGQ="
# → Base64 at 90%

# Decode (one layer)
hashendra --decode "NzIzNjg2OTZkNjk2ZQ=="
# → Layer 1: Decoded Base64 -> 72368696d696e
# → then stops: hex-looking remainder is not valid hex, nothing further fires

# Deep recursive decode (unwrap all layers)
hashendra --deep-decrypt "SGVsbG8gV29ybGQ="
# → Layer 1: Base64 -> Hello World, then stops (plaintext reached)
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

# Decrypt with ciphers (same key formats; full table in CIPHERS.md)
hashendra --decrypt vigenere --key "secret" "LXFOPV..."
hashendra --decrypt adfgx --key "SQUARE,COLUMN" "DFAXFA..."
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

# Carve specific types only (comma-separated)
hashendra forensic carve -t jpg,png,zip file.bin -o images/

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

Workshop commands (full list via `/help` inside):

| Command | Description |
|---|---|
| `/set <text>` | Set current working text |
| `/load <path>` | Load a file into the buffer |
| `/forensic <path>` | Forensic scan on a file or directory |
| `/filetype [path]` | Identify file type |
| `/meta [path]` | Show file metadata |
| `/strings [n]` | Extract printable strings |
| `/context <ctx>` | Set analysis context |
| `/analyze` | Run detection on current text |
| `/base64`, `/hex`, `/base32`, `/base58` | Decode one layer |
| `/binary`, `/octal`, `/ascii85`, `/qp` | Decode one layer |
| `/html`, `/morse`, `/url` | Decode one layer |
| `/rot <n>`, `/rot13`, `/caesar <shift>` | Caesar shifts |
| `/vigenere`, `/beaufort`, `/autokey`, `/gronsfeld`, `/porta <key>` | Vigenère-family decode |
| `/affine <a> <b>`, `/atbash` | Affine / Atbash decode |
| `/rail <n>`, `/columnar <key>` | Transposition decode |
| `/polybius [key]`, `/tap` | Square / dots decode |
| `/adfgx`, `/adfgvx <sq> <ck>` | Fractionating decode |
| `/foursquare`, `/twosquare <k1> <k2>` | Digraph decode |
| `/trifid`, `/bifid <key> [period]` | Fractionating decode |
| `/playfair <key>`, `/bacon [AB]`, `/substitution <KEY26>` | Grid / code decode |
| `/xor <key>` | XOR with a string key |
| `/deep` | Run the auto-unwrapper |
| `/status`, `/history`, `/undo` | State management |
| `/exit` | Exit workshop |

### Batch Processing
```bash
# Process multiple hashes from a file
hashendra -f hashes.txt

# With JSON output for parsing
hashendra -j -f hashes.txt
```
