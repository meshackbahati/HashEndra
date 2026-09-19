# HashEndra User Guide

## What HashEndra does

HashEndra identifies hashes, encodings, and ciphertext from a string,
then decodes, decrypts, or cracks them as appropriate. It also
inspects files and disk images for metadata, embedded content, and
filesystem structures. The sections below follow that order.

## Quick Start

### Identify a hash

```bash
hashendra "5d41402abc4b2a76b9719d911017c592"
```

HashEndra will:
- Detect the hash type (MD5, 72% confidence)
- Show the character length (32 hex characters)
- Display the entropy (≈3.5 bits/char)
- Recommend a hashcat cracking command

### Decode an encoded string

```bash
hashendra --decode "aGVsbG8="
```

### Unwrap multi-layer encoding

```bash
hashendra --deep-decrypt "NzIzNjg2OTZkNjk2ZQ=="
```

This recursively unwraps each layer. It stops at plaintext, on revisit,
or at 10 layers, and reports the stopping condition when it never
reaches plaintext. Short or ambiguous input may stop after one layer;
check `--rot` and `--xor` output directly in that case.

### Carve files from a disk image

```bash
hashendra forensic carve disk_image.dd -o carved/
```

## Detection System

HashEndra scores candidates on several independent measurements:

- **Pattern matching**: regular expressions matched against the signature set
- **Length analysis**: hash lengths mapped to candidate algorithms
- **Entropy calculation**: Shannon entropy in bits per character
- **Charset detection**: hex, Base64, ASCII, Base58, binary, and others
- **Context weighting**: network, database, and filesystem contexts adjust scores
- **Validation**: trial decoding to confirm a candidate before reporting it

### Detection Contexts

Use `--context` to improve detection accuracy:

| Context | Use Case |
|---|---|
| `generic` | Default general-purpose detection |
| `network` | HTTP headers, JWTs, network tokens |
| `database` | SQL queries, database credentials |
| `filesystem` | File paths, permissions |
| `web` | URL parameters, form data |
| `crypto` | Cryptographic keys, certificates |
| `blockchain` | Bitcoin addresses, private keys |
| `windows` | Windows registry, Active Directory |
| `linux` | Shadow files, SSH keys |
| `docker` | Container images, secrets |

## Encoding Formats

| Format | `--to` Name | Description |
|---|---|---|
| Base64 | `base64` | Standard Base64 with `=` padding |
| Base64 URL | `base64url` | URL-safe Base64 (no `+/`, uses `-_`) |
| Base32 | `base32` | RFC 4648 Base32 |
| Base58 | `base58` | Bitcoin-style Base58 (no `0OIl`) |
| Hexadecimal | `hex` | Lowercase hex |
| Hex Upper | `hexupper` | Uppercase hex |
| URL Encoding | `url` | Percent-encoding (RFC 3986) |
| HTML Entities | `html` | HTML entity encoding |
| Quoted-Printable | `qp` | MIME quoted-printable |
| Binary | `binary` | 0s and 1s |
| Octal | `octal` | Octal byte representation |
| Morse Code | `morse` | International Morse code |
| ASCII85 | `ascii85` | Adobe-style ASCII85 |

## Hash Algorithms

| Algorithm | `--hash` Name | Hashcat Mode |
|---|---|---|
| MD5 | `md5` | 0 |
| SHA-1 | `sha1` | 100 |
| SHA-224 | `sha224` | 1300 |
| SHA-256 | `sha256` | 1400 |
| SHA-384 | `sha384` | 1410 |
| SHA-512 | `sha512` | 1700 |
| BLAKE3 | `blake3` | n/a |

## Classical Ciphers

| Cipher | `--encrypt` Name | Key Format |
|---|---|---|
| Caesar | `caesar` | Shift number (e.g., `13`) |
| Vigenere | `vigenere` | Keyword string |
| Affine | `affine` | `a,b` integers (e.g., `5,8`) |
| Rail-Fence | `rail-fence` | Number of rails + `--cipher-param` height |
| XOR | `xor` | Key string |
| Columnar | `columnar` | Column order key |
| Atbash | `atbash` | No key needed |

## File Carving

HashEndra can carve 20+ file types from raw binary data.

### Supported Types

```
jpg, png, gif, bmp, tiff, ico, pdf, doc, zip, gz,
rar, 7z, elf, pe, macho, sqlite, wav, avi, mp4, mp3,
flac, ole2, mft, lnk
```

### Carve Options Explained

| Option | Effect |
|---|---|
| `--quick` | Stops after first match per type. Fast for known files. |
| `--matryoshka` | Recursively carves inside carved files (e.g., ZIP inside JPEG). |
| `--depth <N>` | Limits recursion depth (default: unlimited). |
| `-t <TYPE>` | Only carve specific types. Repeat for multiple types. |
| `--dry-run` | Reports what would be carved without writing files. |
| `--max-size <N>` | Caps file size for types without known footers. |
| `--audit-only` | Writes a JSON audit log instead of carving. |

### Deduplication

HashEndra automatically deduplicates carved files using BLAKE3 hashing. If the same file is found at multiple offsets, only the first copy is extracted.

### Safety

A hard 10 GiB extraction quota is enforced at the carving engine level. It cannot be bypassed with command-line options because it is compiled into the binary.

## Disk Forensics

### Supported Filesystems

- **NTFS**: MFT parsing, resident and stream data, deleted entry recovery, `$Bitmap`, `$LogFile`
- **FAT12/16/32**: BPB parsing, directory entries, long filename support, deleted entry recovery
- **ext2/3/4**: superblock parsing, inode tables, extent trees, deleted inode recovery
- **Btrfs**: superblock parsing

### Disk Inspection

```bash
# Basic disk scan
hashendra forensic disk disk_image.dd

# NTFS with deleted file recovery
hashendra forensic disk --fs ntfs --deleted-only disk.dd

# Extract recoverable files
hashendra forensic disk --extract-data recovered/ --ntfs disk.dd

# Explicit offset for partition
hashendra forensic disk --offset 1048576 --fs ext4 disk.dd
```

## Metadata Inspection

HashEndra can extract metadata from 20+ file formats:

```bash
hashendra forensic scan image.jpg
hashendra forensic scan document.docx
hashendra forensic scan song.mp3
```

Extracted metadata includes:

| Format | Metadata |
|---|---|
| JPEG | EXIF camera model, ISO, aperture, GPS, JFIF |
| PNG | IHDR dimensions, gAMA, pHYs, tEXt, tIME |
| GIF | Version, dimensions, frame count, comments |
| BMP | Size, dimensions, bit depth, compression |
| ICO | Icon count, entry sizes |
| TIFF | IFD tags via TIFF/EXIF parsing |
| MP3 | ID3v1/v2 tags (title, artist, album), bitrate |
| FLAC | STREAMINFO, Vorbis comments |
| WAV | Sample rate, channels, bits, duration |
| AVI | Frame rate, dimensions, streams |
| MP4/MOV | Brands, duration, dimensions, metadata atoms |
| OOXML | Title, author, dates, word/slide count |
| ELF | Architecture, type, entry point, sections |
| PE | Machine type, sections, timestamp, subsystem |
| Mach-O | CPU type, file type, load commands |
| ZIP | Entry count, compression, encryption |
| GZIP | Compression mode, mtime, original name |
| SQLite | Page size, encoding, schema format |

## Entropy Analysis

HashEndra provides binwalk-style entropy analysis:

- **Rolling entropy**: sliding-window Shannon entropy
- **Boundary detection**: transitions between low and high entropy regions
- **Segment classification**: regions labeled low, medium, high, or very-high entropy
- **ASCII visualization**: bar chart for inline display

### Interpreting Entropy

| Entropy Range | Typical Content |
|---|---|
| 0.0-2.0 | Compressed, encrypted, or empty data |
| 2.0-4.0 | Binary code, structured data |
| 4.0-6.0 | Mixed content, partially structured |
| 6.0-8.0 | Text, high-information payloads |

## JSON Output

Use `--json` for machine-parseable output:

```bash
hashendra -j "5d41402abc4b2a76b9719d911017c592"
```

The JSON output is flat: input measurements at the top level and a
ranked `results` array. Confidence is a 0-1 float. The top match is
shown here; further candidates follow in the same array.

```json
{
  "charset": "Hex",
  "context": "Generic",
  "entropy": 3.4803377974034158,
  "input": "5d41402abc4b2a76b9719d911017c592",
  "results": [
    {
      "common_name": "md5",
      "compliance_refs": ["PCI DSS 4.0", "NIST SP 800-131A"],
      "confidence": 0.7199999690055847,
      "description": "Message-Digest Algorithm 5",
      "hashcat_mode": 0,
      "john_format": "raw-md5",
      "name": "MD5",
      "security_rating": "Broken"
    }
  ]
}
```

## Interactive Workshop

The workshop is a REPL for interactive analysis. It keeps a working
buffer and applies the same detection, decoding, and cipher operations
as the CLI flags, one step at a time. It suits iterative work where
retyping full commands is slow. Run it with:

```bash
hashendra workshop
```

Type `/help` inside for the command list. The full table is also in
the CLI reference under Interactive Workshop.
