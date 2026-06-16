# Configuration & Custom Algorithms

## Overview

HashEndra supports two kinds of user configuration:

1. **Custom Detection Signatures** — Add your own hash, encoding, or cipher patterns
2. **Custom Carve Profiles** — Define new file types for carving

## Custom Detection Signatures

### Signature File Location

HashEndra automatically loads custom signatures from:
```
~/.hashendra/signatures.json
```

This file is a JSON array of `Signature` objects. If the file doesn't exist, no custom signatures are loaded.

### Signature Schema

```json
{
  "name": "Display Name",
  "description": "Human-readable description",
  "pattern": "^regex_pattern$",
  "detection_type": "Hash",
  "confidence_weight": 0.85,
  "common_name": "shorthand_name",
  "hashcat_mode": 0,
  "john_format": "raw-md5",
  "security_rating": "Weak",
  "compliance_refs": ["PCI DSS 4.0"],
  "parameters": ["group1", "group2"]
}
```

| Field | Required | Type | Description |
|---|---|---|---|
| `name` | Yes | string | Displayed in detection results |
| `description` | Yes | string | Shown alongside the name |
| `pattern` | Yes | string | Rust regex. Must compile! |
| `detection_type` | Yes | `"Hash"` / `"Encoding"` / `"Cipher"` / `"Stego"` | Category |
| `confidence_weight` | Yes | float (0.0–1.0) | Base confidence multiplier |
| `common_name` | No | string | CLI shorthand (not used yet) |
| `hashcat_mode` | No | int | Shown in detection results for crack suggestions |
| `john_format` | No | string | Shown in detection results |
| `security_rating` | No | `"Secure"` / `"Weak"` / `"Broken"` / `"Insecure"` | Security classification |
| `compliance_refs` | No | string[] | Compliance standard references |
| `parameters` | No | string[] | Named capture groups in `pattern` to extract |

### Examples

#### Custom Hash Signature

```json
[
  {
    "name": "MyApp Hash",
    "description": "Internal hash format used by MyApp",
    "pattern": "^[A-F0-9]{64}$",
    "detection_type": "Hash",
    "confidence_weight": 0.85,
    "common_name": "myapp",
    "security_rating": "Weak",
    "parameters": []
  }
]
```

Now when HashEndra scans a 64-char uppercase hex string, it will show:

```
|  [OK] MyApp Hash                        85%                       |
```

#### Custom Encoding with Parameter Extraction

```json
[
  {
    "name": "Custom Auth Token",
    "description": "Bearer token format: Bearer_<base64>_<id>",
    "pattern": "^Bearer_(?P<data>[A-Za-z0-9+/]+)_(?P<id>\\d+)$",
    "detection_type": "Encoding",
    "confidence_weight": 0.9,
    "parameters": ["data", "id"]
  }
]
```

Detection shows:
```
|  [OK] Custom Auth Token                 90%                       |
|      -> data: dGhpcyBpcyBkYXRh           |
|      -> id: 12345                        |
```

#### Override Built-in Detection

You can override any built-in signature by using the same `name`. For example, to increase MD5 confidence:

```json
[
  {
    "name": "MD5",
    "description": "Message-Digest Algorithm 5",
    "pattern": "^[a-fA-F0-9]{32}$",
    "detection_type": "Hash",
    "confidence_weight": 0.95,
    "common_name": "md5",
    "hashcat_mode": 0,
    "security_rating": "Broken",
    "compliance_refs": ["PCI DSS 4.0"],
    "parameters": []
  }
]
```

Your custom definition takes precedence over the built-in one.

#### Detecting Custom File Types (Stego)

```json
[
  {
    "name": "MyApp Database",
    "description": "MyApp's proprietary database format",
    "pattern": "^MYDB",
    "detection_type": "Stego",
    "confidence_weight": 0.95,
    "parameters": []
  }
]
```

### Verification

To verify your custom signatures are loaded:

```bash
# Custom hashes appear in --list-hashes output
hashendra --list-hashes

# Test detection
hashendra "MYAPP_HASH_VALUE"
```

Look for the `WARN` messages at startup — if the JSON is malformed, HashEndra prints a warning with details.

## Custom Carve Profiles

Custom carve profiles are defined in a **foremost-style config file** and loaded with `--config`.

### Config File Format

```
<extension> <needs_footer> <max_size> <header_pattern> [footer_pattern] <description>
```

Fields are space-separated:

| Field | Description |
|---|---|
| `extension` | File extension for output (e.g., `jpg`, `pdf`) |
| `needs_footer` | `y` or `n` — whether a footer is required |
| `max_size` | Max carve size in bytes. `0` = no limit |
| `header_pattern` | Hex bytes for header, `?` for wildcard (e.g., `FFD8FF` for JPEG) |
| `footer_pattern` | Hex bytes for footer, `-` if none |
| `description` | Human-readable name |

### Example

```
jpg y 0 FFD8FF FFD9 JPEG Image
png y 0 89504E47 49454E44 PNG Image
zip y 0 504B0304 504B0506 ZIP Archive
pdf y 0 25504446 2525454F46 PDF Document
elf n 4096 7F454C46 - ELF Binary
mydb y 1048576 DEADBEEF CAFEBABE MyApp Database
```

### Usage

```bash
# Carve with custom profiles
hashendra forensic carve -c my_profiles.conf disk.dd -o carved/

# List types from custom config
hashendra forensic carve -c my_profiles.conf --list-types

# Mix custom and builtin types
hashendra forensic carve -c my_profiles.conf -t jpg -t mydb disk.dd
```

### Wildcards in Patterns

Use `?` to match any byte in the header/footer:

```
# Match any 2-byte header followed by 0x00 0x01
myfmt n 1024 00??0001 -
```

## Future: Custom Hash/Encode/Encrypt Algorithms

Currently, custom algorithms (actual encoding/hashing/encryption functions) require modifying the Rust source code. If you need a new encoding format, hash algorithm, or cipher, please consider contributing to the project.

The architecture is designed to make this straightforward:

- **Encoding**: Add function to `src/core/encoder.rs`, register in `ENCODING_FORMATS`
- **Hashing**: Add function to `src/core/hasher.rs`, register in `HASH_ALGORITHMS`
- **Ciphers**: Add function to `src/core/scanner.rs`, register in `handle_encrypt()`

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed instructions.
