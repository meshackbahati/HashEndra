# HashEndra wiki

HashEndra takes an unknown string, file, or disk image and reports what
it most likely is, with a confidence score and a suggested next step.
It identifies hash types, decodes layered encodings, encrypts and
decrypts with classical and modern ciphers, runs standard RSA attacks
for CTF work, cracks wordlist hashes, and performs forensic triage
including carving and filesystem inspection. It runs fully offline.

Repository: https://github.com/meshackbahati/HashEndra

Further reading in this repository:

- CLI reference: https://github.com/meshackbahati/HashEndra/blob/main/docs/CLI.md
- User guide: https://github.com/meshackbahati/HashEndra/blob/main/docs/USER_GUIDE.md
- Cipher usage: https://github.com/meshackbahati/HashEndra/blob/main/docs/CIPHERS.md
- Detection system: https://github.com/meshackbahati/HashEndra/blob/main/docs/DETECTORS.md
- Forensics module: https://github.com/meshackbahati/HashEndra/blob/main/docs/FORENSICS.md
- Architecture: https://github.com/meshackbahati/HashEndra/blob/main/docs/ARCHITECTURE.md
- Configuration: https://github.com/meshackbahati/HashEndra/blob/main/docs/CONFIGURATION.md
- Development guide: https://github.com/meshackbahati/HashEndra/blob/main/docs/DEVELOPMENT.md

## Installation

Install with the installer. It fetches a prebuilt binary for your
platform when one exists (Linux x86_64 and aarch64, macOS Intel and
Apple Silicon, Windows x86_64), and builds from source otherwise:

```
curl -sSL https://raw.githubusercontent.com/meshackbahati/HashEndra/main/install.sh | bash
```

Useful flags: `--version 2.0.0` to pin a release, `--prefix DIR` to
choose the install location, `--from-source` to always build,
`--uninstall` to remove. Contributors building from a checkout should
follow the development guide instead:
https://github.com/meshackbahati/HashEndra/blob/main/docs/DEVELOPMENT.md

The current version is 2.0.0.

## Identifying input

```
$ hashendra "5d41402abc4b2a76b9719d911017c592"

[INPUT]        : 5d41402abc4b2a76b9719d911017c592
[CONTEXT]      : Generic
[LENGTH]       : 32 characters
[ENTROPY]      : 3.4803 bits/char
[CHARSET]      : Hex
[CONFIDENCE]   : [#######---] 72%
[SECURITY]     : BROKEN

+-- DETECTION RESULTS -------------------------------------------+
|  [i] MD5                72%  [hashcat: 0] [john: raw-md5] |
```

Each analysis reports the input measurements (length, Shannon entropy
in bits per character, detected charset) followed by ranked candidate
matches. Hash candidates include their hashcat mode and John the
Ripper format so the result feeds directly into dedicated crackers.
The security label reflects the algorithm's standing: MD5 is marked
BROKEN because of practical collision attacks.

The `-j` flag emits the same result as JSON for scripting, and `-f`
reads inputs line by line from a file for batch processing.

## Decoding

Single-layer decoding unwraps one encoding and reports the layer:

```
$ hashendra --decode "aGVsbG8="
  Layer 1: Decoded Base64 -> hello
[OK] Decoded 1 layers to: hello
```

`--deep-decrypt` applies decoders recursively until the output
stabilizes, a previous state repeats, or the layer limit is reached.
When no clear plaintext is reached, it reports the stopping condition
and the best candidate instead of presenting a guess as a result:

```
$ hashendra --deep-decrypt "NzI3Ng=="
[i] Stopped after 1 layer(s) without reaching clear plaintext.
[i] Best candidate so far: 7276
```

The decimal codec accepts space, comma, or newline separated byte
values from 0 to 255. Values outside that range are rejected rather
than coerced, which keeps timestamps and version numbers from decoding
into spurious output.

## Computing hashes

```
$ hashendra --hash sha256 "hello world"

-- Hash Results --
  SHA-256:   b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

Supported algorithms are listed by `--list-hashes`: MD5, SHA-1, the
SHA-2 family, BLAKE3, and HMAC-SHA-256/512 with a `--key`, which is
required and reported as an error when missing. The `--hex-input`
flag hashes the hex-decoded bytes of the input instead of its text,
which is the correct behavior when the hashed value is key material
or a KDF input rather than readable text:

```
$ hashendra --hash sha256 --hex-input 29b035d9...3b041

-- Hash Results --
  SHA-256:   700314a82871cac61d028f13a0d560b0d028e1e59698f9bf4ccf8853e2fb38e3
```

## Classical ciphers

Encryption and decryption share cipher names and key formats
(`--list-ciphers` prints all 27 with key format notes). Examples:

```
$ hashendra --encrypt caesar --key 13 "hello"

-- Encrypted Output --
uryyb
```

```
$ hashendra --encrypt affine --key "5,8" "hello"

-- Encrypted Output --
rclla
```

Keys vary by cipher: a shift number for Caesar, a keyword for
Vigenere, an `a,b` pair for Affine, square and column keys for ADFGX,
and `--cipher-param` for secondary parameters such as rail counts.
The cipher usage page documents every key format:
https://github.com/meshackbahati/HashEndra/blob/main/docs/CIPHERS.md

Two keyless cracking modes are available. `--rot` scores all Caesar
shifts with chi-squared statistics:

```
$ hashendra --rot "Uryyb Jbeyq"
[ROT] Brute-forcing ROT for: Uryyb Jbeyq
  * 16: Ebiil Tloia (chi2=24.0)
  + 24: Wtaad Ldgas (chi2=24.8)
  + 13: Hello World (chi2=28.4)
  ...
```

`--xor` cracks single-byte XOR over hex input and orders
flag-shaped candidates first:

```
$ hashendra --xor e39690dff69190fb90c6fd9191fbc890fd97d697e0fbcf97fdfbc097f695d290939594eafb9194c8f297c0d9
[XOR] Attempting single-byte XOR crack...
  [as hex-decoded bytes]:
    Key 0xa4 (Score 1.00): G24{R54_4bY55_l4Y3r3D_k3Y_d3R1v4710N_50lV3d}
    Key 0xa1 (Score 1.00): B71~W01Z1g\00Zi1\6w6AZn6\Za6W4s1245KZ05iS6ax
    ...
```

## Modern cryptography

Symmetric keys, IVs, nonces, and RSA components are accepted as hex.
AES-CBC and AES-ECB accept 16, 24, or 32 byte keys with a 16 byte IV
for CBC. AES-GCM uses a 16 byte key with the 16 byte tag appended to
the ciphertext. Decryption verifies the tag and reports an error on
any mismatch of key, nonce, or ciphertext; it never outputs
unauthenticated plaintext.

GCM nonces are not restricted to 12 bytes. The standard length uses
the crate implementation, and other lengths use the GHASH J0
derivation from NIST SP 800-38D, matching PyCryptodome behavior. Unit
tests carry PyCryptodome vectors for 8 and 16 byte nonces.

Textbook RSA encrypts small hex messages from `n,e` pairs, and
`rsa-keygen` generates practice keypairs. These implement raw modular
exponentiation for CTF mathematics. They are not padded encryption
and are unsuitable for protecting real data.

## RSA attacks

The `rsa` subcommand covers four standard CTF attacks:

```
hashendra rsa gcd <n1hex> <n2hex>
hashendra rsa wiener <nhex> <ehex>
hashendra rsa hastad <c1> <n1> <c2> <n2> <c3> <n3>
hashendra rsa fermat <nhex>
```

These address shared primes across moduli, small private exponents,
e=3 broadcast across three moduli, and close primes factored outward
from the integer square root:

```
$ hashendra rsa fermat E8D6CA6163
[OK] Fermat factored n:
  p = 0f4261
  q = 0f4243
```

Unsuccessful attacks report failure explicitly. A clean negative
result closes a line of inquiry, which matters as much as a positive
one during timed work.

## Wordlist cracking

```
$ hashendra crack 5d41402abc4b2a76b9719d911017c592 -w wordlist.txt --format md5
[CRACK] MD5 against wordlist.txt (light rules, Normal speed)
[OK] Cracked in 0.0s (3 candidates, 3000 H/s)
  password: hello
```

The wordlist is memory mapped and streamed, so candidate files of any
size process with flat memory usage. Mutation rules, thread count,
candidate limits, and rayon speed tiers (`eco`, `normal`, `turbo`)
are configurable. The exit code is 0 only when a password is found.

## Forensics

`forensic scan` reports file metadata, EXIF and format-specific
fields where applicable, string tables, and matched signatures.
`forensic carve` extracts embedded files from images with header and
footer profiles, BLAKE3 deduplication, and a compiled-in 10 GiB
extraction quota. `forensic disk` parses NTFS, FAT, ext, and Btrfs
structures including deleted entry recovery. Large inputs are memory
mapped and streamed rather than loaded into memory. Full details are
on the forensics page:
https://github.com/meshackbahati/HashEndra/blob/main/docs/FORENSICS.md

## Offline lookup tables

Two reference tables ship in the binary for recurring triage
questions. TLS cipher suite codes resolve with a security rating:

```
$ hashendra tls 1301
TLS suite 0x1301: TLS_AES_128_GCM_SHA256
  rating: secure
  note: TLS 1.3 default
```

EVM function selectors resolve from a bare selector or full
calldata:

```
$ hashendra evm a9059cbb
0xa9059cbb: transfer(address,uint256)
  area: ERC20
```

## Interactive workshop

The `workshop` subcommand opens a REPL with slash-prefixed commands
for decoding layers, shifting ciphers, running detection, and
managing a working buffer. The full command table is in the CLI
reference:
https://github.com/meshackbahati/HashEndra/blob/main/docs/CLI.md

## Solved case studies

The following challenges were solved with this tool. Complete
transcripts are kept alongside each challenge in `ctf-challenges/`.

**borrowed-bits.** A bundle export lost the low 72 bits of an RSA
prime. With a 1024-bit modulus, 72 unknown bits fall well inside the
Coppersmith bound, and Sage `small_roots` recovered the missing bits.
The private exponent followed by standard arithmetic. The remaining
steps ran entirely in HashEndra: `--hash sha256 --hex-input` derived
the AES key under the stated KDF, and `--decrypt aes-gcm` with the
16-byte nonce opened the ciphertext. This challenge motivated both
the general GCM nonce support and the `--hex-input` flag.

**The ripple family** (rsa-ripple, rsa-abyss, prime-vault,
prime-trickle). Four challenges sharing one modulus with close
primes, each shipping a blob longer than the modulus. Because RSA
output cannot exceed its modulus, the asymmetric material was
decorative in all four cases. Every blob shared an opening prefix,
the flag format provided a known-plaintext crib, and single-byte XOR
with key `0xA4` decrypted each one. The applicable routine is to
compare sizes first, compare prefixes across related inputs second,
and drag the crib third.

**number-drift.** A line of decimal byte values that the detector
initially misclassified for lack of a decimal ASCII codec. The codec
was added with strict 0-255 validation, and the challenge input is
now a regression test.

**leaky-crt.** Unsolved. The analysis records the evidence: 255
leaked low bits of a 1024-bit prime against a Coppersmith bound that
requires 512, an exhausted 500-million-iteration Fermat run, a
negative Wiener test, no shared factors with related moduli, and no
small factors. The most probable explanation is a generator error
rather than a missed technique.

## Limitations

HashEndra does not replace dedicated password crackers for expensive
hashes, does not factor properly generated large moduli, and does not
report conclusions beyond what the evidence supports. Low confidence
scores and informational markers mean the result is uncertain and
should be treated accordingly.

## Development notes

The source is organized into `handlers/` for the CLI surface and
`core/`, `detectors/`, and `forensics/` for the engines. No source
file exceeds 500 lines. The test suite holds over 140 tests with
zero clippy warnings as a standing requirement. Build, test, release,
and contribution procedures are documented in the development guide:
https://github.com/meshackbahati/HashEndra/blob/main/docs/DEVELOPMENT.md
