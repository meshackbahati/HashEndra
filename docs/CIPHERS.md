# Cipher Usage Guide

Every cipher supports `--encrypt` and `--decrypt` with a key. Keys are
strings unless noted.

Key formats:

| Cipher | `--key` | `--cipher-param` |
|---|---|---|
| caesar, rot | shift number (default 3) | none |
| atbash | none needed | none |
| vigenere, beaufort, autokey, porta | keyword | none |
| gronsfeld | digits, e.g. `2015` | none |
| affine | `a,b`, e.g. `5,8` | none |
| rail-fence | rails (default 3) | rails (alternative) |
| columnar | keyword | none |
| polybius | square keyword (default: standard square) | none |
| tap | none needed | none |
| adfgx, adfgvx | square keyword | column keyword |
| four-square, two-square | `K1,K2` | none |
| trifid, bifid | square keyword | period (default 5) |
| playfair | keyword | none |
| bacon | 2-char alphabet (default `AB`) | none |
| substitution | 26-letter cipher alphabet | none |
| xor | string key | none (encrypt emits hex, decrypt accepts hex or raw) |

## Examples

```bash
# Vigenère family
hashendra --encrypt vigenere --key LEMON "ATTACKATDAWN"
hashendra --decrypt vigenere --key LEMON "LXFOPVEFRNHR"
hashendra --encrypt beaufort --key LEMON "ATTACKATDAWN"   # -> LLTOLBETLNPR
hashendra --decrypt autokey --key QUEENLY "QNXEPVYTWTWP"  # -> ATTACKATDAWN
hashendra --encrypt gronsfeld --key 2015 "HELLO"
hashendra --encrypt porta --key SECRET "HELLO WORLD"

# Squares and fractionation
hashendra --encrypt polybius "HELLO"                     # -> 2315313134
hashendra --decrypt polybius "2315313134"                # -> HELLO
hashendra --encrypt tap "HI"                             # dots, " / " separated
hashendra --encrypt adfgx --key "" --cipher-param KEY "HELLO"
hashendra --encrypt four-square --key "EXAMPLE,KEYWORD" "HELLOWORLD"
hashendra --encrypt trifid --key SECRET --cipher-param 5 "HELLO WORLD."

# Grids and codes
hashendra --encrypt playfair --key PLAYFAIREXAMPLE "HIDETHEGOLDINTHETRES"
hashendra --decrypt bifid --key SECRET --cipher-param 5 "<ciphertext>"
hashendra --encrypt bacon --key AB "HI"                  # -> AABBBABAAA
hashendra --encrypt substitution --key "QWERTYUIOPASDFGHJKLZXCVBNM" "HELLO"
```

## Conventions worth knowing

- Case is preserved; non-letters pass through (Vigenère family, Caesar,
  Affine, Atbash). Digraph ciphers (four-square, playfair, bifid) drop
  non-letters, merge J into I, and pad odd lengths with X.
- `--encrypt xor` emits hex; `--decrypt xor` accepts hex or raw bytes.
- ADFGX works on A-Z (digits dropped); ADFGVX keeps A-Z0-9.
- Columnar tie-breaks go left to right; Trifid alphabet is A-Z plus `.`.
- Auto-crackers (`--rot`, `--xor`, deep-decrypt) only attempt the keyless
  attacks: Caesar shifts, single-byte XOR, Tap dots, Polybius digits.
  Everything keyed is manual via `--decrypt` or the workshop.

## Modern primitives

AES-CBC/ECB (128/192/256, PKCS7), raw RSA, and HMAC-SHA-256/512. All keys,
IVs, messages, and RSA components are hex (`0x` prefix tolerated).

```bash
hashendra --encrypt aes-cbc --key 2b7e151628aed2a6abf7158809cf4f3c \
  --cipher-param 000102030405060708090a0b0c0d0e0f "AAAAAAAAAAAAAAAA"
hashendra --decrypt aes-ecb --key <keyhex> "<cthex>"
hashendra --encrypt rsa --key "0CA1,11" "41"          # n=3233, e=17
hashendra --decrypt rsa --key "0CA1,0AC1" "0ae6"      # -> 0041
hashendra --encrypt rsa-keygen --cipher-param 512     # prints n/e/d hex
hashendra --hash hmac-sha256 --key "Jefe" "what do ya want for nothing?"
```

RSA is the textbook primitive (raw modular exponentiation, e=65537
keygen with Miller-Rabin) for CTF work. It is not padded PKCS#1 and
not a TLS stack. ECB is offered for compatibility; it leaks block
patterns.
