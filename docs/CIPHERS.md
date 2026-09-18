# Cipher Usage Guide

Every cipher supports `--encrypt` and `--decrypt` with a key. Keys are
strings unless noted. All commands below were run against the binary —
outputs are real.

Key formats:

| Cipher | `--key` | `--cipher-param` |
|---|---|---|
| caesar, rot | shift number (default 3) | — |
| atbash | none needed | — |
| vigenere, beaufort, autokey, porta | keyword | — |
| gronsfeld | digits, e.g. `2015` | — |
| affine | `a,b`, e.g. `5,8` | — |
| rail-fence | rails (default 3) | rails (alternative) |
| columnar | keyword | — |
| polybius | square keyword (default: standard square) | — |
| tap | none needed | — |
| adfgx, adfgvx | square keyword | column keyword |
| four-square, two-square | `K1,K2` | — |
| trifid, bifid | square keyword | period (default 5) |
| playfair | keyword | — |
| bacon | 2-char alphabet (default `AB`) | — |
| substitution | 26-letter cipher alphabet | — |
| xor | string key | — (encrypt emits hex, decrypt accepts hex or raw) |

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
hashendra --encrypt bacon --key AB "HI"                  # -> AAAAAAAAAB
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
