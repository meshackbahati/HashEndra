//! Textbook RSA, offline: raw encrypt/decrypt and key generation.
//!
//! No padding modes — this is the CTF primitive (small-e checks, manual
//! math), not a TLS stack. Keys are big-endian byte strings; the CLI takes
//! hex. Randomness comes from the OS (`/dev/urandom`, with a time fallback
//! that is clearly marked non-cryptographic).

use num_bigint::BigUint;

fn zero() -> BigUint {
    BigUint::from(0u32)
}

fn one() -> BigUint {
    BigUint::from(1u32)
}

/// m^e mod n. Message must be smaller than the modulus.
pub fn rsa_encrypt(message: &[u8], e: &BigUint, n: &BigUint) -> Result<Vec<u8>, String> {
    let m = BigUint::from_bytes_be(message);
    if m >= *n {
        return Err("message must be smaller than the modulus".to_string());
    }
    Ok(rsa_modpow(&m, e, n))
}

/// c^d mod n.
pub fn rsa_decrypt(ciphertext: &[u8], d: &BigUint, n: &BigUint) -> Result<Vec<u8>, String> {
    let c = BigUint::from_bytes_be(ciphertext);
    if c >= *n {
        return Err("ciphertext must be smaller than the modulus".to_string());
    }
    Ok(rsa_modpow(&c, d, n))
}

fn rsa_modpow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> Vec<u8> {
    let width = modulus.bits().div_ceil(8) as usize;
    let mut out = base.modpow(exp, modulus).to_bytes_be();
    while out.len() < width {
        out.insert(0, 0);
    }
    out
}

/// Modular inverse via extended Euclid. None when gcd != 1.
pub fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (mut t, mut new_t) = (zero(), one());
    let (mut r, mut new_r) = (m.clone(), a.clone());
    while new_r != zero() {
        let q = &r / &new_r;
        let tmp_t = t.clone();
        t = new_t.clone();
        // new_t = tmp_t - q * new_t (mod m, kept positive)
        let sub = (&q * &new_t) % m;
        new_t = if tmp_t >= sub {
            (tmp_t - &sub) % m
        } else {
            (m - (&sub - &tmp_t) % m) % m
        };
        let tmp_r = r.clone();
        r = new_r.clone();
        new_r = tmp_r % &new_r;
    }
    if r > one() {
        return None;
    }
    Some(t % m)
}

fn os_random_bytes(len: usize) -> Vec<u8> {
    // NOTE: read_exact, never fs::read — /dev/urandom is infinite.
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let mut buf = vec![0u8; len];
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    // Fallback: NOT cryptographic. Only reached where /dev/urandom is absent.
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15);
    (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 11) as u8
        })
        .collect()
}

/// Miller-Rabin with deterministic small-prime trial division first.
/// `rounds` of 12+ is standard confidence for generated keys.
pub fn is_probable_prime(n: &BigUint, rounds: usize) -> bool {
    if *n < BigUint::from(2u32) {
        return false;
    }
    for small in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let p = BigUint::from(small);
        if *n == p {
            return true;
        }
        if n % &p == zero() {
            return false;
        }
    }
    // n - 1 = 2^s * d with d odd.
    let one = one();
    let nm1 = n - &one;
    let mut d = nm1.clone();
    let mut s = 0u32;
    while (&d & &one) == zero() {
        d >>= 1;
        s += 1;
    }
    for _ in 0..rounds {
        // Random base in [2, n-2] by rejection sampling.
        let a = loop {
            let v = rand_below(n);
            if v >= BigUint::from(2u32) && v <= &nm1 - &one {
                break v;
            }
        };
        let mut x = a.modpow(&d, n);
        if x == one || x == nm1 {
            continue;
        }
        let mut composite = true;
        for _ in 1..s {
            x = (&x * &x) % n;
            if x == nm1 {
                composite = false;
                break;
            }
        }
        if composite {
            return false;
        }
    }
    true
}

/// Uniform random BigUint below n (rejection sampling on OS bytes).
fn rand_below(n: &BigUint) -> BigUint {
    let bytes = (n.bits().div_ceil(8).max(1)) as usize;
    loop {
        let v = BigUint::from_bytes_be(&os_random_bytes(bytes));
        if v < *n {
            return v;
        }
    }
}

/// Random odd number with the top bit set (exact bit length).
fn random_odd(bits: usize) -> BigUint {
    let bytes = bits.div_ceil(8);
    let mut raw = os_random_bytes(bytes);
    let excess = bytes * 8 - bits;
    raw[0] &= 0xFF >> excess;
    raw[0] |= 0x80 >> excess;
    let last = raw.len() - 1;
    raw[last] |= 1;
    BigUint::from_bytes_be(&raw)
}

/// Generate an RSA keypair with `bits`-bit modulus and common e=65537.
/// Returns (n, e, d).
pub fn rsa_keygen(bits: usize, rounds: usize) -> Result<(BigUint, BigUint, BigUint), String> {
    if bits < 64 {
        return Err("refusing toy keys under 64 bits".to_string());
    }
    let e = BigUint::from(65537u32);
    let half = bits / 2;
    for _ in 0..1000 {
        let mut p = random_odd(half);
        while !is_probable_prime(&p, rounds) {
            p += 2u32;
        }
        let mut q = random_odd(bits - half);
        while !is_probable_prime(&q, rounds) || q == p {
            q += 2u32;
        }
        let phi = (p.clone() - 1u32) * (q.clone() - 1u32);
        if let Some(d) = mod_inverse(&e, &phi) {
            return Ok((p * q, e, d));
        }
    }
    Err("key generation failed to converge".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn textbook_roundtrip_small_key() {
        // p=61, q=53: n=3233, e=17, d=2753. The classic textbook key.
        // 65^17 mod 3233 = 2790 = 0x0AE6.
        let n = BigUint::from(3233u32);
        let e = BigUint::from(17u32);
        let d = BigUint::from(2753u32);
        let c = rsa_encrypt(b"A", &e, &n).unwrap();
        assert_eq!(c, vec![0x0A, 0xE6]);
        assert_eq!(rsa_decrypt(&c, &d, &n).unwrap(), vec![0x00, 0x41]);
    }

    #[test]
    fn rejects_oversized_message() {
        let n = BigUint::from(3233u32);
        assert!(rsa_encrypt(&[0xFF, 0xFF], &BigUint::from(17u32), &n).is_err());
    }

    #[test]
    fn miller_rabin_known_values() {
        for p in [2u32, 3, 5, 61, 101, 997, 104729] {
            assert!(is_probable_prime(&BigUint::from(p), 12), "{p} should be prime");
        }
        for c in [1u32, 4, 9, 100, 3233, 104730] {
            assert!(!is_probable_prime(&BigUint::from(c), 12), "{c} should be composite");
        }
    }

    #[test]
    fn keygen_roundtrip_128bit() {
        let (n, e, d) = rsa_keygen(128, 8).unwrap();
        assert!(n.bits() == 128 || n.bits() == 127);
        let c = rsa_encrypt(b"hi", &e, &n).unwrap();
        let m = rsa_decrypt(&c, &d, &n).unwrap();
        assert_eq!(&m[m.len() - 2..], b"hi");
    }
}
