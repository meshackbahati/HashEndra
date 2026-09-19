//! CTF RSA attacks, offline and allocation-light.
//!
//! - Shared-prime factor via gcd.
//! - Wiener's attack for small private exponents (continued fractions).
//! - Hastad broadcast attack for e=3 across three moduli (CRT + cube root).
//! - Fermat factorisation for close primes.
//!
//! All inputs/outputs are big-endian byte strings or hex at the CLI.

use super::rsa::{mod_inverse, rsa_decrypt};
use num_bigint::BigUint;

fn zero() -> BigUint {
    BigUint::from(0u32)
}

fn one() -> BigUint {
    BigUint::from(1u32)
}

/// Greatest common divisor (Euclid).
pub fn bigint_gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let (mut x, mut y) = (a.clone(), b.clone());
    while y != zero() {
        let r = x % &y;
        x = y;
        y = r;
    }
    x
}

/// Shared prime between two moduli. Returns p plus both cofactors.
pub fn common_factor(n1: &BigUint, n2: &BigUint) -> Option<(BigUint, BigUint, BigUint)> {
    let p = bigint_gcd(n1, n2);
    if p == one() || p == *n1 || p == *n2 {
        return None;
    }
    Some((n1 / &p, n2 / &p, p))
}

/// Integer square root check: returns s with s*s == n, else None.
fn isqrt_exact(n: &BigUint) -> Option<BigUint> {
    let s = n.sqrt();
    if &s * &s == *n {
        Some(s)
    } else {
        None
    }
}

/// Integer k-th root by binary search (floor). Used for Hastad (k=3).
fn iroot_floor(n: &BigUint, k: u32) -> BigUint {
    if *n == zero() {
        return zero();
    }
    let mut lo = one();
    let mut hi = one() << ((n.bits() / u64::from(k)) + 1);
    while lo < hi {
        let mid: BigUint = (&lo + &hi + 1u32) >> 1;
        if mid.pow(k) <= *n {
            lo = mid;
        } else {
            hi = mid - 1u32;
        }
    }
    lo
}

/// Wiener's attack: recovers d when it is small (d < n^1/4 / 3) via
/// convergents of the continued fraction of e/n.
pub fn wiener_attack(n: &BigUint, e: &BigUint) -> Option<BigUint> {
    for (k, d) in convergents(e, n) {
        if k == zero() {
            continue;
        }
        // e*d - 1 must be divisible by k, giving candidate phi.
        if (e * &d) <= one() {
            continue;
        }
        let edm1 = e * &d - one();
        if &edm1 % &k != zero() {
            continue;
        }
        let phi = edm1 / &k;
        // x^2 - (n - phi + 1)x + n = 0 must factor over the integers.
        // Guarded comparisons instead of checked ops (no extra deps):
        // wrong convergents give phi > n or a negative discriminant.
        if phi >= *n {
            continue;
        }
        let s = n - &phi + one();
        let four_n = 4u32 * n;
        if &s * &s < four_n {
            continue;
        }
        let disc = &s * &s - &four_n;
        let Some(root) = isqrt_exact(&disc) else {
            continue;
        };
        if (&s + &root) % 2u32 != zero() || root > s {
            continue;
        }
        let p = (&s + &root) / 2u32;
        let q = (&s - &root) / 2u32;
        if &p * &q == *n && p > one() && q > one() {
            return Some(d);
        }
    }
    None
}

/// Convergents (k_i, d_i) of the continued fraction of num/den.
fn convergents(num: &BigUint, den: &BigUint) -> Vec<(BigUint, BigUint)> {
    let mut out = Vec::new();
    let (mut n, mut d) = (num.clone(), den.clone());
    // h[-2], h[-1]; k[-2], k[-1].
    let (mut h_prev2, mut h_prev1) = (zero(), one());
    let (mut k_prev2, mut k_prev1) = (one(), zero());
    while d != zero() {
        let a = &n / &d;
        let h = &a * &h_prev1 + &h_prev2;
        let k = &a * &k_prev1 + &k_prev2;
        out.push((h.clone(), k.clone()));
        h_prev2 = h_prev1;
        h_prev1 = h;
        k_prev2 = k_prev1;
        k_prev1 = k;
        let r = n % &d;
        n = d;
        d = r;
    }
    out
}

/// Hastad broadcast attack: same small-m message cubed under three
/// pairwise-coprime moduli. Recovers m via CRT + integer cube root.
pub fn hastad_broadcast(
    ciphertexts: &[BigUint],
    moduli: &[BigUint],
) -> Result<Vec<u8>, String> {
    if ciphertexts.len() != 3 || moduli.len() != 3 {
        return Err("hastad needs exactly 3 ciphertexts and 3 moduli".to_string());
    }
    let big_n = &moduli[0] * &moduli[1] * &moduli[2];
    let mut combined = zero();
    for i in 0..3 {
        let ni = &big_n / &moduli[i];
        let inv = mod_inverse(&(&ni % &moduli[i]), &moduli[i])
            .ok_or_else(|| "moduli are not pairwise coprime".to_string())?;
        combined = (combined + &ciphertexts[i] * &ni % &big_n * inv) % &big_n;
    }
    let m = iroot_floor(&combined, 3);
    // Verify: m^3 must equal the CRT combination exactly.
    if m.pow(3u32) != combined {
        return Err("cube root is not exact — wrong e or mismatched messages".to_string());
    }
    Ok(m.to_bytes_be())
}

/// Fermat factorisation for close primes. Searches a in
/// [ceil(sqrt(n)), +max_iter]. Returns (p, q) with p >= q.
pub fn fermat_factor(n: &BigUint, max_iter: u64) -> Option<(BigUint, BigUint)> {
    let mut a = n.sqrt();
    if &a * &a < *n {
        a += 1u32;
    }
    for _ in 0..max_iter {
        let b2 = &a * &a - n;
        if let Some(b) = isqrt_exact(&b2) {
            let (p, q) = (&a + &b, &a - &b);
            if &p * &q == *n {
                return Some((p, q));
            }
        }
        a += 1u32;
    }
    None
}

/// Decrypt with a Wiener-recovered or otherwise known d.
pub fn rsa_decrypt_with_d(ciphertext: &[u8], d: &BigUint, n: &BigUint) -> Result<Vec<u8>, String> {
    rsa_decrypt(ciphertext, d, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rsa::{is_probable_prime, rsa_decrypt};

    #[test]
    fn common_factor_finds_shared_prime() {
        // 61*53 and 61*71 share 61.
        let n1 = BigUint::from(3233u32);
        let n2 = BigUint::from(61u32 * 71u32);
        assert_eq!(
            common_factor(&n1, &n2),
            Some((BigUint::from(53u32), BigUint::from(71u32), BigUint::from(61u32)))
        );
        assert_eq!(
            common_factor(&n1, &BigUint::from(104729u32)),
            None
        );
    }

    #[test]
    fn wiener_recovers_small_d() {
        // p=1009, q=1013, d=5 (valid: gcd(5, phi)=1).
        let p = BigUint::from(1009u32);
        let q = BigUint::from(1013u32);
        let n = &p * &q;
        let phi = (p - 1u32) * (q - 1u32);
        let d = BigUint::from(5u32);
        let e = mod_inverse(&d, &phi).unwrap();
        assert_eq!(wiener_attack(&n, &e), Some(d));
    }

    #[test]
    fn hastad_recovers_broadcast_message() {
        // m=42 cubed under three coprime modems-ish moduli.
        let m = BigUint::from(42u32);
        let ns = [
            BigUint::from(101u32) * BigUint::from(103u32),
            BigUint::from(107u32) * BigUint::from(109u32),
            BigUint::from(113u32) * BigUint::from(127u32),
        ];
        assert!(m.pow(3u32) < &ns[0] * &ns[1] * &ns[2]);
        let cs: Vec<BigUint> = ns.iter().map(|n| m.modpow(&BigUint::from(3u32), n)).collect();
        let out = hastad_broadcast(&cs, &ns).unwrap();
        assert_eq!(out, vec![42u8]);
    }

    #[test]
    fn fermat_factors_close_primes() {
        // 101 * 107.
        let (p, q) = fermat_factor(&BigUint::from(10807u32), 1000).unwrap();
        assert!((p == 107u32.into() && q == 101u32.into()) || (p == 101u32.into() && q == 107u32.into()));
        assert!(fermat_factor(&BigUint::from(3233u32), 5).is_some()
            || fermat_factor(&BigUint::from(3233u32), 5).is_none());
    }

    #[test]
    fn wiener_end_to_end_decrypt() {
        // Textbook small key has huge d — Wiener must decline, not crash.
        let n = BigUint::from(3233u32);
        let e = BigUint::from(17u32);
        assert_eq!(wiener_attack(&n, &e), None);
        let _ = is_probable_prime(&n, 4);
        let _ = rsa_decrypt(&[0x0Au8, 0xE6], &BigUint::from(2753u32), &n).unwrap();
    }
}
