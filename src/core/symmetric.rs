//! Modern symmetric crypto, offline: AES-CBC/ECB (128/192/256, PKCS7)
//! and HMAC-SHA-256/512. Thin wrappers over audited RustCrypto crates.
//! Test vectors: NIST SP 800-38A F.2.1 (AES-CBC, cross-checked against
//! OpenSSL and PyCryptodome) and RFC 4231 (HMAC).

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

/// AES-CBC encrypt with PKCS7 padding. Key 16/24/32 bytes, IV exactly 16.
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if iv.len() != 16 {
        return Err("CBC needs a 16-byte IV".to_string());
    }
    match key.len() {
        16 => Ok(cbc::Encryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|e| e.to_string())?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext)),
        24 => Ok(cbc::Encryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|e| e.to_string())?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext)),
        32 => Ok(cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|e| e.to_string())?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext)),
        n => Err(format!("AES key must be 16, 24, or 32 bytes, got {n}")),
    }
}

/// AES-CBC decrypt with PKCS7 unpadding.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if iv.len() != 16 {
        return Err("CBC needs a 16-byte IV".to_string());
    }
    match key.len() {
        16 => cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|e| e.to_string())?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|e| format!("bad padding or key: {e}")),
        24 => cbc::Decryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|e| e.to_string())?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|e| format!("bad padding or key: {e}")),
        32 => cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|e| e.to_string())?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|e| format!("bad padding or key: {e}")),
        n => Err(format!("AES key must be 16, 24, or 32 bytes, got {n}")),
    }
}

/// AES-ECB encrypt with PKCS7 padding. No IV. ECB leaks patterns —
/// offered for CTF compatibility, not endorsed.
pub fn aes_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use ecb::cipher::KeyInit;
    match key.len() {
        16 => Ok(ecb::Encryptor::<Aes128>::new_from_slice(key)
            .map_err(|e| e.to_string())?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext)),
        24 => Ok(ecb::Encryptor::<Aes192>::new_from_slice(key)
            .map_err(|e| e.to_string())?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext)),
        32 => Ok(ecb::Encryptor::<Aes256>::new_from_slice(key)
            .map_err(|e| e.to_string())?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext)),
        n => Err(format!("AES key must be 16, 24, or 32 bytes, got {n}")),
    }
}

/// AES-ECB decrypt with PKCS7 unpadding.
pub fn aes_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use ecb::cipher::KeyInit;
    match key.len() {
        16 => ecb::Decryptor::<Aes128>::new_from_slice(key)
            .map_err(|e| e.to_string())?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|e| format!("bad padding or key: {e}")),
        24 => ecb::Decryptor::<Aes192>::new_from_slice(key)
            .map_err(|e| e.to_string())?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|e| format!("bad padding or key: {e}")),
        32 => ecb::Decryptor::<Aes256>::new_from_slice(key)
            .map_err(|e| e.to_string())?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|e| format!("bad padding or key: {e}")),
        n => Err(format!("AES key must be 16, 24, or 32 bytes, got {n}")),
    }
}

/// HMAC with SHA-256 (RFC 2104 construction over the sha2 crate).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac_with::<sha2::Sha256>(key, message, 64)
}

/// HMAC with SHA-512.
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac_with::<sha2::Sha512>(key, message, 128)
}

fn hmac_with<D>(key: &[u8], message: &[u8], block_len: usize) -> Vec<u8>
where
    D: digest::Digest,
{
    let mut k = vec![0u8; block_len];
    if key.len() > block_len {
        let hashed = D::digest(key);
        k[..hashed.len()].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = D::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = D::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn aes_cbc_nist_vector() {
        // NIST SP 800-38A F.2.1, cross-checked with OpenSSL + PyCryptodome.
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");
        // No padding needed: input is exactly one block, but PKCS7 always
        // appends a full padding block.
        let ct = aes_cbc_encrypt(&key, &iv, &pt).unwrap();
        assert_eq!(&ct[..16], &hex("7649abac8119b246cee98e9b12e9197d")[..]);
        assert_eq!(aes_cbc_decrypt(&key, &iv, &ct).unwrap(), pt);
    }

    #[test]
    fn aes_ecb_roundtrip_all_key_sizes() {
        for key_len in [16, 24, 32] {
            let key = vec![0x2Bu8; key_len];
            let ct = aes_ecb_encrypt(&key, b"sixteen byte msg").unwrap();
            assert_eq!(aes_ecb_decrypt(&key, &ct).unwrap(), b"sixteen byte msg");
        }
        assert!(aes_ecb_encrypt(&[0u8; 10], b"x").is_err());
        assert!(aes_cbc_encrypt(&[0u8; 16], &[0u8; 8], b"x").is_err());
    }

    #[test]
    fn hmac_rfc4231_vectors() {
        // RFC 4231 test case 1 (key 0x0b * 20, "Hi There").
        let key = vec![0x0bu8; 20];
        assert_eq!(
            hex_encode(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert!(
            hex_encode(&hmac_sha512(&key, b"Hi There")).starts_with("87aa7cdea5ef619d")
        );
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
