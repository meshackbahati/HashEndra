//! Modern symmetric crypto, offline: AES-CBC/ECB (128/192/256, PKCS7),
//! AES-GCM (128-bit; 12-byte nonces plus GHASH J0 for other lengths),
//! and HMAC-SHA-256/512. Thin wrappers over audited RustCrypto crates
//! plus a small self-contained GHASH for non-standard nonce lengths.
//! Test vectors: NIST SP 800-38A F.2.1 (AES-CBC, cross-checked against
//! OpenSSL and PyCryptodome), PyCryptodome GCM vectors for 8/16-byte
//! nonces, and RFC 4231 (HMAC).

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

/// AES-GCM encrypt (128-bit key). Returns ciphertext with the 16-byte tag
/// appended. The standard 12-byte nonce takes the fast path; other lengths
/// go through the GHASH J0 derivation (NIST 800-38D), matching what common
/// libraries accept.
pub fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    if key.len() != 16 {
        return Err("GCM here uses a 16-byte key".to_string());
    }
    if nonce.len() == 12 {
        return aes_gcm::Aes128Gcm::new_from_slice(key)
            .map_err(|e| e.to_string())?
            .encrypt(nonce.into(), plaintext)
            .map_err(|e| format!("encrypt failed: {e}"));
    }
    gcm_crypt(key, nonce, plaintext, true)
}

/// AES-GCM decrypt. Expects ciphertext with the 16-byte tag appended;
/// wrong key/nonce/tag fails closed with an error, never garbage.
pub fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    if key.len() != 16 {
        return Err("GCM here uses a 16-byte key".to_string());
    }
    if nonce.len() == 12 {
        return aes_gcm::Aes128Gcm::new_from_slice(key)
            .map_err(|e| e.to_string())?
            .decrypt(nonce.into(), ciphertext)
            .map_err(|_| "authentication failed (wrong key, nonce, or tampered ciphertext)".to_string());
    }
    gcm_crypt(key, nonce, ciphertext, false)
}

/// GCM with a non-12-byte nonce: J0 via GHASH, CTR via raw AES blocks
/// (NIST SP 800-38D section 7.1). AAD is empty in the CTF shapes we target.
fn gcm_crypt(key: &[u8], nonce: &[u8], data: &[u8], encrypt: bool) -> Result<Vec<u8>, String> {
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    let cipher = aes::Aes128::new_from_slice(key).map_err(|e| e.to_string())?;
    let enc_block = |bytes: &[u8; 16]| -> [u8; 16] {
        let mut block = GenericArray::clone_from_slice(bytes);
        cipher.encrypt_block(&mut block);
        block.into()
    };
    let h = u128::from_be_bytes(enc_block(&[0u8; 16]));
    // J0 = GHASH_H(IV || 0^(s+64) || len(IV)_64).
    let mut j0_input = nonce.to_vec();
    while !j0_input.len().is_multiple_of(16) {
        j0_input.push(0);
    }
    j0_input.extend_from_slice(&[0u8; 8]);
    j0_input.extend_from_slice(&((nonce.len() as u64) * 8).to_be_bytes());
    let mut j0 = 0u128;
    for block in j0_input.chunks(16) {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(block);
        j0 = ghash_mul(j0 ^ u128::from_be_bytes(arr), h);
    }
    // Split payload from the trailing 16-byte tag on decrypt.
    let (payload, tag) = if encrypt {
        (data, None)
    } else {
        if data.len() < 16 {
            return Err("GCM input is shorter than the 16-byte tag".to_string());
        }
        (&data[..data.len() - 16], Some(&data[data.len() - 16..]))
    };
    // CTR with 32-bit increment starting at inc32(J0)+... = J0+1.
    let mut out = Vec::with_capacity(payload.len());
    for (i, chunk) in payload.chunks(16).enumerate() {
        let ctr = (j0 & !0xFFFF_FFFF) | (u128::from((j0 as u32).wrapping_add(i as u32 + 1)));
        let keystream = enc_block(&ctr.to_be_bytes());
        for (j, &b) in chunk.iter().enumerate() {
            out.push(b ^ keystream[j]);
        }
    }
    // Tag = E(K, J0) XOR GHASH_H(C) over the ciphertext.
    let ct_bytes: &[u8] = if encrypt { &out } else { payload };
    let mut ghash_in = ct_bytes.to_vec();
    while !ghash_in.len().is_multiple_of(16) {
        ghash_in.push(0);
    }
    ghash_in.extend_from_slice(&0u64.to_be_bytes()); // AAD bit length (empty)
    ghash_in.extend_from_slice(&((ct_bytes.len() as u64) * 8).to_be_bytes());
    let mut g = 0u128;
    for block in ghash_in.chunks(16) {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(block);
        g = ghash_mul(g ^ u128::from_be_bytes(arr), h);
    }
    let e_j0 = enc_block(&j0.to_be_bytes());
    let computed: Vec<u8> = g
        .to_be_bytes()
        .iter()
        .zip(e_j0.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    if encrypt {
        out.extend_from_slice(&computed);
        Ok(out)
    } else {
        match tag {
            Some(t) if t == computed.as_slice() => Ok(out),
            _ => Err("authentication failed (wrong key, nonce, or tampered ciphertext)".to_string()),
        }
    }
}

/// GF(2^128) multiply as GHASH defines it (NIST SP 800-38D, Algorithm 1):
/// right shifts with R = 11100001 || 0^120.
fn ghash_mul(x: u128, mut y: u128) -> u128 {
    const R: u128 = 0xE1 << 120;
    let mut z = 0u128;
    let mut v = x;
    for _ in 0..128 {
        if y >> 127 & 1 != 0 {
            z ^= v;
        }
        let lsb = v & 1;
        v >>= 1;
        if lsb != 0 {
            v ^= R;
        }
        y <<= 1;
    }
    z
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
    fn aes_gcm_roundtrip_and_tamper_reject() {
        let key = [0x42u8; 16];
        let nonce = [0x07u8; 12];
        let ct = aes_gcm_encrypt(&key, &nonce, b"GCM test message").unwrap();
        assert_eq!(ct.len(), 16 + 16); // message + tag
        assert_eq!(aes_gcm_decrypt(&key, &nonce, &ct).unwrap(), b"GCM test message");
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(aes_gcm_decrypt(&key, &nonce, &bad).is_err());
        let mut bad_tag = ct.clone();
        let last = bad_tag.len() - 1;
        bad_tag[last] ^= 1;
        assert!(aes_gcm_decrypt(&key, &nonce, &bad_tag).is_err());
        assert!(aes_gcm_encrypt(&[0u8; 10], &nonce, b"x").is_err());
        assert!(aes_gcm_decrypt(&key, &[0u8; 8], &ct).is_err());
    }

    #[test]
    fn aes_gcm_general_nonce_matches_reference() {
        // Cross-checked against PyCryptodome (AES.new(key, MODE_GCM, nonce)).
        let key = hex("000102030405060708090a0b0c0d0e0f");
        // 16-byte nonce, 20-byte message (borrowed-bits shape).
        let nonce = hex("6465666768696a6b6c6d6e6f70717273");
        let pt = hex("c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadb");
        let exp_ct = hex("ea3fd02a78085b9db7f939d9e745d816cc1ed737");
        let exp_tag = hex("c47deec4c67149d73a368d649adcbdc1");
        let ct = aes_gcm_encrypt(&key, &nonce, &pt).unwrap();
        assert_eq!(ct, [exp_ct, exp_tag].concat());
        assert_eq!(aes_gcm_decrypt(&key, &nonce, &ct).unwrap(), pt);
        // 8-byte nonce, unaligned length, plus empty-plaintext tag.
        let nonce8 = hex("6465666768696a6b");
        let ct8 = aes_gcm_encrypt(&key, &nonce8, &pt).unwrap();
        assert_eq!(&ct8[..20], &hex("c70bca1d64432a28655576edb489d474977d9588")[..]);
        assert_eq!(
            &ct8[20..],
            &hex("78c2f66ec95701f5a13598499a2f718f")[..]
        );
        assert_eq!(aes_gcm_decrypt(&key, &nonce8, &ct8).unwrap(), pt);
        let tag_only = aes_gcm_encrypt(&key, &nonce, b"").unwrap();
        assert_eq!(tag_only, hex("a92142af17533472bd1b934c101379d2"));
        // Wrong key fails closed, never garbage.
        assert!(aes_gcm_decrypt(&[9u8; 16], &nonce, &ct).is_err());
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
