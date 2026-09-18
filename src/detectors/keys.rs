//! Key material, certificates, wallets, and algorithm identifiers.
//!
//! Sources: NIST CSOR OIDs (ML-KEM/ML-DSA/SLH-DSA), PEM/PKCS/OpenSSH label
//! standards, age/Spec, BIP/bech32 address formats. Patterns favor exact
//! literals; heuristic ones carry lower weights and say so.
use crate::core::patterns::{DetectionType, SecurityRating, Signature};

pub fn get_key_signatures() -> Vec<Signature> {
    vec![
        // ----- PEM / PKCS blocks -----
        sig("RSA Private Key", "PKCS#1 PEM block", "-----BEGIN RSA PRIVATE KEY-----", 0.95,
            Some("rsa"), None),
        sig("EC Private Key", "SEC1 PEM block", "-----BEGIN EC PRIVATE KEY-----", 0.95,
            Some("ec"), None),
        sig("OpenSSH Private Key", "OpenSSH-format private key", "-----BEGIN OPENSSH PRIVATE KEY-----", 0.95,
            Some("openssh-key"), None),
        sig("Encrypted Private Key", "PKCS#8 encrypted PEM block", "-----BEGIN ENCRYPTED PRIVATE KEY-----", 0.95,
            None, None),
        sig("PKCS#8 Private Key", "Unencrypted PKCS#8 PEM block", "-----BEGIN PRIVATE KEY-----", 0.9,
            None, None),
        sig("DSA Private Key", "OpenSSL DSA PEM block", "-----BEGIN DSA PRIVATE KEY-----", 0.9,
            None, None),
        sig("Public Key", "X.509 SubjectPublicKeyInfo PEM block", "-----BEGIN PUBLIC KEY-----", 0.9,
            None, None),
        sig("X.509 Certificate", "PEM certificate", "-----BEGIN CERTIFICATE-----", 0.95,
            None, None),
        sig("Certificate Signing Request", "PKCS#10 PEM block", "-----BEGIN CERTIFICATE REQUEST-----", 0.9,
            None, None),
        sig("PGP Public Key", "Armored OpenPGP public key", "-----BEGIN PGP PUBLIC KEY BLOCK-----", 0.9,
            None, None),
        sig("PGP Signature", "Armored detached OpenPGP signature", "-----BEGIN PGP SIGNATURE-----", 0.9,
            None, None),
        // ----- Structured key JSON -----
        sig("JSON Web Key", "JWK object with kty discriminator",
            r#"\{\s*"kty"\s*:\s*"(RSA|EC|oct|OKP)""#, 0.85, None, None),
        sig("Ethereum Keystore", "geth-style UTC keystore JSON",
            r#"\{\s*"address"\s*:\s*"[0-9a-fA-F]{40}""#, 0.6, None, None),
        // ----- SSH -----
        sig("SSH Public Key", "OpenSSH authorized_keys line",
            r"^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]+( .*)?$",
            0.9, None, None),
        // ----- Modern file encryption -----
        sig("Age Recipient", "age-encryption.org X25519 recipient (bech32, 62 chars)",
            r"\bage1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}\b", 0.9, None, None),
        sig("Age File Header", "age encrypted file magic",
            "age-encryption\\.org/v1", 0.95, None, None),
        sig("Minisign Key", "minisign base64 public key (approximate shape)",
            r"\bRW[A-Za-z0-9+/]{52}==\b", 0.6, None, None),
        sig("Ansible Vault", "Ansible Vault envelope",
            r"\$ANSIBLE_VAULT;[0-9.]+;[A-Z0-9]+", 0.95, None, None),
        // ----- Password KDF extras -----
        sig("PHC Scrypt", "Password Hashing Competition string format",
            r"^\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$", 0.9,
            Some("scrypt"), None),
        // ----- Chain addresses not covered elsewhere -----
        sig("Bitcoin Bech32", "Segwit address (bc1/tb1)",
            r"\b(bc1|tb1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8,}\b", 0.85, None, None),
        sig("Litecoin Bech32", "Segwit address (ltc1)",
            r"\bltc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8,}\b", 0.85, None, None),
        sig("Litecoin Base58", "P2PKH (L) or P2SH (M) address",
            r"\b[LM][1-9A-HJ-NP-Za-km-z]{25,34}\b", 0.7, None, None),
        sig("Solana Address", "Base58 system account (heuristic: overlaps BTC P2PKH range)",
            r"\b[1-9A-HJ-NP-Za-km-z]{43,44}\b", 0.45, None, None),
        sig("XRP Address", "Base58 account starting with r",
            r"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b", 0.6, None, None),
        sig("Monero Address", "95-char standard or 106-char integrated address",
            r"\b4[1-9A-HJ-NP-Za-km-z]{94}\b|\b4[1-9A-HJ-NP-Za-km-z]{105}\b", 0.7, None, None),
        // ----- Post-quantum OIDs (NIST CSOR, dotted form as seen in dumps) -----
        sig("ML-KEM OID", "NIST FIPS 203 key-encapsulation algorithm identifier",
            r"2\.16\.840\.1\.101\.3\.4\.4\.[123]\b", 0.9, None,
            Some(SecurityRating::Secure)),
        sig("ML-DSA OID", "NIST FIPS 204 signature algorithm identifier",
            r"2\.16\.840\.1\.101\.3\.4\.3\.1[789]\b", 0.9, None,
            Some(SecurityRating::Secure)),
        sig("SLH-DSA OID", "NIST FIPS 205 hash-based signature identifier",
            r"2\.16\.840\.1\.101\.3\.4\.3\.(2[0-9]|3[01]|3[25-9]|4[0-6])\b", 0.9, None,
            Some(SecurityRating::Secure)),
    ]
}

fn sig(
    name: &str,
    description: &str,
    pattern: &str,
    confidence_weight: f32,
    common_name: Option<&str>,
    rating: Option<SecurityRating>,
) -> Signature {
    Signature {
        name: name.to_string(),
        description: description.to_string(),
        pattern: pattern.to_string(),
        detection_type: DetectionType::Key,
        confidence_weight,
        common_name: common_name.map(str::to_string),
        hashcat_mode: None,
        john_format: None,
        security_rating: rating,
        compliance_refs: vec![],
        parameters: vec![],
    }
}

#[cfg(test)]
mod tests {
    use crate::core::patterns::scan_input;
    use crate::core::patterns::ScanningContext;

    fn top(input: &str) -> Option<String> {
        scan_input(input, ScanningContext::Generic)
            .into_iter()
            .max_by(|a, b| a.confidence.total_cmp(&b.confidence))
            .map(|r| r.name)
    }

    #[test]
    fn detects_pem_blocks() {
        assert_eq!(
            top("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."),
            Some("RSA Private Key".to_string())
        );
        assert_eq!(
            top("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA..."),
            Some("OpenSSH Private Key".to_string())
        );
    }

    #[test]
    fn detects_ssh_pubkey_and_jwk() {
        assert_eq!(
            top("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqM youtube"),
            Some("SSH Public Key".to_string())
        );
        assert_eq!(
            top(r#"{"kty":"RSA","n":"12345","e":"AQAB"}"#),
            Some("JSON Web Key".to_string())
        );
    }

    #[test]
    fn detects_age_and_ansible() {
        assert_eq!(
            top("age1ql3z7hj432v2jl2z8alunwwun8hm4s4h6d03n3h6d03n3h6d03n38l6uze"),
            Some("Age Recipient".to_string())
        );
        assert_eq!(
            top("$ANSIBLE_VAULT;1.1;AES256"),
            Some("Ansible Vault".to_string())
        );
    }

    #[test]
    fn detects_pqc_oids() {
        // RFC 9881 example: ML-DSA-44 public key algorithm identifier.
        assert_eq!(
            top("OBJECT IDENTIFIER 2.16.840.1.101.3.4.3.17"),
            Some("ML-DSA OID".to_string())
        );
        assert_eq!(
            top("2.16.840.1.101.3.4.4.2"),
            Some("ML-KEM OID".to_string())
        );
    }

    #[test]
    fn detects_chain_extras() {
        assert_eq!(
            top("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            Some("Bitcoin Bech32".to_string())
        );
        assert_eq!(
            top("$scrypt$ln=16,r=8,p=1$aabbcc$ddeeff"),
            Some("PHC Scrypt".to_string())
        );
    }
}
