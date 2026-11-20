//! D-OS crypto for code signing and measured boot. See `docs/signing.md`.
//!
//! - [`sha2`]: SHA-256 (TPM PCR bank, measurements) and SHA-512 (Ed25519, `.dsig` content hashes)
//! - [`ed25519`]: Ed25519 (RFC 8032): key from seed, sign (constant-time), verify (strict:
//!   canonical S and A)
//! - [`p256`]: ECDSA P-256 verification (the curve TPM attestation keys sign with)
//! - [`tpm`]: TPM 2.0 quotes: attestation key public area, quote and signature parsing, verification;
//!   the EK and AK templates; binding an AK to an EK (`make_credential`)
//! - [`rsa`]: RSA public operations (PKCS #1 v1.5 verification, OAEP encryption) for EKs
//! - [`sym`]: HMAC-SHA256, the TPM's KDFa, AES-128-CFB
//! - [`x509`]: X.509 certificates (EK certificates): parsing, RSA signature checks
//! - [`testkeys`]: fixed TEST keys and certificates (the test TPM simulator, tests); never trusted
//! - [`dsig`]: the 256-byte `.dsig` detached signature (shared with D-PACK)
//! - [`attest`]: remote attestation reports (built and signed by the kernel, checked by verifiers)
//!
//! Signing is constant-time with respect to the key, the nonce and the message (the kernel signs
//! attestation reports with a per-boot key). Verification handles only public data and is not.
#![no_std]

pub mod aes_gcm;
pub mod attest;
pub mod chacha20;
pub mod ct;
pub mod dsig;
pub mod ed25519;
pub mod hkdf;
pub mod mlkem;
pub mod p256;
pub mod p384;
pub mod rsa;
pub mod sha2;
pub mod sha3;
pub mod sym;
pub mod testkeys;
pub mod tpm;
pub mod x25519;
pub mod x509;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_ek;
#[cfg(test)]
mod tests_hw;
#[cfg(test)]
mod tests_tls;
