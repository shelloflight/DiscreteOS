//! PBKDF2-HMAC-SHA256 (RFC 2898 / RFC 8018) and credential verifier derivation.
//!
//! All temporary secret buffers are wiped via `doscrypt::ct::wipe_bytes` before returning.

use doscrypt::ct::wipe_bytes;
use doscrypt::sym::hmac_sha256;

/// Default iteration count: strong offline resistance while unlocking cleanly in milliseconds.
pub const DEFAULT_ITERATIONS: u32 = 10_000;
/// Minimum accepted iteration count in stored credentials (tests may use 100).
pub const MIN_ITERATIONS: u32 = 100;
/// Upper bound to prevent CPU exhaustion on untrusted credential files.
pub const MAX_ITERATIONS: u32 = 200_000;

/// Compute PBKDF2-HMAC-SHA256 into `out` (`iterations >= 1`).
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    if out.is_empty() || iterations == 0 {
        return;
    }
    let mut block_idx = 1u32;
    for chunk in out.chunks_mut(32) {
        let idx_be = block_idx.to_be_bytes();
        let mut u = hmac_sha256(password, &[salt, &idx_be]);
        let mut acc = u;
        for _ in 1..iterations {
            u = hmac_sha256(password, &[&u]);
            for (a, &b) in acc.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        chunk.copy_from_slice(&acc[..chunk.len()]);
        wipe_bytes(&mut u);
        wipe_bytes(&mut acc);
        block_idx = block_idx.wrapping_add(1);
    }
}

/// Derive a 32-byte sealing/unsealing key (used directly as the ChaCha20-Poly1305 key in software
/// seal mode or as the TPM 2.0 `userAuth` secret in hardware seal mode).
pub fn derive_seal_key(passphrase: &[u8], salt: &[u8; 16], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    let iter = iterations.clamp(MIN_ITERATIONS, MAX_ITERATIONS);
    pbkdf2_hmac_sha256(passphrase, salt, iter, &mut key);
    key
}

/// Bind a recovered 32-byte identity secret to its `(identity_id, name)` so swapping credential
/// blobs across identities is detected in constant time.
pub fn derive_verifier(secret: &[u8; 32], identity_id: u32, name: &str) -> [u8; 32] {
    hmac_sha256(secret, &[b"dos-id-verify-v1:", &identity_id.to_le_bytes(), b":", name.as_bytes()])
}
