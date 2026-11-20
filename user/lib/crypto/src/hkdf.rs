//! HKDF (RFC 5869) and TLS 1.3 key schedule helpers (RFC 8446 §7.1).

use crate::chacha20::wipe_bytes;
use crate::sha2::{Sha512, sha384};
use crate::sym::hmac_sha256;

/// HMAC-SHA384 over the concatenation of `parts`.
pub fn hmac_sha384(key: &[u8], parts: &[&[u8]]) -> [u8; 48] {
    let mut k = [0u8; 128];
    if key.len() > 128 {
        k[..48].copy_from_slice(&sha384(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha512::new_384();
    let mut outer = Sha512::new_384();
    let (mut ipad, mut opad) = ([0x36u8; 128], [0x5Cu8; 128]);
    for i in 0..128 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    inner.update(&ipad);
    for p in parts {
        inner.update(p);
    }
    outer.update(&opad);
    outer.update(&inner.finish_384());
    wipe_bytes(&mut k);
    wipe_bytes(&mut ipad);
    wipe_bytes(&mut opad);
    outer.finish_384()
}

/// HKDF-Extract with SHA-256 (RFC 5869 §2.2).
/// An empty `salt` is treated as 32 zero bytes.
pub fn extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let zero = [0u8; 32];
    let s = if salt.is_empty() { &zero[..] } else { salt };
    hmac_sha256(s, &[ikm])
}

/// HKDF-Expand with SHA-256 (RFC 5869 §2.3).
/// Returns `false` if `out.len() > 255 * 32`.
pub fn expand_sha256(prk: &[u8], info: &[u8], out: &mut [u8]) -> bool {
    if out.len() > 255 * 32 {
        return false;
    }
    let mut t = [0u8; 32];
    let mut t_len = 0usize;
    for (idx, chunk) in out.chunks_mut(32).enumerate() {
        let ctr = [(idx + 1) as u8];
        t = hmac_sha256(prk, &[&t[..t_len], info, &ctr]);
        t_len = 32;
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    wipe_bytes(&mut t);
    true
}

/// TLS 1.3 `HKDF-Expand-Label` with SHA-256 (RFC 8446 §7.1).
/// `label` is the short label without the `"tls13 "` prefix (e.g. `b"derived"`, `b"key"`, `b"iv"`).
pub fn expand_label_sha256(secret: &[u8; 32], label: &[u8], context: &[u8], out: &mut [u8]) -> bool {
    let full_label_len = 6 + label.len();
    if out.len() > u16::MAX as usize || full_label_len > 255 || context.len() > 255 {
        return false;
    }
    // HkdfLabel = length(2) || label_len(1) || "tls13 " || label || ctx_len(1) || context
    let mut info = [0u8; 2 + 1 + 255 + 1 + 255];
    let mut pos = 0usize;
    info[pos..pos + 2].copy_from_slice(&(out.len() as u16).to_be_bytes());
    pos += 2;
    info[pos] = full_label_len as u8;
    pos += 1;
    info[pos..pos + 6].copy_from_slice(b"tls13 ");
    pos += 6;
    info[pos..pos + label.len()].copy_from_slice(label);
    pos += label.len();
    info[pos] = context.len() as u8;
    pos += 1;
    info[pos..pos + context.len()].copy_from_slice(context);
    pos += context.len();

    let ok = expand_sha256(secret, &info[..pos], out);
    wipe_bytes(&mut info[..pos]);
    ok
}

/// TLS 1.3 `Derive-Secret(Secret, Label, TranscriptHash)` with SHA-256 (RFC 8446 §7.1).
pub fn derive_secret_sha256(secret: &[u8; 32], label: &[u8], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let _ = expand_label_sha256(secret, label, transcript_hash, &mut out);
    out
}

/// HKDF-Extract with SHA-384 (RFC 5869 §2.2). An empty `salt` is treated as 48 zero bytes.
pub fn extract_sha384(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    let zero = [0u8; 48];
    let s = if salt.is_empty() { &zero[..] } else { salt };
    hmac_sha384(s, &[ikm])
}

/// HKDF-Expand with SHA-384 (RFC 5869 §2.3). Returns `false` if `out.len() > 255 * 48`.
pub fn expand_sha384(prk: &[u8], info: &[u8], out: &mut [u8]) -> bool {
    if out.len() > 255 * 48 {
        return false;
    }
    let mut t = [0u8; 48];
    let mut t_len = 0usize;
    for (idx, chunk) in out.chunks_mut(48).enumerate() {
        let ctr = [(idx + 1) as u8];
        t = hmac_sha384(prk, &[&t[..t_len], info, &ctr]);
        t_len = 48;
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    wipe_bytes(&mut t);
    true
}

/// TLS 1.3 `HKDF-Expand-Label` with SHA-384 (RFC 8446 §7.1, for `TLS_AES_256_GCM_SHA384`).
pub fn expand_label_sha384(secret: &[u8; 48], label: &[u8], context: &[u8], out: &mut [u8]) -> bool {
    let full_label_len = 6 + label.len();
    if out.len() > u16::MAX as usize || full_label_len > 255 || context.len() > 255 {
        return false;
    }
    let mut info = [0u8; 2 + 1 + 255 + 1 + 255];
    let mut pos = 0usize;
    info[pos..pos + 2].copy_from_slice(&(out.len() as u16).to_be_bytes());
    pos += 2;
    info[pos] = full_label_len as u8;
    pos += 1;
    info[pos..pos + 6].copy_from_slice(b"tls13 ");
    pos += 6;
    info[pos..pos + label.len()].copy_from_slice(label);
    pos += label.len();
    info[pos] = context.len() as u8;
    pos += 1;
    info[pos..pos + context.len()].copy_from_slice(context);
    pos += context.len();

    let ok = expand_sha384(secret, &info[..pos], out);
    wipe_bytes(&mut info[..pos]);
    ok
}

/// TLS 1.3 `Derive-Secret(Secret, Label, TranscriptHash)` with SHA-384 (RFC 8446 §7.1).
pub fn derive_secret_sha384(secret: &[u8; 48], label: &[u8], transcript_hash: &[u8; 48]) -> [u8; 48] {
    let mut out = [0u8; 48];
    let _ = expand_label_sha384(secret, label, transcript_hash, &mut out);
    out
}
