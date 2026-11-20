//! Root CA trust-bundle loading and encoding (`no_std`, `#![forbid(unsafe_code)]`).
//!
//! Supports:
//! - Compact binary DER bundle (`sys:/certs/roots.der` on the Ed25519-verified `sys` volume):
//!   magic `"DRTS"` (4 bytes) + version `1` (`u32 LE`) + count (`u32 LE`) + repeated
//!   `[len: u32 LE][der_bytes...]`.
//! - Standard PEM bundle (`-----BEGIN CERTIFICATE-----` ... `-----END CERTIFICATE-----`).

use alloc::vec::Vec;

const BUNDLE_MAGIC: [u8; 4] = *b"DRTS";
const BUNDLE_VERSION: u32 = 1;
const MAX_CERT_BYTES: usize = 16 * 1024;
const MAX_CERTS: usize = 512;

/// Encode DER certificates into the compact `DRTS` binary bundle format.
pub fn encode_der_bundle(certs: &[&[u8]]) -> Vec<u8> {
    let total: usize = certs.iter().map(|c| 4 + c.len()).sum();
    let mut out = Vec::with_capacity(12 + total);
    out.extend_from_slice(&BUNDLE_MAGIC);
    out.extend_from_slice(&BUNDLE_VERSION.to_le_bytes());
    out.extend_from_slice(&(certs.len() as u32).to_le_bytes());
    for c in certs {
        out.extend_from_slice(&(c.len() as u32).to_le_bytes());
        out.extend_from_slice(c);
    }
    out
}

/// Decode a `DRTS` binary root CA bundle into DER certificate byte vectors.
pub fn parse_der_bundle(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if data.len() < 12 || data[..4] != BUNDLE_MAGIC {
        return None;
    }
    let ver = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if ver != BUNDLE_VERSION {
        return None;
    }
    let count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if count > MAX_CERTS {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    let mut off = 12usize;
    for _ in 0..count {
        if off + 4 > data.len() {
            return None;
        }
        let len = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as usize;
        off += 4;
        if len == 0 || len > MAX_CERT_BYTES || off + len > data.len() {
            return None;
        }
        out.push(data[off..off + len].to_vec());
        off += len;
    }
    if off != data.len() {
        return None;
    }
    Some(out)
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut quad = [0u8; 4];
    let mut qlen = 0usize;
    let mut pad = 0usize;
    for &b in input {
        if b == b'\r' || b == b'\n' || b == b' ' || b == b'\t' {
            continue;
        }
        if b == b'=' {
            if qlen < 2 || pad >= 2 {
                return None;
            }
            quad[qlen] = 0;
            qlen += 1;
            pad += 1;
        } else {
            if pad > 0 {
                return None;
            }
            quad[qlen] = b64_val(b)?;
            qlen += 1;
        }
        if qlen == 4 {
            let v = (u32::from(quad[0]) << 18)
                | (u32::from(quad[1]) << 12)
                | (u32::from(quad[2]) << 6)
                | u32::from(quad[3]);
            out.push((v >> 16) as u8);
            if pad < 2 {
                out.push((v >> 8) as u8);
            }
            if pad == 0 {
                out.push(v as u8);
            }
            qlen = 0;
            if pad > 0 {
                break;
            }
        }
    }
    if qlen != 0 {
        return None;
    }
    Some(out)
}

/// Parse zero or more `-----BEGIN CERTIFICATE-----` PEM blocks into DER certificate vectors.
pub fn parse_pem_bundle(pem: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + BEGIN.len() < pem.len() && out.len() < MAX_CERTS {
        let Some(start) = pem[pos..].windows(BEGIN.len()).position(|w| w == BEGIN) else {
            break;
        };
        let body_start = pos + start + BEGIN.len();
        let Some(end) = pem[body_start..].windows(END.len()).position(|w| w == END) else {
            break;
        };
        if let Some(der) = decode_base64(&pem[body_start..body_start + end])
            && !der.is_empty()
            && der.len() <= MAX_CERT_BYTES
        {
            out.push(der);
        }
        pos = body_start + end + END.len();
    }
    out
}
