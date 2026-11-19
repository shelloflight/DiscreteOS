//! RSA for TPM endorsement keys (docs/attestation.md): the public operations a verifier needs.
//!
//! - PKCS #1 v1.5 signature verification with SHA-256 or SHA-384 (EK certificates are signed
//!   this way by the TPM vendor's CA);
//! - RSAES-OAEP encryption with SHA-256 (TPM2_MakeCredential: the seed is encrypted to the EK).
//!
//! Moduli of 1024 to 4096 bits, odd. Montgomery multiplication on 64-bit limbs. Only public data is
//! handled here (keys, signatures, the verifier's own seed), so nothing is constant-time; the
//! private operation exists for the test TPM simulator only (`sim`).

use crate::sha2::{Sha256, sha256, sha384};

/// Largest modulus, in bytes (4096 bits).
pub const MAX_BYTES: usize = 512;
const LIMBS: usize = MAX_BYTES / 8;

#[derive(Clone)]
pub struct PublicKey {
    n: [u64; LIMBS],
    len: usize,
    bytes: usize,
    e: u32,
    n0inv: u64,
    r2: [u64; LIMBS],
}

fn from_be(b: &[u8], out: &mut [u64; LIMBS]) {
    *out = [0; LIMBS];
    for (i, &x) in b.iter().rev().enumerate() {
        out[i / 8] |= u64::from(x) << (8 * (i % 8));
    }
}

fn to_be(a: &[u64; LIMBS], out: &mut [u8]) {
    let n = out.len();
    for (i, o) in out.iter_mut().enumerate() {
        let k = n - 1 - i;
        *o = (a[k / 8] >> (8 * (k % 8))) as u8;
    }
}

fn geq(a: &[u64], b: &[u64]) -> bool {
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn sub_in_place(a: &mut [u64], b: &[u64]) {
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = u64::from(b1 || b2);
    }
}

impl PublicKey {
    /// From a big-endian modulus (leading zero bytes allowed) and exponent.
    pub fn new(n: &[u8], e: u32) -> Option<PublicKey> {
        let n = &n[n.iter().position(|&b| b != 0).unwrap_or(n.len())..];
        if n.len() < 128 || n.len() > MAX_BYTES || n[n.len() - 1] & 1 == 0 || e < 3 || e & 1 == 0 {
            return None;
        }
        let mut k = PublicKey { n: [0; LIMBS], len: n.len().div_ceil(8), bytes: n.len(), e, n0inv: 0, r2: [0; LIMBS] };
        from_be(n, &mut k.n);
        // -n^-1 mod 2^64 (Newton: each step doubles the correct bits).
        let mut x: u64 = 1;
        for _ in 0..7 {
            x = x.wrapping_mul(2u64.wrapping_sub(k.n[0].wrapping_mul(x)));
        }
        k.n0inv = x.wrapping_neg();
        // R^2 mod n, R = 2^(64 len): double 1 up 2 * 64 * len times.
        let mut r = [0u64; LIMBS];
        r[0] = 1;
        for _ in 0..2 * 64 * k.len {
            let mut carry = 0;
            for limb in r.iter_mut().take(k.len) {
                let c = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = c;
            }
            if carry != 0 || geq(&r[..k.len], &k.n[..k.len]) {
                sub_in_place(&mut r[..k.len], &k.n[..k.len]);
            }
        }
        k.r2 = r;
        Some(k)
    }

    /// Modulus size in bytes.
    pub fn size(&self) -> usize {
        self.bytes
    }

    pub fn exponent(&self) -> u32 {
        self.e
    }

    /// The modulus, big-endian, `size()` bytes.
    pub fn modulus(&self, out: &mut [u8]) {
        to_be(&self.n, &mut out[..self.bytes]);
    }

    /// Montgomery product a * b * R^-1 mod n.
    fn mont_mul(&self, a: &[u64; LIMBS], b: &[u64; LIMBS]) -> [u64; LIMBS] {
        let len = self.len;
        let mut t = [0u64; LIMBS + 2];
        for &bi in b.iter().take(len) {
            let mut c: u128 = 0;
            for j in 0..len {
                let s = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + c;
                t[j] = s as u64;
                c = s >> 64;
            }
            let s = u128::from(t[len]) + c;
            t[len] = s as u64;
            t[len + 1] = (s >> 64) as u64;
            let m = t[0].wrapping_mul(self.n0inv);
            let s = u128::from(t[0]) + u128::from(m) * u128::from(self.n[0]);
            let mut c = s >> 64;
            for j in 1..len {
                let s = u128::from(t[j]) + u128::from(m) * u128::from(self.n[j]) + c;
                t[j - 1] = s as u64;
                c = s >> 64;
            }
            let s = u128::from(t[len]) + c;
            t[len - 1] = s as u64;
            let s2 = u128::from(t[len + 1]) + (s >> 64);
            t[len] = s2 as u64;
            t[len + 1] = 0;
        }
        let mut r = [0u64; LIMBS];
        r[..len].copy_from_slice(&t[..len]);
        if t[len] != 0 || geq(&r[..len], &self.n[..len]) {
            sub_in_place(&mut r[..len], &self.n[..len]);
        }
        r
    }

    /// x^exp mod n for a big-endian x < n and a big-endian exponent; None if x >= n.
    fn pow(&self, x: &[u8], exp: &[u8], out: &mut [u8]) -> Option<()> {
        if x.len() != self.bytes || out.len() != self.bytes {
            return None;
        }
        let mut b = [0u64; LIMBS];
        from_be(x, &mut b);
        if geq(&b[..self.len], &self.n[..self.len]) {
            return None;
        }
        let bm = self.mont_mul(&b, &self.r2);
        let mut one = [0u64; LIMBS];
        one[0] = 1;
        let mut acc = self.mont_mul(&one, &self.r2); // R mod n
        for byte in exp {
            for bit in (0..8).rev() {
                acc = self.mont_mul(&acc, &acc);
                if (byte >> bit) & 1 != 0 {
                    acc = self.mont_mul(&acc, &bm);
                }
            }
        }
        let r = self.mont_mul(&acc, &one);
        to_be(&r, out);
        Some(())
    }

    /// The public operation x^e mod n.
    pub fn public_op(&self, x: &[u8], out: &mut [u8]) -> Option<()> {
        self.pow(x, &self.e.to_be_bytes(), out)
    }
}

const DIGEST_INFO_SHA256: &[u8] = &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
const DIGEST_INFO_SHA384: &[u8] = &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hash {
    Sha256,
    Sha384,
}

/// PKCS #1 v1.5 (RSASSA-PKCS1-v1_5) verification of `sig` over `msg`.
pub fn verify_pkcs1(key: &PublicKey, hash: Hash, msg: &[u8], sig: &[u8]) -> bool {
    let k = key.size();
    if sig.len() != k {
        return false;
    }
    let mut em = [0u8; MAX_BYTES];
    if key.public_op(sig, &mut em[..k]).is_none() {
        return false;
    }
    let (prefix, d256, d384);
    let digest: &[u8] = match hash {
        Hash::Sha256 => {
            prefix = DIGEST_INFO_SHA256;
            d256 = sha256(msg);
            &d256
        }
        Hash::Sha384 => {
            prefix = DIGEST_INFO_SHA384;
            d384 = sha384(msg);
            &d384
        }
    };
    let t = prefix.len() + digest.len();
    if k < t + 11 {
        return false;
    }
    let ps = k - t - 3;
    let em = &em[..k];
    em[0] == 0 && em[1] == 1 && em[2..2 + ps].iter().all(|&b| b == 0xFF) && em[2 + ps] == 0 && &em[3 + ps..3 + ps + prefix.len()] == prefix && &em[k - digest.len()..] == digest
}

/// MGF1 with SHA-256: xor the mask into `out`.
fn mgf1_xor(seed: &[u8], out: &mut [u8]) {
    for (counter, chunk) in out.chunks_mut(32).enumerate() {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(&(counter as u32).to_be_bytes());
        let m = h.finish();
        for (o, x) in chunk.iter_mut().zip(m.iter()) {
            *o ^= x;
        }
    }
}

/// RSAES-OAEP encryption with SHA-256 and MGF1-SHA-256 (RFC 8017, 7.1.1); `seed` is the
/// encryptor's 32 random bytes. Writes `size()` bytes to `out`.
pub fn oaep_encrypt(key: &PublicKey, msg: &[u8], label: &[u8], seed: &[u8; 32], out: &mut [u8]) -> Option<()> {
    let k = key.size();
    if out.len() != k || msg.len() + 2 * 32 + 2 > k {
        return None;
    }
    let mut em = [0u8; MAX_BYTES];
    let (s, db) = em[1..k].split_at_mut(32);
    db[..32].copy_from_slice(&sha256(label));
    let one = db.len() - msg.len() - 1;
    db[one] = 1;
    db[one + 1..].copy_from_slice(msg);
    s.copy_from_slice(seed);
    mgf1_xor(s, db);
    mgf1_xor(db, s);
    key.public_op(&em[..k], out)
}

/// The private side, for the test TPM simulator only (not constant-time, not for real keys).
pub mod sim {
    use super::*;

    /// x^d mod n.
    pub fn private_op(key: &PublicKey, d: &[u8], x: &[u8], out: &mut [u8]) -> Option<()> {
        key.pow(x, d, out)
    }

    /// RSAES-OAEP decryption (SHA-256); the message length.
    pub fn oaep_decrypt(key: &PublicKey, d: &[u8], ct: &[u8], label: &[u8], out: &mut [u8]) -> Option<usize> {
        let k = key.size();
        let mut em = [0u8; MAX_BYTES];
        private_op(key, d, ct, &mut em[..k])?;
        if em[0] != 0 {
            return None;
        }
        let (s, db) = em[1..k].split_at_mut(32);
        mgf1_xor(db, s);
        mgf1_xor(s, db);
        if db[..32] != sha256(label) {
            return None;
        }
        let one = 32 + db[32..].iter().position(|&b| b != 0)?;
        if db[one] != 1 {
            return None;
        }
        let m = &db[one + 1..];
        out.get_mut(..m.len())?.copy_from_slice(m);
        Some(m.len())
    }
}
