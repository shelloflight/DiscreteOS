//! RSA for TPM endorsement keys (docs/attestation.md): the public operations a verifier needs.
//!
//! - PKCS #1 v1.5 signature verification with SHA-256 or SHA-384 (EK certificates are signed
//!   this way by the TPM vendor's CA);
//! - RSAES-OAEP encryption with SHA-256 (TPM2_MakeCredential: the seed is encrypted to the EK).
//!
//! Moduli of 1024 to 4096 bits, odd. Montgomery multiplication on 64-bit limbs. Only public data is
//! handled here (keys, signatures, the verifier's own seed), so nothing is constant-time; the
//! private operation exists for the test TPM simulator only (`sim`).

use crate::sha2::{Sha256, Sha512, sha256, sha384, sha512};

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

    /// Exact modulus size in bits (leading zero bits excluded).
    pub fn bits(&self) -> usize {
        let top_limb = self.n[self.len - 1];
        (self.len - 1) * 64 + (64 - top_limb.leading_zeros() as usize)
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
const DIGEST_INFO_SHA512: &[u8] = &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
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
    let (prefix, d256, d384, d512);
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
        Hash::Sha512 => {
            prefix = DIGEST_INFO_SHA512;
            d512 = sha512(msg);
            &d512
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
    mgf1_xor_hash(Hash::Sha256, seed, out);
}

/// MGF1 with `hash`: xor the mask into `out` (RFC 8017 Appendix B.2.1).
fn mgf1_xor_hash(hash: Hash, seed: &[u8], out: &mut [u8]) {
    let hlen = match hash {
        Hash::Sha256 => 32,
        Hash::Sha384 => 48,
        Hash::Sha512 => 64,
    };
    for (counter, chunk) in out.chunks_mut(hlen).enumerate() {
        let ctr = (counter as u32).to_be_bytes();
        let mut mask = [0u8; 64];
        match hash {
            Hash::Sha256 => {
                let mut h = Sha256::new();
                h.update(seed);
                h.update(&ctr);
                mask[..32].copy_from_slice(&h.finish());
            }
            Hash::Sha384 => {
                let mut h = Sha512::new_384();
                h.update(seed);
                h.update(&ctr);
                mask[..48].copy_from_slice(&h.finish_384());
            }
            Hash::Sha512 => {
                let mut h = Sha512::new();
                h.update(seed);
                h.update(&ctr);
                mask[..64].copy_from_slice(&h.finish());
            }
        }
        let clen = chunk.len();
        for (o, x) in chunk.iter_mut().zip(mask[..clen].iter()) {
            *o ^= x;
        }
    }
}

/// RSASSA-PSS verification (RFC 8017 §8.1.2, §9.1.2) with salt length equal to the hash length
/// (required by TLS 1.3 RFC 8446 §4.2.3: `rsa_pss_rsae_sha256` / `sha384` / `sha512`).
pub fn verify_pss(key: &PublicKey, hash: Hash, msg: &[u8], sig: &[u8]) -> bool {
    let k = key.size();
    if sig.len() != k {
        return false;
    }
    let mut em_full = [0u8; MAX_BYTES];
    if key.public_op(sig, &mut em_full[..k]).is_none() {
        return false;
    }
    let mod_bits = key.bits();
    if mod_bits < 2 {
        return false;
    }
    let em_bits = mod_bits - 1;
    let em_len = em_bits.div_ceil(8);
    if em_len > k {
        return false;
    }
    // Any leading byte above `em_len` must be zero.
    let start = k - em_len;
    if em_full[..start].iter().any(|&b| b != 0) {
        return false;
    }
    let em = &em_full[start..k];

    let hlen = match hash {
        Hash::Sha256 => 32usize,
        Hash::Sha384 => 48usize,
        Hash::Sha512 => 64usize,
    };
    let slen = hlen;
    if em_len < hlen + slen + 2 {
        return false;
    }
    if em[em_len - 1] != 0xBC {
        return false;
    }
    let db_len = em_len - hlen - 1;
    let unused_bits = 8 * em_len - em_bits;
    let top_mask = if unused_bits == 0 { 0u8 } else { 0xFFu8 << (8 - unused_bits) };
    if em[0] & top_mask != 0 {
        return false;
    }

    let h = &em[db_len..db_len + hlen];
    let mut db = [0u8; MAX_BYTES];
    db[..db_len].copy_from_slice(&em[..db_len]);
    mgf1_xor_hash(hash, h, &mut db[..db_len]);
    db[0] &= !top_mask;

    let ps_len = em_len - hlen - slen - 2;
    if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
        return false;
    }
    let salt = &db[db_len - slen..db_len];

    let mut mhash = [0u8; 64];
    let mut h_prime = [0u8; 64];
    match hash {
        Hash::Sha256 => {
            mhash[..32].copy_from_slice(&sha256(msg));
            let mut hasher = Sha256::new();
            hasher.update(&[0u8; 8]);
            hasher.update(&mhash[..32]);
            hasher.update(salt);
            h_prime[..32].copy_from_slice(&hasher.finish());
        }
        Hash::Sha384 => {
            mhash[..48].copy_from_slice(&sha384(msg));
            let mut hasher = Sha512::new_384();
            hasher.update(&[0u8; 8]);
            hasher.update(&mhash[..48]);
            hasher.update(salt);
            h_prime[..48].copy_from_slice(&hasher.finish_384());
        }
        Hash::Sha512 => {
            mhash[..64].copy_from_slice(&sha512(msg));
            let mut hasher = Sha512::new();
            hasher.update(&[0u8; 8]);
            hasher.update(&mhash[..64]);
            hasher.update(salt);
            h_prime[..64].copy_from_slice(&hasher.finish());
        }
    }
    &h_prime[..hlen] == h
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

    /// RSASSA-PSS signing for tests and local test servers (not constant-time).
    /// `salt` length must match `hash` (32 for SHA-256, 48 for SHA-384).
    pub fn sign_pss(key: &PublicKey, d: &[u8], hash: Hash, msg: &[u8], salt: &[u8], out: &mut [u8]) -> Option<()> {
        let k = key.size();
        let hlen = match hash {
            Hash::Sha256 => 32usize,
            Hash::Sha384 => 48usize,
            Hash::Sha512 => 64usize,
        };
        if out.len() != k || salt.len() != hlen {
            return None;
        }
        let mod_bits = key.bits();
        let em_bits = mod_bits.checked_sub(1)?;
        let em_len = em_bits.div_ceil(8);
        if em_len > k || em_len < hlen + hlen + 2 {
            return None;
        }
        let db_len = em_len - hlen - 1;
        let ps_len = em_len - hlen - hlen - 2;
        let unused_bits = 8 * em_len - em_bits;
        let top_mask = if unused_bits == 0 { 0u8 } else { 0xFFu8 << (8 - unused_bits) };

        let mut h = [0u8; 64];
        match hash {
            Hash::Sha256 => {
                let mh = sha256(msg);
                let mut hasher = Sha256::new();
                hasher.update(&[0u8; 8]);
                hasher.update(&mh);
                hasher.update(salt);
                h[..32].copy_from_slice(&hasher.finish());
            }
            Hash::Sha384 => {
                let mh = sha384(msg);
                let mut hasher = Sha512::new_384();
                hasher.update(&[0u8; 8]);
                hasher.update(&mh);
                hasher.update(salt);
                h[..48].copy_from_slice(&hasher.finish_384());
            }
            Hash::Sha512 => {
                let mh = sha512(msg);
                let mut hasher = Sha512::new();
                hasher.update(&[0u8; 8]);
                hasher.update(&mh);
                hasher.update(salt);
                h[..64].copy_from_slice(&hasher.finish());
            }
        }
        let mut em_full = [0u8; MAX_BYTES];
        let start = k - em_len;
        let em = &mut em_full[start..k];
        em[ps_len] = 0x01;
        em[ps_len + 1..ps_len + 1 + hlen].copy_from_slice(salt);
        mgf1_xor_hash(hash, &h[..hlen], &mut em[..db_len]);
        em[0] &= !top_mask;
        em[db_len..db_len + hlen].copy_from_slice(&h[..hlen]);
        em[em_len - 1] = 0xBC;
        private_op(key, d, &em_full[..k], out)
    }
}
