//! FIPS 203 ML-KEM-768 post-quantum key encapsulation mechanism (`no_std`, zero-alloc).
//!
//! Used with X25519 in TLS 1.3 hybrid key exchange `X25519MLKEM768` (`0x11EC`,
//! `draft-ietf-tls-ecdhe-mlkem`), providing ~192-bit NIST Level 3 post-quantum security alongside
//! classical X25519 forward secrecy.
//!
//! Security properties:
//! - Strictly follows FIPS 203 final (including `G(d || k)` domain separation in `K-PKE.KeyGen`).
//! - Constant-time modular arithmetic (Barrett reduction, no secret-dependent division or branches).
//! - Strict FIPS 203 encapsulation-key modulus validation (`< 3329` for every 12-bit coefficient).
//! - Constant-time FO transform with implicit rejection (`ct_select_bytes`) in `decaps`.
//! - All secret polynomials and keys are wiped with `write_volatile` on drop.

use crate::ct::{ct_eq, ct_select_bytes, wipe_bytes};
use crate::sha3::{Sha3_256, Sha3_512, Shake128, Shake256, sha3_256};

const N: usize = 256;
const Q: i32 = 3329;
const K: usize = 3;

pub const EK_LEN: usize = 384 * K + 32; // 1184 bytes
pub const DK_LEN: usize = 384 * K + EK_LEN + 64; // 2400 bytes
pub const CT_LEN: usize = 32 * (10 * K + 4); // 1088 bytes
pub const SS_LEN: usize = 32;

const fn bitrev7(mut x: usize) -> usize {
    let mut r = 0;
    let mut i = 0;
    while i < 7 {
        r = (r << 1) | (x & 1);
        x >>= 1;
        i += 1;
    }
    r
}

const fn pow_mod_q(mut base: i32, mut exp: usize) -> i16 {
    let mut res = 1i32;
    while exp > 0 {
        if (exp & 1) != 0 {
            res = (res * base) % Q;
        }
        base = (base * base) % Q;
        exp >>= 1;
    }
    res as i16
}

/// `ZETAS[i] = 17^(BitRev7(i)) mod 3329` for `i = 0..128` (FIPS 203 §4.3).
const ZETAS: [i16; 128] = {
    let mut t = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        t[i] = pow_mod_q(17, bitrev7(i));
        i += 1;
    }
    t
};

/// `GAMMAS[i] = 17^(2 * BitRev7(i) + 1) mod 3329` for `i = 0..128` (base-case NTT multiply).
const GAMMAS: [i16; 128] = {
    let mut t = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        t[i] = pow_mod_q(17, 2 * bitrev7(i) + 1);
        i += 1;
    }
    t
};

/// Constant-time Barrett reduction to canonical `[0, Q - 1]` for any `a` in `[-2^24, 2^24]`.
#[inline(always)]
fn mod_q(a: i32) -> i16 {
    // 2^26 / 3329 = 20159.7... ; use i64 with 2^32 / 3329 = 1_290_167 for exact quotient.
    let x = i64::from(a);
    let q = (x * 1_290_167) >> 32;
    let mut r = (x - q * i64::from(Q)) as i32;
    // Correct residual into [0, Q - 1] branchlessly (r is within [-Q, 2Q]).
    r += Q & (r >> 31);
    let d = r - Q;
    r = d + (Q & (d >> 31));
    let d2 = r - Q;
    r = d2 + (Q & (d2 >> 31));
    r as i16
}

#[inline(always)]
fn mul_mod_q(a: i16, b: i16) -> i16 {
    mod_q(i32::from(a) * i32::from(b))
}

#[inline(always)]
fn add_mod_q(a: i16, b: i16) -> i16 {
    let s = i32::from(a) + i32::from(b);
    let d = s - Q;
    (d + (Q & (d >> 31))) as i16
}

#[inline(always)]
fn sub_mod_q(a: i16, b: i16) -> i16 {
    let d = i32::from(a) - i32::from(b);
    (d + (Q & (d >> 31))) as i16
}

/// Constant-time `Compress_d(x) = round((2^d / q) * x) mod 2^d` (FIPS 203 §4.2.1).
#[inline(always)]
pub(crate) fn compress(x: i16, d: u32) -> u16 {
    // Exact constant-time division by 3329 using fixed-point multiplier `ceil(2^36 / 3329)`.
    const DIV_Q: u64 = 20_642_679; // floor(2^36 / 3329) + 1 = 20_642_678 + 1
    let num = ((u64::from(x as u16) << d) + 1664) * DIV_Q;
    ((num >> 36) as u16) & ((1u16 << d) - 1)
}

/// `Decompress_d(y) = round((q / 2^d) * y)` (FIPS 203 §4.2.1).
#[inline(always)]
pub(crate) fn decompress(y: u16, d: u32) -> i16 {
    (((u32::from(y) * 3329) + (1u32 << (d - 1))) >> d) as i16
}

#[derive(Clone, Copy)]
struct Poly([i16; N]);

impl Poly {
    const ZERO: Self = Self([0; N]);

    fn wipe(&mut self) {
        for c in &mut self.0 {
            // SAFETY: volatile write to a live mutable reference.
            unsafe { core::ptr::write_volatile(c, 0) };
        }
    }

    fn add(&self, o: &Self) -> Self {
        let mut r = Self::ZERO;
        for i in 0..N {
            r.0[i] = add_mod_q(self.0[i], o.0[i]);
        }
        r
    }

    fn sub(&self, o: &Self) -> Self {
        let mut r = Self::ZERO;
        for i in 0..N {
            r.0[i] = sub_mod_q(self.0[i], o.0[i]);
        }
        r
    }

    /// FIPS 203 Algorithm 9 (`NTT`).
    fn ntt(&mut self) {
        let mut i = 1usize;
        let mut len = 128usize;
        while len >= 2 {
            let mut start = 0usize;
            while start < N {
                let zeta = ZETAS[i];
                i += 1;
                for j in start..start + len {
                    let t = mul_mod_q(zeta, self.0[j + len]);
                    self.0[j + len] = sub_mod_q(self.0[j], t);
                    self.0[j] = add_mod_q(self.0[j], t);
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    /// FIPS 203 Algorithm 10 (`NTT^-1`).
    fn inv_ntt(&mut self) {
        let mut i = 127usize;
        let mut len = 2usize;
        while len <= 128 {
            let mut start = 0usize;
            while start < N {
                let zeta = ZETAS[i];
                i = i.wrapping_sub(1);
                for j in start..start + len {
                    let t = self.0[j];
                    self.0[j] = add_mod_q(t, self.0[j + len]);
                    self.0[j + len] = mul_mod_q(zeta, sub_mod_q(self.0[j + len], t));
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        // Multiply by 128^-1 mod 3329 = 3303.
        for c in &mut self.0 {
            *c = mul_mod_q(*c, 3303);
        }
    }

    /// FIPS 203 Algorithm 11 (`MultiplyNTTs`).
    fn mul_ntt(&self, o: &Self) -> Self {
        let mut r = Self::ZERO;
        for i in 0..128 {
            let a0 = self.0[2 * i];
            let a1 = self.0[2 * i + 1];
            let b0 = o.0[2 * i];
            let b1 = o.0[2 * i + 1];
            let gamma = GAMMAS[i];
            let c0 = add_mod_q(mul_mod_q(a0, b0), mul_mod_q(mul_mod_q(a1, b1), gamma));
            let c1 = add_mod_q(mul_mod_q(a0, b1), mul_mod_q(a1, b0));
            r.0[2 * i] = c0;
            r.0[2 * i + 1] = c1;
        }
        r
    }
}

/// FIPS 203 Algorithm 7 (`SampleNTT`) from `SHAKE128(rho || j || i)`.
fn sample_ntt(rho: &[u8; 32], j: u8, i: u8) -> Poly {
    let mut xof = Shake128::new();
    xof.update(rho);
    xof.update(&[j, i]);
    let mut poly = Poly::ZERO;
    let mut count = 0usize;
    let mut buf = [0u8; 3];
    while count < N {
        xof.squeeze(&mut buf);
        let d1 = u16::from(buf[0]) | (u16::from(buf[1] & 0x0F) << 8);
        let d2 = (u16::from(buf[1]) >> 4) | (u16::from(buf[2]) << 4);
        if i32::from(d1) < Q {
            poly.0[count] = d1 as i16;
            count += 1;
        }
        if i32::from(d2) < Q && count < N {
            poly.0[count] = d2 as i16;
            count += 1;
        }
    }
    poly
}

/// FIPS 203 Algorithm 8 (`SamplePolyCBD_2`) from `SHAKE256(sigma || nonce)` (128 bytes).
fn sample_cbd2(sigma: &[u8; 32], nonce: u8) -> Poly {
    let mut xof = Shake256::new();
    xof.update(sigma);
    xof.update(&[nonce]);
    let mut b = [0u8; 128];
    xof.squeeze(&mut b);
    let mut p = Poly::ZERO;
    for (i, coeff) in p.0.iter_mut().enumerate() {
        let bit_pos = 4 * i;
        let byte = b[bit_pos / 8];
        let nib = (byte >> (bit_pos % 8)) & 0x0F;
        let x = i32::from((nib & 1) + ((nib >> 1) & 1));
        let y = i32::from(((nib >> 2) & 1) + ((nib >> 3) & 1));
        *coeff = sub_mod_q(x as i16, y as i16);
    }
    wipe_bytes(&mut b);
    p
}

/// FIPS 203 `ByteEncode_12` (256 coefficients in `[0, q-1]` -> 384 bytes).
fn encode_12(p: &Poly, out: &mut [u8]) {
    for i in 0..128 {
        let a = p.0[2 * i] as u16;
        let b = p.0[2 * i + 1] as u16;
        out[3 * i] = (a & 0xFF) as u8;
        out[3 * i + 1] = ((a >> 8) | ((b & 0x0F) << 4)) as u8;
        out[3 * i + 2] = (b >> 4) as u8;
    }
}

/// FIPS 203 `ByteDecode_12` with optional strict `< q` validation (required for `ek`).
fn decode_12(src: &[u8], strict_q: bool) -> Option<Poly> {
    if src.len() != 384 {
        return None;
    }
    let mut p = Poly::ZERO;
    for i in 0..128 {
        let a = u16::from(src[3 * i]) | (u16::from(src[3 * i + 1] & 0x0F) << 8);
        let b = (u16::from(src[3 * i + 1]) >> 4) | (u16::from(src[3 * i + 2]) << 4);
        if strict_q && (i32::from(a) >= Q || i32::from(b) >= Q) {
            return None;
        }
        p.0[2 * i] = mod_q(i32::from(a));
        p.0[2 * i + 1] = mod_q(i32::from(b));
    }
    Some(p)
}

/// Encode `Compress_10(p)` into 320 bytes.
fn encode_u10(p: &Poly, out: &mut [u8]) {
    for i in 0..64 {
        let c0 = compress(p.0[4 * i], 10);
        let c1 = compress(p.0[4 * i + 1], 10);
        let c2 = compress(p.0[4 * i + 2], 10);
        let c3 = compress(p.0[4 * i + 3], 10);
        out[5 * i] = (c0 & 0xFF) as u8;
        out[5 * i + 1] = ((c0 >> 8) | ((c1 & 0x3F) << 2)) as u8;
        out[5 * i + 2] = ((c1 >> 6) | ((c2 & 0x0F) << 4)) as u8;
        out[5 * i + 3] = ((c2 >> 4) | ((c3 & 0x03) << 6)) as u8;
        out[5 * i + 4] = (c3 >> 2) as u8;
    }
}

/// Decode 320 bytes with `Decompress_10`.
fn decode_u10(src: &[u8]) -> Poly {
    let mut p = Poly::ZERO;
    for i in 0..64 {
        let b0 = u16::from(src[5 * i]);
        let b1 = u16::from(src[5 * i + 1]);
        let b2 = u16::from(src[5 * i + 2]);
        let b3 = u16::from(src[5 * i + 3]);
        let b4 = u16::from(src[5 * i + 4]);
        let c0 = b0 | ((b1 & 0x03) << 8);
        let c1 = (b1 >> 2) | ((b2 & 0x0F) << 6);
        let c2 = (b2 >> 4) | ((b3 & 0x3F) << 4);
        let c3 = (b3 >> 6) | (b4 << 2);
        p.0[4 * i] = decompress(c0, 10);
        p.0[4 * i + 1] = decompress(c1, 10);
        p.0[4 * i + 2] = decompress(c2, 10);
        p.0[4 * i + 3] = decompress(c3, 10);
    }
    p
}

/// Encode `Compress_4(p)` into 128 bytes.
fn encode_v4(p: &Poly, out: &mut [u8]) {
    for i in 0..128 {
        let a = compress(p.0[2 * i], 4) as u8;
        let b = compress(p.0[2 * i + 1], 4) as u8;
        out[i] = a | (b << 4);
    }
}

/// Decode 128 bytes with `Decompress_4`.
fn decode_v4(src: &[u8]) -> Poly {
    let mut p = Poly::ZERO;
    for i in 0..128 {
        p.0[2 * i] = decompress(u16::from(src[i] & 0x0F), 4);
        p.0[2 * i + 1] = decompress(u16::from(src[i] >> 4), 4);
    }
    p
}

fn encode_msg1(p: &Poly) -> [u8; 32] {
    let mut m = [0u8; 32];
    for i in 0..N {
        let bit = compress(p.0[i], 1) as u8;
        m[i / 8] |= bit << (i % 8);
    }
    m
}

fn decode_msg1(m: &[u8; 32]) -> Poly {
    let mut p = Poly::ZERO;
    for i in 0..N {
        let bit = u16::from((m[i / 8] >> (i % 8)) & 1);
        p.0[i] = decompress(bit, 1);
    }
    p
}

// ---- K-PKE (FIPS 203 Algorithms 13, 14, 15) -----------------------------------------------------

fn kpke_keygen(d: &[u8; 32], ek_out: &mut [u8; EK_LEN], dk_pke_out: &mut [u8; 384 * K]) {
    let mut g = Sha3_512::new();
    g.update(d);
    g.update(&[K as u8]); // FIPS 203 final domain separation
    let mut rho_sigma = g.finish();
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&rho_sigma[..32]);
    sigma.copy_from_slice(&rho_sigma[32..64]);
    wipe_bytes(&mut rho_sigma);

    let mut s = [Poly::ZERO; K];
    let mut e = [Poly::ZERO; K];
    for (i, si) in s.iter_mut().enumerate() {
        *si = sample_cbd2(&sigma, i as u8);
        si.ntt();
    }
    for (i, ei) in e.iter_mut().enumerate() {
        *ei = sample_cbd2(&sigma, (K + i) as u8);
        ei.ntt();
    }
    wipe_bytes(&mut sigma);

    let mut t = [Poly::ZERO; K];
    for (i, ti) in t.iter_mut().enumerate() {
        let mut acc = Poly::ZERO;
        for (j, sj) in s.iter().enumerate() {
            let a_ij = sample_ntt(&rho, j as u8, i as u8);
            acc = acc.add(&a_ij.mul_ntt(sj));
        }
        *ti = acc.add(&e[i]);
    }

    for i in 0..K {
        encode_12(&t[i], &mut ek_out[i * 384..(i + 1) * 384]);
        encode_12(&s[i], &mut dk_pke_out[i * 384..(i + 1) * 384]);
        s[i].wipe();
        e[i].wipe();
    }
    ek_out[384 * K..].copy_from_slice(&rho);
}

fn kpke_encrypt(ek: &[u8; EK_LEN], m: &[u8; 32], r_seed: &[u8; 32]) -> Option<[u8; CT_LEN]> {
    let mut t_hat = [Poly::ZERO; K];
    for i in 0..K {
        t_hat[i] = decode_12(&ek[i * 384..(i + 1) * 384], true)?;
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * K..]);

    let mut y = [Poly::ZERO; K];
    let mut e1 = [Poly::ZERO; K];
    for (i, yi) in y.iter_mut().enumerate() {
        *yi = sample_cbd2(r_seed, i as u8);
        yi.ntt();
    }
    for (i, e1i) in e1.iter_mut().enumerate() {
        *e1i = sample_cbd2(r_seed, (K + i) as u8);
    }
    let mut e2 = sample_cbd2(r_seed, (2 * K) as u8);

    let mut u = [Poly::ZERO; K];
    for (i, ui) in u.iter_mut().enumerate() {
        let mut acc = Poly::ZERO;
        for (j, yj) in y.iter().enumerate() {
            // A^T[i][j] = A[j][i] = SampleNTT(rho, i, j)
            let a_ji = sample_ntt(&rho, i as u8, j as u8);
            acc = acc.add(&a_ji.mul_ntt(yj));
        }
        acc.inv_ntt();
        *ui = acc.add(&e1[i]);
    }

    let mut v = Poly::ZERO;
    for i in 0..K {
        v = v.add(&t_hat[i].mul_ntt(&y[i]));
    }
    v.inv_ntt();
    let mu = decode_msg1(m);
    v = v.add(&e2).add(&mu);

    let mut ct = [0u8; CT_LEN];
    for i in 0..K {
        encode_u10(&u[i], &mut ct[i * 320..(i + 1) * 320]);
        y[i].wipe();
        e1[i].wipe();
    }
    encode_v4(&v, &mut ct[320 * K..]);
    e2.wipe();
    Some(ct)
}

fn kpke_decrypt(dk_pke: &[u8; 384 * K], ct: &[u8; CT_LEN]) -> [u8; 32] {
    let mut u = [Poly::ZERO; K];
    let mut s_hat = [Poly::ZERO; K];
    for i in 0..K {
        u[i] = decode_u10(&ct[i * 320..(i + 1) * 320]);
        u[i].ntt();
        s_hat[i] = decode_12(&dk_pke[i * 384..(i + 1) * 384], false).unwrap_or(Poly::ZERO);
    }
    let v = decode_v4(&ct[320 * K..]);

    let mut acc = Poly::ZERO;
    for i in 0..K {
        acc = acc.add(&s_hat[i].mul_ntt(&u[i]));
        s_hat[i].wipe();
    }
    acc.inv_ntt();
    let mut w = v.sub(&acc);
    let m = encode_msg1(&w);
    w.wipe();
    m
}

// ---- Public ML-KEM-768 API (FIPS 203 Algorithms 16, 17, 18) -------------------------------------

/// ML-KEM-768 decapsulation key (wipes all 2400 secret bytes on `Drop`).
pub struct DecapsKey {
    bytes: [u8; DK_LEN],
}

impl Drop for DecapsKey {
    fn drop(&mut self) {
        wipe_bytes(&mut self.bytes);
    }
}

/// Generate an ML-KEM-768 keypair `(ek, dk)` from 64 fresh CSPRNG bytes (`d = seed[..32]`, `z = seed[32..64]`).
pub fn keygen(seed_64: &[u8; 64]) -> ([u8; EK_LEN], DecapsKey) {
    let mut d = [0u8; 32];
    d.copy_from_slice(&seed_64[..32]);
    let mut ek = [0u8; EK_LEN];
    let mut dk_pke = [0u8; 384 * K];
    kpke_keygen(&d, &mut ek, &mut dk_pke);
    wipe_bytes(&mut d);

    let h_ek = sha3_256(&ek);
    let mut dk = [0u8; DK_LEN];
    dk[..384 * K].copy_from_slice(&dk_pke);
    dk[384 * K..384 * K + EK_LEN].copy_from_slice(&ek);
    dk[384 * K + EK_LEN..384 * K + EK_LEN + 32].copy_from_slice(&h_ek);
    dk[384 * K + EK_LEN + 32..].copy_from_slice(&seed_64[32..64]);
    wipe_bytes(&mut dk_pke);
    (ek, DecapsKey { bytes: dk })
}

/// Validate an ML-KEM-768 encapsulation key per FIPS 203 §7.2 (modulus check on every 12-bit coeff).
pub fn validate_ek(ek: &[u8; EK_LEN]) -> bool {
    for i in 0..K {
        if decode_12(&ek[i * 384..(i + 1) * 384], true).is_none() {
            return false;
        }
    }
    true
}

/// ML-KEM-768 encapsulation (FIPS 203 Algorithm 17) using 32 fresh CSPRNG bytes `m`.
/// Returns `None` if `ek` fails FIPS 203 modulus validation.
pub fn encaps(ek: &[u8; EK_LEN], m: &[u8; 32]) -> Option<([u8; CT_LEN], [u8; SS_LEN])> {
    if !validate_ek(ek) {
        return None;
    }
    let h_ek = sha3_256(ek);
    let mut g = Sha3_512::new();
    g.update(m);
    g.update(&h_ek);
    let mut k_r = g.finish();
    let mut ss = [0u8; SS_LEN];
    let mut r = [0u8; 32];
    ss.copy_from_slice(&k_r[..32]);
    r.copy_from_slice(&k_r[32..64]);
    wipe_bytes(&mut k_r);

    let ct = kpke_encrypt(ek, m, &r)?;
    wipe_bytes(&mut r);
    Some((ct, ss))
}

/// ML-KEM-768 decapsulation (FIPS 203 Algorithm 18) with constant-time implicit rejection.
pub fn decaps(dk: &DecapsKey, ct: &[u8; CT_LEN]) -> [u8; SS_LEN] {
    let mut dk_pke = [0u8; 384 * K];
    dk_pke.copy_from_slice(&dk.bytes[..384 * K]);
    let mut ek = [0u8; EK_LEN];
    ek.copy_from_slice(&dk.bytes[384 * K..384 * K + EK_LEN]);
    let h_ek = &dk.bytes[384 * K + EK_LEN..384 * K + EK_LEN + 32];
    let z = &dk.bytes[384 * K + EK_LEN + 32..];

    let mut m_prime = kpke_decrypt(&dk_pke, ct);
    wipe_bytes(&mut dk_pke);

    let mut g = Sha3_512::new();
    g.update(&m_prime);
    g.update(h_ek);
    let mut k_r = g.finish();
    let mut k_prime = [0u8; 32];
    let mut r_prime = [0u8; 32];
    k_prime.copy_from_slice(&k_r[..32]);
    r_prime.copy_from_slice(&k_r[32..64]);
    wipe_bytes(&mut k_r);

    // Implicit rejection key K_bar = SHAKE256(z || ct, 32).
    let mut j = Shake256::new();
    j.update(z);
    j.update(ct);
    let mut k_bar = [0u8; 32];
    j.squeeze(&mut k_bar);

    // Re-encrypt and compare ciphertexts in constant time.
    let ct_prime = kpke_encrypt(&ek, &m_prime, &r_prime).unwrap_or([0u8; CT_LEN]);
    wipe_bytes(&mut m_prime);
    wipe_bytes(&mut r_prime);

    let valid = u8::from(ct_eq(ct, &ct_prime));
    let mut out = [0u8; SS_LEN];
    ct_select_bytes(valid, &k_prime, &k_bar, &mut out);
    wipe_bytes(&mut k_prime);
    wipe_bytes(&mut k_bar);
    out
}

#[allow(dead_code)]
fn _keep_sha3_256() {
    let _ = Sha3_256::new();
}
