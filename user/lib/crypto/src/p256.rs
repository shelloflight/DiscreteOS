//! ECDSA over NIST P-256 (FIPS 186-5, SEC 1), verification only: the curve TPMs sign quotes with.
//!
//! Integers are four little-endian u64 limbs. Both moduli (the field prime p and the group order
//! n) use one generic Montgomery multiplication (CIOS, u128 products); inverses are Fermat powers
//! (both moduli are prime). Points are in Jacobian coordinates (a = -3 doubling, complete handling
//! of the identity and of P + P / P - P in the addition); u1*G + u2*Q is one Shamir ladder.
//!
//! Verification handles public data only, so nothing here is constant-time. Strict: public keys
//! must be affine points on the curve with coordinates < p; r and s must be in [1, n - 1]. Both s
//! and n - s verify (ECDSA is malleable; a TPM does not normalise s).

use crate::sha2::sha256;

type U256 = [u64; 4];

const P: U256 = [0xFFFF_FFFF_FFFF_FFFF, 0x0000_0000_FFFF_FFFF, 0x0000_0000_0000_0000, 0xFFFF_FFFF_0000_0001];
const N: U256 = [0xF3B9_CAC2_FC63_2551, 0xBCE6_FAAD_A717_9E84, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_0000_0000];
const B: U256 = [0x3BCE_3C3E_27D2_604B, 0x651D_06B0_CC53_B0F6, 0xB3EB_BD55_7698_86BC, 0x5AC6_35D8_AA3A_93E7];
const GX: U256 = [0xF4A1_3945_D898_C296, 0x7703_7D81_2DEB_33A0, 0xF8BC_E6E5_63A4_40F2, 0x6B17_D1F2_E12C_4247];
const GY: U256 = [0xCBB6_4068_37BF_51F5, 0x2BCE_3357_6B31_5ECE, 0x8EE7_EB4A_7C0F_9E16, 0x4FE3_42E2_FE1A_7F9B];

fn from_be(b: &[u8; 32]) -> U256 {
    let mut r = [0u64; 4];
    for (i, limb) in r.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[32 - 8 * (i + 1)..32 - 8 * i]);
        *limb = u64::from_be_bytes(w);
    }
    r
}

fn to_be(a: &U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[32 - 8 * (i + 1)..32 - 8 * i].copy_from_slice(&a[i].to_be_bytes());
    }
    out
}

fn is_zero(a: &U256) -> bool {
    a.iter().all(|&x| x == 0)
}

/// a >= b
fn geq(a: &U256, b: &U256) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// a + b, carry out
fn add(a: &U256, b: &U256) -> (U256, bool) {
    let mut r = [0u64; 4];
    let mut c = false;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(c as u64);
        r[i] = s2;
        c = c1 || c2;
    }
    (r, c)
}

/// a - b, borrow out
fn sub(a: &U256, b: &U256) -> (U256, bool) {
    let mut r = [0u64; 4];
    let mut br = false;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(br as u64);
        r[i] = d2;
        br = b1 || b2;
    }
    (r, br)
}

/// Arithmetic modulo a prime m > 2^255, values in Montgomery form (x * 2^256 mod m).
struct Field {
    m: U256,
    minv: u64, // -m^-1 mod 2^64
    r2: U256,  // 2^512 mod m
    one: U256, // 2^256 mod m (1 in Montgomery form)
}

impl Field {
    fn new(m: U256) -> Field {
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
        }
        let mut f = Field { m, minv: inv.wrapping_neg(), r2: [0; 4], one: [0; 4] };
        let mut x: U256 = [1, 0, 0, 0];
        for i in 0..512 {
            x = f.add(&x, &x);
            if i == 255 {
                f.one = x;
            }
        }
        f.r2 = x;
        f
    }

    fn add(&self, a: &U256, b: &U256) -> U256 {
        let (s, c) = add(a, b);
        if c || geq(&s, &self.m) { sub(&s, &self.m).0 } else { s }
    }

    fn sub(&self, a: &U256, b: &U256) -> U256 {
        let (d, br) = sub(a, b);
        if br { add(&d, &self.m).0 } else { d }
    }

    fn mul(&self, a: &U256, b: &U256) -> U256 {
        let mut t = [0u64; 6];
        for &bi in b {
            let mut c: u128 = 0;
            for j in 0..4 {
                let v = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + c;
                t[j] = v as u64;
                c = v >> 64;
            }
            let v = u128::from(t[4]) + c;
            t[4] = v as u64;
            t[5] = (v >> 64) as u64;
            let q = t[0].wrapping_mul(self.minv);
            let v = u128::from(t[0]) + u128::from(q) * u128::from(self.m[0]);
            let mut c = v >> 64;
            for j in 1..4 {
                let v = u128::from(t[j]) + u128::from(q) * u128::from(self.m[j]) + c;
                t[j - 1] = v as u64;
                c = v >> 64;
            }
            let v = u128::from(t[4]) + c;
            t[3] = v as u64;
            t[4] = t[5] + (v >> 64) as u64;
            t[5] = 0;
        }
        let r = [t[0], t[1], t[2], t[3]];
        if t[4] != 0 || geq(&r, &self.m) { sub(&r, &self.m).0 } else { r }
    }

    fn sqr(&self, a: &U256) -> U256 {
        self.mul(a, a)
    }

    /// Normal (reduced, < m) -> Montgomery form.
    fn to_mont(&self, a: &U256) -> U256 {
        self.mul(a, &self.r2)
    }

    fn out_of_mont(&self, a: &U256) -> U256 {
        self.mul(a, &[1, 0, 0, 0])
    }

    fn pow(&self, a: &U256, e: &U256) -> U256 {
        let mut r = self.one;
        for i in (0..256).rev() {
            r = self.sqr(&r);
            if (e[i / 64] >> (i % 64)) & 1 == 1 {
                r = self.mul(&r, a);
            }
        }
        r
    }

    /// a^-1 (a != 0), Montgomery form in and out.
    fn inv(&self, a: &U256) -> U256 {
        let e = sub(&self.m, &[2, 0, 0, 0]).0;
        self.pow(a, &e)
    }
}

/// Jacobian point over the field (Montgomery form); z = 0 is the identity.
#[derive(Clone, Copy)]
struct Jac {
    x: U256,
    y: U256,
    z: U256,
}

struct Curve {
    f: Field,
    b: U256, // Montgomery form
}

impl Curve {
    fn new() -> Curve {
        let f = Field::new(P);
        let b = f.to_mont(&B);
        Curve { f, b }
    }

    fn identity(&self) -> Jac {
        Jac { x: self.f.one, y: self.f.one, z: [0; 4] }
    }

    /// Affine (normal form, already checked < p) -> Jacobian.
    fn point(&self, x: &U256, y: &U256) -> Jac {
        Jac { x: self.f.to_mont(x), y: self.f.to_mont(y), z: self.f.one }
    }

    /// y^2 = x^3 - 3x + b, coordinates in normal form.
    fn on_curve(&self, x: &U256, y: &U256) -> bool {
        let f = &self.f;
        let (xm, ym) = (f.to_mont(x), f.to_mont(y));
        let x3 = f.mul(&f.sqr(&xm), &xm);
        let three_x = f.add(&f.add(&xm, &xm), &xm);
        let rhs = f.add(&f.sub(&x3, &three_x), &self.b);
        f.sqr(&ym) == rhs
    }

    /// dbl-2001-b (a = -3).
    fn double(&self, p: &Jac) -> Jac {
        let f = &self.f;
        if is_zero(&p.z) {
            return *p;
        }
        let delta = f.sqr(&p.z);
        let gamma = f.sqr(&p.y);
        let beta = f.mul(&p.x, &gamma);
        let t = f.mul(&f.sub(&p.x, &delta), &f.add(&p.x, &delta));
        let alpha = f.add(&f.add(&t, &t), &t);
        let beta4 = f.add(&f.add(&beta, &beta), &f.add(&beta, &beta));
        let beta8 = f.add(&beta4, &beta4);
        let x3 = f.sub(&f.sqr(&alpha), &beta8);
        let yz = f.add(&p.y, &p.z);
        let z3 = f.sub(&f.sub(&f.sqr(&yz), &gamma), &delta);
        let g2 = f.sqr(&gamma);
        let g4 = f.add(&g2, &g2);
        let g8 = f.add(&f.add(&g4, &g4), &f.add(&g4, &g4));
        let y3 = f.sub(&f.mul(&alpha, &f.sub(&beta4, &x3)), &g8);
        Jac { x: x3, y: y3, z: z3 }
    }

    /// add-2007-bl, with the identity and equal / opposite points handled.
    fn add(&self, p: &Jac, q: &Jac) -> Jac {
        let f = &self.f;
        if is_zero(&p.z) {
            return *q;
        }
        if is_zero(&q.z) {
            return *p;
        }
        let z1z1 = f.sqr(&p.z);
        let z2z2 = f.sqr(&q.z);
        let u1 = f.mul(&p.x, &z2z2);
        let u2 = f.mul(&q.x, &z1z1);
        let s1 = f.mul(&f.mul(&p.y, &q.z), &z2z2);
        let s2 = f.mul(&f.mul(&q.y, &p.z), &z1z1);
        let h = f.sub(&u2, &u1);
        let rr = f.sub(&s2, &s1);
        if is_zero(&h) {
            return if is_zero(&rr) { self.double(p) } else { self.identity() };
        }
        let h2 = f.add(&h, &h);
        let i = f.sqr(&h2);
        let j = f.mul(&h, &i);
        let r = f.add(&rr, &rr);
        let v = f.mul(&u1, &i);
        let x3 = f.sub(&f.sub(&f.sqr(&r), &j), &f.add(&v, &v));
        let s1j = f.mul(&s1, &j);
        let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.add(&s1j, &s1j));
        let zs = f.add(&p.z, &q.z);
        let z3 = f.mul(&f.sub(&f.sub(&f.sqr(&zs), &z1z1), &z2z2), &h);
        Jac { x: x3, y: y3, z: z3 }
    }

    /// a*P + b*Q (scalars in normal form), one ladder over both.
    fn mul2(&self, a: &U256, p: &Jac, b: &U256, q: &Jac) -> Jac {
        let pq = self.add(p, q);
        let mut r = self.identity();
        for i in (0..256).rev() {
            r = self.double(&r);
            let (ba, bb) = ((a[i / 64] >> (i % 64)) & 1, (b[i / 64] >> (i % 64)) & 1);
            r = match (ba, bb) {
                (1, 1) => self.add(&r, &pq),
                (1, 0) => self.add(&r, p),
                (0, 1) => self.add(&r, q),
                _ => r,
            };
        }
        r
    }

    /// Affine x (normal form); None for the identity.
    fn affine_x(&self, p: &Jac) -> Option<U256> {
        if is_zero(&p.z) {
            return None;
        }
        let zi = self.f.inv(&p.z);
        Some(self.f.out_of_mont(&self.f.mul(&p.x, &self.f.sqr(&zi))))
    }

    fn affine(&self, p: &Jac) -> Option<(U256, U256)> {
        if is_zero(&p.z) {
            return None;
        }
        let zi = self.f.inv(&p.z);
        let zi2 = self.f.sqr(&zi);
        let x = self.f.out_of_mont(&self.f.mul(&p.x, &zi2));
        let y = self.f.out_of_mont(&self.f.mul(&p.y, &self.f.mul(&zi2, &zi)));
        Some((x, y))
    }
}

/// A P-256 public key: an affine point on the curve (never the identity).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey {
    x: U256,
    y: U256,
}

impl PublicKey {
    /// From big-endian affine coordinates; None unless both are < p and the point is on the curve.
    pub fn from_xy(x: &[u8; 32], y: &[u8; 32]) -> Option<PublicKey> {
        let (x, y) = (from_be(x), from_be(y));
        if geq(&x, &P) || geq(&y, &P) {
            return None;
        }
        // (0, 0) is not on the curve (b != 0), so this also refuses the usual identity encoding.
        if !Curve::new().on_curve(&x, &y) {
            return None;
        }
        Some(PublicKey { x, y })
    }

    /// From the SEC 1 uncompressed encoding `04 || x || y` (65 bytes).
    pub fn from_sec1(b: &[u8]) -> Option<PublicKey> {
        if b.len() != 65 || b[0] != 0x04 {
            return None;
        }
        PublicKey::from_xy(b[1..33].try_into().ok()?, b[33..65].try_into().ok()?)
    }

    pub fn x(&self) -> [u8; 32] {
        to_be(&self.x)
    }

    pub fn y(&self) -> [u8; 32] {
        to_be(&self.y)
    }
}

/// The leftmost 256 bits of `hash` as an integer mod n (SEC 1 4.1.4 step 5).
fn hash_to_scalar(hash: &[u8]) -> U256 {
    let mut b = [0u8; 32];
    let n = hash.len().min(32);
    b[32 - n..].copy_from_slice(&hash[..n]);
    let e = from_be(&b);
    if geq(&e, &N) { sub(&e, &N).0 } else { e }
}

/// ECDSA verification of the signature (r, s), big-endian, over an already computed `hash`.
pub fn verify_prehash(key: &PublicKey, hash: &[u8], r: &[u8; 32], s: &[u8; 32]) -> bool {
    let (r, s) = (from_be(r), from_be(s));
    if is_zero(&r) || is_zero(&s) || geq(&r, &N) || geq(&s, &N) {
        return false;
    }
    let c = Curve::new();
    let fnn = Field::new(N);
    let e = hash_to_scalar(hash);
    let w = fnn.inv(&fnn.to_mont(&s));
    let u1 = fnn.out_of_mont(&fnn.mul(&fnn.to_mont(&e), &w));
    let u2 = fnn.out_of_mont(&fnn.mul(&fnn.to_mont(&r), &w));
    let g = c.point(&GX, &GY);
    let q = c.point(&key.x, &key.y);
    let Some(x) = c.affine_x(&c.mul2(&u1, &g, &u2, &q)) else {
        return false;
    };
    let v = if geq(&x, &N) { sub(&x, &N).0 } else { x };
    v == r
}

/// ECDSA-SHA256 verification of `sig` = r || s (64 bytes, big-endian) over `msg`.
pub fn verify(key: &PublicKey, msg: &[u8], sig: &[u8; 64]) -> bool {
    let (r, s) = sig.split_at(32);
    match (r.try_into(), s.try_into()) {
        (Ok(r), Ok(s)) => verify_prehash(key, &sha256(msg), r, s),
        _ => false,
    }
}

// ---- signing with a caller-chosen nonce: tests and the TPM simulator only ------------------------

#[cfg(test)]
pub(crate) use sim as testsign;

/// Signing for the test TPM simulator and the tests: the caller picks the nonce `k`, nothing is
/// constant-time. Never for a real key.
pub mod sim {
    use super::*;

    /// Public key of the private scalar `d` (big-endian, 1 <= d < n).
    pub fn public(d: &[u8; 32]) -> PublicKey {
        let c = Curve::new();
        let g = c.point(&GX, &GY);
        let (x, y) = c.affine(&c.mul2(&from_be(d), &g, &[0; 4], &g)).unwrap();
        PublicKey { x, y }
    }

    /// (r, s) for `hash` with private key `d` and nonce `k`; None if r or s is 0.
    pub fn sign_prehash(d: &[u8; 32], k: &[u8; 32], hash: &[u8]) -> Option<([u8; 32], [u8; 32])> {
        let c = Curve::new();
        let fnn = Field::new(N);
        let g = c.point(&GX, &GY);
        let x = c.affine_x(&c.mul2(&from_be(k), &g, &[0; 4], &g))?;
        let r = if geq(&x, &N) { sub(&x, &N).0 } else { x };
        let e = hash_to_scalar(hash);
        let rd = fnn.mul(&fnn.to_mont(&r), &fnn.to_mont(&from_be(d)));
        let sum = fnn.add(&fnn.to_mont(&e), &rd);
        let s = fnn.out_of_mont(&fnn.mul(&fnn.inv(&fnn.to_mont(&from_be(k))), &sum));
        if is_zero(&r) || is_zero(&s) {
            return None;
        }
        Some((to_be(&r), to_be(&s)))
    }

    /// n - s (the other valid signature of the same pair).
    pub fn negate_s(s: &[u8; 32]) -> [u8; 32] {
        to_be(&sub(&N, &from_be(s)).0)
    }

    /// The group order n (big-endian).
    pub fn order() -> [u8; 32] {
        to_be(&N)
    }

    /// n * G is the identity and G is on the curve (the constants are right).
    pub fn check_constants() -> bool {
        let c = Curve::new();
        let g = c.point(&GX, &GY);
        let ng = c.mul2(&N, &g, &[0; 4], &g);
        let n1 = sub(&N, &[1, 0, 0, 0]).0;
        let neg_g = c.affine(&c.mul2(&n1, &g, &[0; 4], &g)).unwrap();
        c.on_curve(&GX, &GY) && is_zero(&ng.z) && neg_g.0 == GX && neg_g.1 == sub(&P, &GY).0
    }
}
