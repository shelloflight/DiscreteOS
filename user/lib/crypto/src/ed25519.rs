//! Ed25519 (RFC 8032), pure Ed25519 (no prehash, no context).
//!
//! Field elements mod p = 2^255 - 19 in radix 2^51 (five u64 limbs, u128 products); points in
//! extended twisted-Edwards coordinates (X:Y:Z:T), unified addition (also used for doubling);
//! scalars mod L with the byte-limb reduction of TweetNaCl (public domain). Curve constants (d, 2d,
//! sqrt(-1), the base point) are computed, not tabulated.
//!
//! Verification is strict: S must be < L and the public key's y canonical (< p); it accepts iff
//! encode([S]B - [k]A) == R. It handles public data only and is not constant-time.
//!
//! Signing and key derivation are constant-time with respect to the secret scalar, the nonce and
//! the message: the scalar multiplications by secrets (`Point::mul_ct`) double and add on every
//! bit and pick the result with a mask, field arithmetic has no data-dependent branches or
//! indices, the scalar arithmetic mod L (`mod_l`) runs a fixed sequence of operations, and the
//! only values encoded (R, A) are public. The key material is wiped when a `SigningKey` drops.

use crate::sha2::Sha512;

const MASK: u64 = (1 << 51) - 1;

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

const ZERO: Fe = Fe([0; 5]);
const ONE: Fe = Fe([1, 0, 0, 0, 0]);

fn load64(b: &[u8], at: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(x)
}

impl Fe {
    fn from_bytes(b: &[u8; 32]) -> Fe {
        Fe([
            load64(b, 0) & MASK,
            (load64(b, 6) >> 3) & MASK,
            (load64(b, 12) >> 6) & MASK,
            (load64(b, 19) >> 1) & MASK,
            (load64(b, 24) >> 12) & MASK,
        ])
    }

    fn small(v: u64) -> Fe {
        Fe([v, 0, 0, 0, 0])
    }

    /// Weak reduction: every limb below 2^51 + a little.
    fn carry(mut h: [u64; 5]) -> Fe {
        for _ in 0..2 {
            for i in 0..4 {
                h[i + 1] += h[i] >> 51;
                h[i] &= MASK;
            }
            h[0] += 19 * (h[4] >> 51);
            h[4] &= MASK;
        }
        Fe(h)
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut h = Fe::carry(self.0).0;
        // Now h < 2^255 + small; subtract p once if h >= p.
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        for i in 0..4 {
            h[i + 1] += h[i] >> 51;
            h[i] &= MASK;
        }
        h[4] &= MASK;
        let mut out = [0u8; 32];
        let mut acc: u128 = 0;
        let mut bits = 0;
        let mut k = 0;
        for limb in h {
            acc |= (limb as u128) << bits;
            bits += 51;
            while bits >= 8 && k < 32 {
                out[k] = acc as u8;
                acc >>= 8;
                bits -= 8;
                k += 1;
            }
        }
        if k < 32 {
            out[k] = acc as u8;
        }
        out
    }

    fn add(self, o: Fe) -> Fe {
        let mut r = [0u64; 5];
        for (i, x) in r.iter_mut().enumerate() {
            *x = self.0[i] + o.0[i];
        }
        Fe::carry(r)
    }

    fn sub(self, o: Fe) -> Fe {
        // + 4p keeps every limb positive for weakly reduced inputs
        const P4: [u64; 5] = [0x1FFFFFFFFFFFB4, 0x1FFFFFFFFFFFFC, 0x1FFFFFFFFFFFFC, 0x1FFFFFFFFFFFFC, 0x1FFFFFFFFFFFFC];
        let mut r = [0u64; 5];
        for (i, x) in r.iter_mut().enumerate() {
            *x = self.0[i] + P4[i] - o.0[i];
        }
        Fe::carry(r)
    }

    fn neg(self) -> Fe {
        ZERO.sub(self)
    }

    fn mul(self, o: Fe) -> Fe {
        let a = self.0.map(u128::from);
        let b = o.0.map(u128::from);
        let (b1, b2, b3, b4) = (19 * b[1], 19 * b[2], 19 * b[3], 19 * b[4]);
        let r0 = a[0] * b[0] + a[1] * b4 + a[2] * b3 + a[3] * b2 + a[4] * b1;
        let r1 = a[0] * b[1] + a[1] * b[0] + a[2] * b4 + a[3] * b3 + a[4] * b2;
        let r2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * b4 + a[4] * b3;
        let r3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * b4;
        let r4 = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0];
        let m = MASK as u128;
        let c0 = r0 >> 51;
        let r1 = r1 + c0;
        let c1 = r1 >> 51;
        let r2 = r2 + c1;
        let c2 = r2 >> 51;
        let r3 = r3 + c2;
        let c3 = r3 >> 51;
        let r4 = r4 + c3;
        let c4 = r4 >> 51;
        let h = [((r0 & m) + 19 * c4) as u64, (r1 & m) as u64, (r2 & m) as u64, (r3 & m) as u64, (r4 & m) as u64];
        Fe::carry(h)
    }

    fn square(self) -> Fe {
        self.mul(self)
    }

    /// self^e, e little-endian bytes.
    fn pow(self, e: &[u8; 32]) -> Fe {
        let mut r = ONE;
        for i in (0..256).rev() {
            r = r.square();
            if (e[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.mul(self);
            }
        }
        r
    }

    fn invert(self) -> Fe {
        let mut e = [0xFFu8; 32];
        e[0] = 0xEB; // p - 2
        e[31] = 0x7F;
        self.pow(&e)
    }

    /// `b` where `mask` is all ones, else `self` (mask is 0 or !0), without a branch.
    fn select(self, b: Fe, mask: u64) -> Fe {
        let mut r = self.0;
        for (i, x) in r.iter_mut().enumerate() {
            *x ^= (*x ^ b.0[i]) & mask;
        }
        Fe(r)
    }

    fn is_zero(self) -> bool {
        self.to_bytes() == [0; 32]
    }

    fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    fn eq(self, o: Fe) -> bool {
        self.to_bytes() == o.to_bytes()
    }
}

struct Consts {
    d: Fe,
    d2: Fe,
    sqrt_m1: Fe,
}

fn consts() -> Consts {
    let d = Fe::small(121665).mul(Fe::small(121666).invert()).neg();
    let mut e = [0xFFu8; 32]; // (p - 1) / 4 = 2^253 - 5
    e[0] = 0xFB;
    e[31] = 0x1F;
    Consts { d, d2: d.add(d), sqrt_m1: Fe::small(2).pow(&e) }
}

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

const IDENTITY: Point = Point { x: ZERO, y: ONE, z: ONE, t: ZERO };

impl Point {
    fn add(self, q: Point, c: &Consts) -> Point {
        let a = self.y.sub(self.x).mul(q.y.sub(q.x));
        let b = self.y.add(self.x).mul(q.y.add(q.x));
        let cc = self.t.mul(c.d2).mul(q.t);
        let d = self.z.add(self.z).mul(q.z);
        let (e, f, g, h) = (b.sub(a), d.sub(cc), d.add(cc), b.add(a));
        Point { x: e.mul(f), y: g.mul(h), z: f.mul(g), t: e.mul(h) }
    }

    /// [s]P, s little-endian (256 bits).
    fn mul(self, s: &[u8; 32], c: &Consts) -> Point {
        let mut r = IDENTITY;
        for i in (0..256).rev() {
            r = r.add(r, c);
            if (s[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.add(self, c);
            }
        }
        r
    }

    /// [s]P in constant time: double and add for every bit, the sum kept by a mask (for secret s).
    fn mul_ct(self, s: &[u8; 32], c: &Consts) -> Point {
        let mut r = IDENTITY;
        for i in (0..256).rev() {
            r = r.add(r, c);
            let sum = r.add(self, c);
            let bit = u64::from((s[i / 8] >> (i % 8)) & 1);
            r = r.select(sum, bit.wrapping_neg());
        }
        r
    }

    fn select(self, q: Point, mask: u64) -> Point {
        Point { x: self.x.select(q.x, mask), y: self.y.select(q.y, mask), z: self.z.select(q.z, mask), t: self.t.select(q.t, mask) }
    }

    fn neg(self) -> Point {
        Point { x: self.x.neg(), y: self.y, z: self.z, t: self.t.neg() }
    }

    fn encode(self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x.mul(zi);
        let mut out = self.y.mul(zi).to_bytes();
        out[31] |= (x.is_negative() as u8) << 7;
        out
    }

    /// Strict decoding (RFC 8032 5.1.3): None for a non-canonical y or a point not on the curve.
    fn decode(b: &[u8; 32], c: &Consts) -> Option<Point> {
        let sign = b[31] >> 7;
        let mut yb = *b;
        yb[31] &= 0x7F;
        let y = Fe::from_bytes(&yb);
        if y.to_bytes() != yb {
            return None; // y >= p
        }
        let yy = y.square();
        let u = yy.sub(ONE);
        let v = c.d.mul(yy).add(ONE);
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let mut e = [0xFFu8; 32]; // (p - 5) / 8 = 2^252 - 3
        e[0] = 0xFD;
        e[31] = 0x0F;
        let mut x = u.mul(v3).mul(u.mul(v7).pow(&e));
        let vxx = v.mul(x.square());
        if !vxx.eq(u) {
            if vxx.eq(u.neg()) {
                x = x.mul(c.sqrt_m1);
            } else {
                return None;
            }
        }
        if x.is_zero() && sign == 1 {
            return None;
        }
        if x.is_negative() as u8 != sign {
            x = x.neg();
        }
        Some(Point { x, y, z: ONE, t: x.mul(y) })
    }
}

fn base(c: &Consts) -> Point {
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    Point::decode(&b, c).expect("base point")
}

// ---- scalars mod L ------------------------------------------------------------------------------

const L: [i64; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn mod_l(x: &mut [i64; 64]) -> [u8; 32] {
    for i in (32..64).rev() {
        let mut carry = 0i64;
        let mut j = i - 32;
        while j < i - 12 {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
            j += 1;
        }
        x[j] += carry;
        x[i] = 0;
    }
    let mut carry = 0i64;
    for j in 0..32 {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for j in 0..32 {
        x[j] -= carry * L[j];
    }
    let mut r = [0u8; 32];
    for i in 0..32 {
        x[i + 1] += x[i] >> 8;
        r[i] = (x[i] & 255) as u8;
    }
    r
}

fn reduce64(h: &[u8; 64]) -> [u8; 32] {
    let mut x = [0i64; 64];
    for i in 0..64 {
        x[i] = h[i] as i64;
    }
    mod_l(&mut x)
}

/// S < L (little-endian compare)?
fn scalar_canonical(s: &[u8]) -> bool {
    for i in (0..32).rev() {
        let l = L[i] as u8;
        if s[i] < l {
            return true;
        }
        if s[i] > l {
            return false;
        }
    }
    false
}

fn hash_k(r: &[u8], a: &[u8; 32], m: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(m);
    reduce64(&h.finish())
}

// ---- API ----------------------------------------------------------------------------------------

/// A signing key: derived from a 32-byte seed (the RFC 8032 "private key").
pub struct SigningKey {
    a: [u8; 32],
    prefix: [u8; 32],
    public: [u8; 32],
}

impl SigningKey {
    pub fn from_seed(seed: &[u8; 32]) -> SigningKey {
        let mut h = crate::sha2::sha512(seed);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);
        let c = consts();
        let public = base(&c).mul_ct(&a, &c).encode();
        let key = SigningKey { a, prefix, public };
        for x in h.iter_mut() {
            // SAFETY: a plain write to a live local (the expanded secret key).
            unsafe { core::ptr::write_volatile(x, 0) };
        }
        wipe(&mut a);
        wipe(&mut prefix);
        key
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    pub fn sign(&self, m: &[u8]) -> [u8; 64] {
        let c = consts();
        let mut h = Sha512::new();
        h.update(&self.prefix);
        h.update(m);
        let mut r = reduce64(&h.finish());
        let rr = base(&c).mul_ct(&r, &c).encode();
        let k = hash_k(&rr, &self.public, m);
        let mut x = [0i64; 64];
        for i in 0..32 {
            x[i] = r[i] as i64;
        }
        for i in 0..32 {
            for j in 0..32 {
                x[i + j] += k[i] as i64 * self.a[j] as i64;
            }
        }
        let s = mod_l(&mut x);
        wipe(&mut r);
        for v in x.iter_mut() {
            // SAFETY: a plain write to a live local; volatile so the wipe is not optimised away.
            unsafe { core::ptr::write_volatile(v, 0) };
        }
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&rr);
        sig[32..].copy_from_slice(&s);
        sig
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        wipe(&mut self.a);
        wipe(&mut self.prefix);
    }
}

/// Overwrite secret bytes (volatile: not optimised away as a dead store).
fn wipe(b: &mut [u8; 32]) {
    for x in b.iter_mut() {
        // SAFETY: a plain write to a live byte.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
}

#[cfg(test)]
pub(crate) fn mul_ct_matches(s: &[u8; 32]) -> bool {
    let c = consts();
    let b = base(&c);
    b.mul_ct(s, &c).encode() == b.mul(s, &c).encode()
}

/// True iff `sig` is a valid Ed25519 signature of `m` by `public`.
pub fn verify(public: &[u8; 32], m: &[u8], sig: &[u8; 64]) -> bool {
    if !scalar_canonical(&sig[32..]) {
        return false;
    }
    let c = consts();
    let Some(a) = Point::decode(public, &c) else {
        return false;
    };
    let k = hash_k(&sig[..32], public, m);
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);
    let check = base(&c).mul(&s, &c).add(a.neg().mul(&k, &c), &c);
    check.encode()[..] == sig[..32]
}
