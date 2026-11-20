//! ECDSA over NIST P-384 (`secp384r1`, FIPS 186-5, SEC 1), verification only.
//!
//! Required for verifying real-world public-internet TLS certificate chains (ISRG Root X2,
//! DigiCert Global Root G3, Google Trust Services R3/R4, etc.) and TLS 1.3 `CertificateVerify`
//! with `ecdsa_secp384r1_sha384` (`0x0503`).
//!
//! Integers are six little-endian u64 limbs. Both moduli (field prime `p` and group order `n`)
//! use CIOS Montgomery multiplication; inverses are Fermat powers (`m - 2`). Points are in
//! Jacobian coordinates (`a = -3` doubling) and `u1*G + u2*Q` uses one Shamir ladder.
//! Verification handles only public data.

use crate::sha2::sha384;

type U384 = [u64; 6];

const P: U384 = [
    0x0000_0000_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];
const N: U384 = [
    0xECEC_196A_CCC5_2973,
    0x581A_0DB2_48B0_A77A,
    0xC763_4D81_F437_2DDF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];
const B: U384 = [
    0x2A85_C8ED_D3EC_2AEF,
    0xC656_398D_8A2E_D19D,
    0x0314_088F_5013_875A,
    0x181D_9C6E_FE81_4112,
    0x988E_056B_E3F8_2D19,
    0xB331_2FA7_E23E_E7E4,
];
const GX: U384 = [
    0x3A54_5E38_7276_0AB7,
    0x5502_F25D_BF55_296C,
    0x59F7_41E0_8254_2A38,
    0x6E1D_3B62_8BA7_9B98,
    0x8EB1_C71E_F320_AD74,
    0xAA87_CA22_BE8B_0537,
];
const GY: U384 = [
    0x7A43_1D7C_90EA_0E5F,
    0x0A60_B1CE_1D7E_819D,
    0xE9DA_3113_B5F0_B8C0,
    0xF8F4_1DBD_289A_147C,
    0x5D9E_98BF_9292_DC29,
    0x3617_DE4A_9626_2C6F,
];

fn from_be(b: &[u8; 48]) -> U384 {
    let mut r = [0u64; 6];
    for (i, limb) in r.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[48 - 8 * (i + 1)..48 - 8 * i]);
        *limb = u64::from_be_bytes(w);
    }
    r
}

fn to_be(a: &U384) -> [u8; 48] {
    let mut out = [0u8; 48];
    for i in 0..6 {
        out[48 - 8 * (i + 1)..48 - 8 * i].copy_from_slice(&a[i].to_be_bytes());
    }
    out
}

fn is_zero(a: &U384) -> bool {
    a.iter().all(|&x| x == 0)
}

fn geq(a: &U384, b: &U384) -> bool {
    for i in (0..6).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn add(a: &U384, b: &U384) -> (U384, bool) {
    let mut r = [0u64; 6];
    let mut c = false;
    for i in 0..6 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(c as u64);
        r[i] = s2;
        c = c1 || c2;
    }
    (r, c)
}

fn sub(a: &U384, b: &U384) -> (U384, bool) {
    let mut r = [0u64; 6];
    let mut br = false;
    for i in 0..6 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(br as u64);
        r[i] = d2;
        br = b1 || b2;
    }
    (r, br)
}

struct Field {
    m: U384,
    minv: u64,
    r2: U384,
    one: U384,
}

impl Field {
    fn new(m: U384) -> Field {
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
        }
        let mut f = Field { m, minv: inv.wrapping_neg(), r2: [0; 6], one: [0; 6] };
        let mut x: U384 = [1, 0, 0, 0, 0, 0];
        for i in 0..768 {
            x = f.add(&x, &x);
            if i == 383 {
                f.one = x;
            }
        }
        f.r2 = x;
        f
    }

    fn add(&self, a: &U384, b: &U384) -> U384 {
        let (s, c) = add(a, b);
        if c || geq(&s, &self.m) { sub(&s, &self.m).0 } else { s }
    }

    fn sub(&self, a: &U384, b: &U384) -> U384 {
        let (d, br) = sub(a, b);
        if br { add(&d, &self.m).0 } else { d }
    }

    fn mul(&self, a: &U384, b: &U384) -> U384 {
        let mut t = [0u64; 8];
        for &bi in b {
            let mut c: u128 = 0;
            for j in 0..6 {
                let s = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + c;
                t[j] = s as u64;
                c = s >> 64;
            }
            let s = u128::from(t[6]) + c;
            t[6] = s as u64;
            t[7] = (s >> 64) as u64;
            let u = t[0].wrapping_mul(self.minv);
            let s = u128::from(t[0]) + u128::from(u) * u128::from(self.m[0]);
            let mut c = s >> 64;
            for j in 1..6 {
                let s = u128::from(t[j]) + u128::from(u) * u128::from(self.m[j]) + c;
                t[j - 1] = s as u64;
                c = s >> 64;
            }
            let s = u128::from(t[6]) + c;
            t[5] = s as u64;
            t[6] = (u128::from(t[7]) + (s >> 64)) as u64;
            t[7] = 0;
        }
        let r = [t[0], t[1], t[2], t[3], t[4], t[5]];
        if t[6] != 0 || geq(&r, &self.m) { sub(&r, &self.m).0 } else { r }
    }

    fn sq(&self, a: &U384) -> U384 {
        self.mul(a, a)
    }

    fn to_mont(&self, a: &U384) -> U384 {
        self.mul(a, &self.r2)
    }

    #[allow(clippy::wrong_self_convention)]
    fn from_mont(&self, a: &U384) -> U384 {
        self.mul(a, &[1, 0, 0, 0, 0, 0])
    }

    fn pow(&self, base: &U384, exp: &U384) -> U384 {
        let mut acc = self.one;
        for &limb in exp.iter().rev() {
            for bit in (0..64).rev() {
                acc = self.sq(&acc);
                if (limb >> bit) & 1 != 0 {
                    acc = self.mul(&acc, base);
                }
            }
        }
        acc
    }

    fn inv(&self, a: &U384) -> U384 {
        let exp = sub(&self.m, &[2, 0, 0, 0, 0, 0]).0;
        self.pow(a, &exp)
    }

    fn small(&self, n: u64) -> U384 {
        self.to_mont(&[n, 0, 0, 0, 0, 0])
    }
}

#[derive(Clone, Copy)]
struct Jac {
    x: U384,
    y: U384,
    z: U384,
}

impl Jac {
    const INF: Jac = Jac { x: [0; 6], y: [0; 6], z: [0; 6] };

    fn is_inf(&self) -> bool {
        is_zero(&self.z)
    }

    fn double(&self, f: &Field) -> Jac {
        if self.is_inf() || is_zero(&self.y) {
            return Jac::INF;
        }
        let delta = f.sq(&self.z);
        let gamma = f.sq(&self.y);
        let beta = f.mul(&self.x, &gamma);
        let s1 = f.sub(&self.x, &delta);
        let s2 = f.add(&self.x, &delta);
        let p = f.mul(&s1, &s2);
        let alpha = f.add(&f.add(&p, &p), &p); // 3 * (X - Z^2)(X + Z^2)
        let b2 = f.add(&beta, &beta);
        let b4 = f.add(&b2, &b2);
        let b8 = f.add(&b4, &b4);
        let x3 = f.sub(&f.sq(&alpha), &b8);
        let g2 = f.sq(&gamma);
        let g4 = f.add(&g2, &g2);
        let g8 = f.add(&g4, &g4);
        let y3 = f.sub(&f.mul(&alpha, &f.sub(&b4, &x3)), &f.add(&g8, &g8));
        let yz = f.mul(&self.y, &self.z);
        let z3 = f.add(&yz, &yz);
        Jac { x: x3, y: y3, z: z3 }
    }

    fn add(&self, q: &Jac, f: &Field) -> Jac {
        if self.is_inf() {
            return *q;
        }
        if q.is_inf() {
            return *self;
        }
        let z1z1 = f.sq(&self.z);
        let z2z2 = f.sq(&q.z);
        let u1 = f.mul(&self.x, &z2z2);
        let u2 = f.mul(&q.x, &z1z1);
        let s1 = f.mul(&self.y, &f.mul(&q.z, &z2z2));
        let s2 = f.mul(&q.y, &f.mul(&self.z, &z1z1));
        let h = f.sub(&u2, &u1);
        let r = f.sub(&s2, &s1);
        if is_zero(&h) {
            return if is_zero(&r) { self.double(f) } else { Jac::INF };
        }
        let hh = f.sq(&h);
        let hhh = f.mul(&h, &hh);
        let v = f.mul(&u1, &hh);
        let x3 = f.sub(&f.sub(&f.sq(&r), &hhh), &f.add(&v, &v));
        let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.mul(&s1, &hhh));
        let z3 = f.mul(&f.mul(&self.z, &q.z), &h);
        Jac { x: x3, y: y3, z: z3 }
    }
}

/// A validated point on NIST P-384 (affine coordinates `(x, y)` in big-endian).
#[derive(Clone, Copy)]
pub struct PublicKey {
    x: U384,
    y: U384,
}

impl PublicKey {
    /// From affine coordinates `(x, y)`, each 48 bytes big-endian. Rejects points not on the curve.
    pub fn from_xy(x_be: &[u8; 48], y_be: &[u8; 48]) -> Option<PublicKey> {
        let x = from_be(x_be);
        let y = from_be(y_be);
        if geq(&x, &P) || geq(&y, &P) {
            return None;
        }
        let f = Field::new(P);
        let xm = f.to_mont(&x);
        let ym = f.to_mont(&y);
        let bm = f.to_mont(&B);
        let lhs = f.sq(&ym);
        let x3 = f.mul(&f.sq(&xm), &xm);
        let three_x = f.mul(&f.small(3), &xm);
        let rhs = f.add(&f.sub(&x3, &three_x), &bm);
        (lhs == rhs).then_some(PublicKey { x, y })
    }

    /// From uncompressed SEC 1 encoding (`0x04 || x(48) || y(48)`).
    pub fn from_sec1(b: &[u8]) -> Option<PublicKey> {
        if b.len() != 97 || b[0] != 0x04 {
            return None;
        }
        let x: &[u8; 48] = b[1..49].try_into().ok()?;
        let y: &[u8; 48] = b[49..97].try_into().ok()?;
        Self::from_xy(x, y)
    }

    pub fn to_xy(&self) -> ([u8; 48], [u8; 48]) {
        (to_be(&self.x), to_be(&self.y))
    }
}

/// Verify an ECDSA-P384 signature `(r || s)` (96 bytes big-endian) over SHA-384(`msg`).
pub fn verify(key: &PublicKey, msg: &[u8], sig: &[u8; 96]) -> bool {
    let digest = sha384(msg);
    verify_prehash(key, &digest, sig)
}

/// Verify an ECDSA-P384 signature `(r || s)` over a 48-byte pre-hashed digest.
pub fn verify_prehash(key: &PublicKey, digest: &[u8; 48], sig: &[u8; 96]) -> bool {
    let r = from_be(sig[..48].try_into().unwrap());
    let s = from_be(sig[48..96].try_into().unwrap());
    if is_zero(&r) || geq(&r, &N) || is_zero(&s) || geq(&s, &N) {
        return false;
    }
    let fn_ = Field::new(N);
    let mut z = from_be(digest);
    if geq(&z, &N) {
        z = sub(&z, &N).0;
    }
    let sm = fn_.to_mont(&s);
    let w = fn_.inv(&sm);
    let u1 = fn_.from_mont(&fn_.mul(&fn_.to_mont(&z), &w));
    let u2 = fn_.from_mont(&fn_.mul(&fn_.to_mont(&r), &w));

    let fp = Field::new(P);
    let g = Jac { x: fp.to_mont(&GX), y: fp.to_mont(&GY), z: fp.one };
    let q = Jac { x: fp.to_mont(&key.x), y: fp.to_mont(&key.y), z: fp.one };
    let gq = g.add(&q, &fp);

    let mut acc = Jac::INF;
    for limb in (0..6).rev() {
        for bit in (0..64).rev() {
            acc = acc.double(&fp);
            let b1 = ((u1[limb] >> bit) & 1) != 0;
            let b2 = ((u2[limb] >> bit) & 1) != 0;
            match (b1, b2) {
                (true, true) => acc = acc.add(&gq, &fp),
                (true, false) => acc = acc.add(&g, &fp),
                (false, true) => acc = acc.add(&q, &fp),
                (false, false) => {}
            }
        }
    }
    if acc.is_inf() {
        return false;
    }
    let zi = fp.inv(&acc.z);
    let zi2 = fp.sq(&zi);
    let mut x = fp.from_mont(&fp.mul(&acc.x, &zi2));
    if geq(&x, &N) {
        x = sub(&x, &N).0;
    }
    x == r
}

/// Self-check that the generator `(GX, GY)` lies on the curve (used in tests).
#[cfg(test)]
pub(crate) fn generator_on_curve() -> bool {
    PublicKey::from_xy(&to_be(&GX), &to_be(&GY)).is_some()
}
