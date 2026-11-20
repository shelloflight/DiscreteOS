//! Constant-time X25519 Diffie-Hellman key agreement (RFC 7748).
//!
//! Montgomery ladder over GF(2^255 - 19) using five 51-bit limbs (u128 products).
//! Every operation on the secret scalar is branchless and memory-access-uniform;
//! conditional swaps use bitmasks and the local clamped scalar is wiped before return.

use crate::ct::{ct_is_zero, ct_mask_u64, wipe_bytes};

const MASK: u64 = (1 << 51) - 1;
const A24: u64 = 121_665;

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

const ZERO: Fe = Fe([0; 5]);
const ONE: Fe = Fe([1, 0, 0, 0, 0]);

fn load64_le(b: &[u8], at: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(x)
}

impl Fe {
    fn from_bytes(b: &[u8; 32]) -> Fe {
        // RFC 7748 §5: clear bit 255 of u-coordinate.
        let mut t = *b;
        t[31] &= 0x7F;
        Fe([
            load64_le(&t, 0) & MASK,
            (load64_le(&t, 6) >> 3) & MASK,
            (load64_le(&t, 12) >> 6) & MASK,
            (load64_le(&t, 19) >> 1) & MASK,
            (load64_le(&t, 24) >> 12) & MASK,
        ])
    }

    #[inline]
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

    #[inline]
    fn add(self, o: Fe) -> Fe {
        Fe::carry([
            self.0[0] + o.0[0],
            self.0[1] + o.0[1],
            self.0[2] + o.0[2],
            self.0[3] + o.0[3],
            self.0[4] + o.0[4],
        ])
    }

    #[inline]
    fn sub(self, o: Fe) -> Fe {
        // + 4p keeps every limb strictly non-negative for weakly reduced inputs.
        const P4: [u64; 5] = [
            0x1FFFFFFFFFFFB4,
            0x1FFFFFFFFFFFFC,
            0x1FFFFFFFFFFFFC,
            0x1FFFFFFFFFFFFC,
            0x1FFFFFFFFFFFFC,
        ];
        Fe::carry([
            self.0[0] + P4[0] - o.0[0],
            self.0[1] + P4[1] - o.0[1],
            self.0[2] + P4[2] - o.0[2],
            self.0[3] + P4[3] - o.0[3],
            self.0[4] + P4[4] - o.0[4],
        ])
    }

    #[inline]
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
        Fe::carry([
            ((r0 & m) + 19 * c4) as u64,
            (r1 & m) as u64,
            (r2 & m) as u64,
            (r3 & m) as u64,
            (r4 & m) as u64,
        ])
    }

    #[inline]
    fn mul_small(self, s: u64) -> Fe {
        let s = u128::from(s);
        let m = MASK as u128;
        let r0 = u128::from(self.0[0]) * s;
        let r1 = u128::from(self.0[1]) * s + (r0 >> 51);
        let r2 = u128::from(self.0[2]) * s + (r1 >> 51);
        let r3 = u128::from(self.0[3]) * s + (r2 >> 51);
        let r4 = u128::from(self.0[4]) * s + (r3 >> 51);
        Fe::carry([
            ((r0 & m) + 19 * (r4 >> 51)) as u64,
            (r1 & m) as u64,
            (r2 & m) as u64,
            (r3 & m) as u64,
            (r4 & m) as u64,
        ])
    }

    #[inline]
    fn square(self) -> Fe {
        self.mul(self)
    }

    /// Constant-time inversion via Fermat's little theorem: self^(2^255 - 21).
    fn invert(self) -> Fe {
        let pow2k = |mut x: Fe, k: usize| -> Fe {
            for _ in 0..k {
                x = x.square();
            }
            x
        };
        let x2 = self.square();
        let x9 = pow2k(x2, 2).mul(self);
        let x11 = x9.mul(x2);
        let x22 = x11.square();
        let x_5_0 = x22.mul(x9); // 2^5 - 1
        let x_10_0 = pow2k(x_5_0, 5).mul(x_5_0); // 2^10 - 1
        let x_20_0 = pow2k(x_10_0, 10).mul(x_10_0); // 2^20 - 1
        let x_40_0 = pow2k(x_20_0, 20).mul(x_20_0); // 2^40 - 1
        let x_50_0 = pow2k(x_40_0, 10).mul(x_10_0); // 2^50 - 1
        let x_100_0 = pow2k(x_50_0, 50).mul(x_50_0); // 2^100 - 1
        let x_200_0 = pow2k(x_100_0, 100).mul(x_100_0); // 2^200 - 1
        let x_250_0 = pow2k(x_200_0, 50).mul(x_50_0); // 2^250 - 1
        pow2k(x_250_0, 5).mul(x11) // 2^255 - 21 = p - 2
    }

    #[inline(never)]
    fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
        let mask = ct_mask_u64(swap);
        for i in 0..5 {
            let diff = (a.0[i] ^ b.0[i]) & mask;
            a.0[i] ^= diff;
            b.0[i] ^= diff;
        }
    }
}

/// Raw RFC 7748 X25519 scalar multiplication `scalar * u` (does not reject zero output).
pub fn x25519_raw(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x_1 = Fe::from_bytes(u);
    let mut x_2 = ONE;
    let mut z_2 = ZERO;
    let mut x_3 = x_1;
    let mut z_3 = ONE;
    let mut swap = 0u64;

    for t in (0..255).rev() {
        let k_t = u64::from((k[t >> 3] >> (t & 7)) & 1);
        swap ^= k_t;
        Fe::cswap(swap, &mut x_2, &mut x_3);
        Fe::cswap(swap, &mut z_2, &mut z_3);
        swap = k_t;

        let a = x_2.add(z_2);
        let aa = a.square();
        let b = x_2.sub(z_2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x_3.add(z_3);
        let d = x_3.sub(z_3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x_3 = da.add(cb).square();
        z_3 = x_1.mul(da.sub(cb).square());
        x_2 = aa.mul(bb);
        z_2 = e.mul(aa.add(e.mul_small(A24)));
    }
    Fe::cswap(swap, &mut x_2, &mut x_3);
    Fe::cswap(swap, &mut z_2, &mut z_3);
    wipe_bytes(&mut k);
    x_2.mul(z_2.invert()).to_bytes()
}

/// X25519 shared secret computation (`RFC 7748` + `RFC 8446 §7.4.2`).
/// Returns `None` if the shared secret is the all-zero low-order point.
pub fn diffie_hellman(secret: &[u8; 32], peer_public: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = x25519_raw(secret, peer_public);
    if ct_is_zero(&shared) { None } else { Some(shared) }
}

/// Derive the X25519 public key for `secret` (`u = 9`).
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519_raw(secret, &base)
}
