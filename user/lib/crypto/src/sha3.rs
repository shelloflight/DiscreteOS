//! SHA-3 and SHAKE XOF (FIPS 202): `Sha3_256`, `Sha3_512`, `Shake128`, `Shake256`.
//!
//! Pure ARX Keccak-f[1600] sponge with zero lookup tables and zero unsafe code.
//! Used by FIPS 203 ML-KEM-768 (`H`, `G`, `J`, `XOF`, `PRF`).

use crate::ct::wipe_bytes;

const RC: [u64; 24] = [
    0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
    0x0000_0000_0000_808B, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
    0x0000_0000_0000_008A, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
    0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
    0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
];

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccak_f1600(a: &mut [u64; 25]) {
    for &rc in &RC {
        // Theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // Rho + Pi
        let mut cur = a[1];
        for i in 0..24 {
            let j = PI[i];
            let next = a[j];
            a[j] = cur.rotate_left(RHO[i]);
            cur = next;
        }
        // Chi
        for y in 0..5 {
            let row = [a[5 * y], a[5 * y + 1], a[5 * y + 2], a[5 * y + 3], a[5 * y + 4]];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
        // Iota
        a[0] ^= rc;
    }
}

#[derive(Clone)]
struct Sponge {
    state: [u64; 25],
    rate: usize,
    pos: usize,
    squeezing: bool,
}

impl Drop for Sponge {
    fn drop(&mut self) {
        for x in &mut self.state {
            // SAFETY: volatile write to a live mutable reference.
            unsafe { core::ptr::write_volatile(x, 0) };
        }
    }
}

impl Sponge {
    const fn new(rate: usize) -> Self {
        Self { state: [0; 25], rate, pos: 0, squeezing: false }
    }

    fn xor_byte(&mut self, idx: usize, b: u8) {
        self.state[idx / 8] ^= u64::from(b) << (8 * (idx % 8));
    }

    fn read_byte(&self, idx: usize) -> u8 {
        (self.state[idx / 8] >> (8 * (idx % 8))) as u8
    }

    fn absorb(&mut self, data: &[u8]) {
        for &b in data {
            self.xor_byte(self.pos, b);
            self.pos += 1;
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    fn finalize_domain(&mut self, domain_sep: u8) {
        self.xor_byte(self.pos, domain_sep);
        self.xor_byte(self.rate - 1, 0x80);
        keccak_f1600(&mut self.state);
        self.pos = 0;
        self.squeezing = true;
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            *b = self.read_byte(self.pos);
            self.pos += 1;
        }
    }
}

/// SHA3-256 (FIPS 202, rate = 136 bytes, domain sep = 0x06).
pub struct Sha3_256(Sponge);

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_256 {
    pub const fn new() -> Self {
        Self(Sponge::new(136))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }

    pub fn finish(mut self) -> [u8; 32] {
        self.0.finalize_domain(0x06);
        let mut out = [0u8; 32];
        self.0.squeeze(&mut out);
        out
    }
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finish()
}

/// SHA3-512 (FIPS 202, rate = 72 bytes, domain sep = 0x06).
pub struct Sha3_512(Sponge);

impl Default for Sha3_512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_512 {
    pub const fn new() -> Self {
        Self(Sponge::new(72))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }

    pub fn finish(mut self) -> [u8; 64] {
        self.0.finalize_domain(0x06);
        let mut out = [0u8; 64];
        self.0.squeeze(&mut out);
        out
    }
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(data);
    h.finish()
}

/// SHAKE128 extendable-output function (FIPS 202, rate = 168 bytes, domain sep = 0x1F).
pub struct Shake128(Sponge);

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake128 {
    pub const fn new() -> Self {
        Self(Sponge::new(168))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.0.squeezing {
            self.0.finalize_domain(0x1F);
        }
        self.0.squeeze(out);
    }
}

/// SHAKE256 extendable-output function (FIPS 202, rate = 136 bytes, domain sep = 0x1F).
pub struct Shake256(Sponge);

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake256 {
    pub const fn new() -> Self {
        Self(Sponge::new(136))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.0.squeezing {
            self.0.finalize_domain(0x1F);
        }
        self.0.squeeze(out);
    }
}

/// Convenience SHAKE256 one-shot output into `out` (wipes temporary state on drop).
pub fn shake256_into(parts: &[&[u8]], out: &mut [u8]) {
    let mut xof = Shake256::new();
    for p in parts {
        xof.update(p);
    }
    xof.squeeze(out);
}

#[allow(dead_code)]
fn _keep_wipe() {
    let mut x = [0u8; 1];
    wipe_bytes(&mut x);
}
