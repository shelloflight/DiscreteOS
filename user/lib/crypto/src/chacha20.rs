//! Constant-time ChaCha20-Poly1305 AEAD (RFC 8439).
//!
//! Pure ARX ChaCha20 and radix-2^26 Poly1305 (Donna reduction mod 2^130 - 5) with no lookup
//! tables and no secret-dependent branches. Authentication tag verification is constant-time,
//! and decryption wipes the plaintext buffer on authentication failure.

use crate::ct::ct_mask_u32;
pub use crate::ct::{ct_eq, wipe_bytes};

#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);

    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);

    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);

    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

#[inline]
fn u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Compute one 64-byte ChaCha20 keystream block (RFC 8439 §2.3).
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let init = [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        u32_le(key, 0),
        u32_le(key, 4),
        u32_le(key, 8),
        u32_le(key, 12),
        u32_le(key, 16),
        u32_le(key, 20),
        u32_le(key, 24),
        u32_le(key, 28),
        counter,
        u32_le(nonce, 0),
        u32_le(nonce, 4),
        u32_le(nonce, 8),
    ];
    let mut w = init;
    for _ in 0..10 {
        quarter_round(&mut w, 0, 4, 8, 12);
        quarter_round(&mut w, 1, 5, 9, 13);
        quarter_round(&mut w, 2, 6, 10, 14);
        quarter_round(&mut w, 3, 7, 11, 15);
        quarter_round(&mut w, 0, 5, 10, 15);
        quarter_round(&mut w, 1, 6, 11, 12);
        quarter_round(&mut w, 2, 7, 8, 13);
        quarter_round(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = w[i].wrapping_add(init[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// XOR `data` in place with ChaCha20 keystream starting at `counter`.
pub fn chacha20_xor(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    for chunk in data.chunks_mut(64) {
        let mut block = chacha20_block(key, counter, nonce);
        for (d, &k) in chunk.iter_mut().zip(block.iter()) {
            *d ^= k;
        }
        wipe_bytes(&mut block);
        counter = counter.wrapping_add(1);
    }
}

/// Streaming Poly1305 authenticator (RFC 8439 §2.5), constant-time radix-2^26.
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    h: [u32; 5],
    buf: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let t0 = u32_le(key, 0);
        let t1 = u32_le(key, 4);
        let t2 = u32_le(key, 8);
        let t3 = u32_le(key, 12);
        // Clamp r per RFC 8439 §2.5.
        let r0 = t0 & 0x03ff_ffff;
        let r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ff_ff03;
        let r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ff_c0ff;
        let r3 = ((t2 >> 14) | (t3 << 18)) & 0x03f0_3fff;
        let r4 = (t3 >> 8) & 0x000f_ffff;
        Self {
            r: [r0, r1, r2, r3, r4],
            s: [u32_le(key, 16), u32_le(key, 20), u32_le(key, 24), u32_le(key, 28)],
            h: [0; 5],
            buf: [0; 16],
            buf_len: 0,
        }
    }

    fn block(&mut self, msg: &[u8; 16], hibit: u32) {
        let [r0, r1, r2, r3, r4] = self.r.map(u64::from);
        let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);

        let t0 = u32_le(msg, 0);
        let t1 = u32_le(msg, 4);
        let t2 = u32_le(msg, 8);
        let t3 = u32_le(msg, 12);

        let h0 = u64::from(self.h[0]) + u64::from(t0 & 0x03ff_ffff);
        let h1 = u64::from(self.h[1]) + u64::from(((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff);
        let h2 = u64::from(self.h[2]) + u64::from(((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff);
        let h3 = u64::from(self.h[3]) + u64::from(((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff);
        let h4 = u64::from(self.h[4]) + u64::from((t3 >> 8) | hibit);

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c = d0 >> 26;
        let mut h0 = (d0 as u32) & 0x03ff_ffff;
        d1 += c;
        c = d1 >> 26;
        let mut h1 = (d1 as u32) & 0x03ff_ffff;
        d2 += c;
        c = d2 >> 26;
        let h2 = (d2 as u32) & 0x03ff_ffff;
        d3 += c;
        c = d3 >> 26;
        let h3 = (d3 as u32) & 0x03ff_ffff;
        d4 += c;
        c = d4 >> 26;
        let h4 = (d4 as u32) & 0x03ff_ffff;
        h0 += (c as u32) * 5;
        let c2 = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c2;

        self.h = [h0, h1, h2, h3, h4];
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 16 {
                let b = self.buf;
                self.block(&b, 1 << 24);
                self.buf_len = 0;
            }
        }
        while data.len() >= 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&data[..16]);
            self.block(&b, 1 << 24);
            data = &data[16..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn pad16(&mut self) {
        if self.buf_len != 0 {
            let zeros = [0u8; 16];
            self.update(&zeros[..16 - self.buf_len]);
        }
    }

    pub fn finish(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            let mut b = [0u8; 16];
            b[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            b[self.buf_len] = 1;
            self.block(&b, 0);
        }

        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
        let mut c = h1 >> 26;
        h1 &= 0x03ff_ffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x03ff_ffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x03ff_ffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x03ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;

        // Compute h + 5 - 2^130; select it iff carry out (h >= p).
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x03ff_ffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x03ff_ffff;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x03ff_ffff;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x03ff_ffff;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        let mask = ct_mask_u32((g4 >> 31) ^ 1); // 0xFFFFFFFF if h >= p else 0
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let g4_masked = g4 & mask;
        let nmask = !mask;
        h0 = (h0 & nmask) | g0;
        h1 = (h1 & nmask) | g1;
        h2 = (h2 & nmask) | g2;
        h3 = (h3 & nmask) | g3;
        h4 = (h4 & nmask) | g4_masked;

        // Pack 5x26-bit limbs into 4x32-bit words and add s mod 2^128.
        let mut f = u64::from(h0 | (h1 << 26)) + u64::from(self.s[0]);
        let w0 = f as u32;
        f = (f >> 32) + u64::from((h1 >> 6) | (h2 << 20)) + u64::from(self.s[1]);
        let w1 = f as u32;
        f = (f >> 32) + u64::from((h2 >> 12) | (h3 << 14)) + u64::from(self.s[2]);
        let w2 = f as u32;
        f = (f >> 32) + u64::from((h3 >> 18) | (h4 << 8)) + u64::from(self.s[3]);
        let w3 = f as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&w0.to_le_bytes());
        tag[4..8].copy_from_slice(&w1.to_le_bytes());
        tag[8..12].copy_from_slice(&w2.to_le_bytes());
        tag[12..16].copy_from_slice(&w3.to_le_bytes());
        tag
    }
}

pub fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(key);
    p.update(msg);
    p.finish()
}

fn poly1305_aead_tag(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(otk);
    p.update(aad);
    p.pad16();
    p.update(ct);
    p.pad16();
    p.update(&(aad.len() as u64).to_le_bytes());
    p.update(&(ct.len() as u64).to_le_bytes());
    p.finish()
}

/// Encrypt `buf` in place and return the 16-byte Poly1305 authentication tag (RFC 8439 §2.8).
pub fn seal_in_place(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    let mut block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);
    wipe_bytes(&mut block0);

    chacha20_xor(key, 1, nonce, buf);
    let tag = poly1305_aead_tag(&otk, aad, buf);
    wipe_bytes(&mut otk);
    tag
}

/// Verify `tag` and decrypt `buf` in place (RFC 8439 §2.8).
/// On authentication failure, wipes `buf` and returns `false`.
pub fn open_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    let mut block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);
    wipe_bytes(&mut block0);

    let expected = poly1305_aead_tag(&otk, aad, buf);
    wipe_bytes(&mut otk);
    if !ct_eq(&expected, tag) {
        wipe_bytes(buf);
        return false;
    }
    chacha20_xor(key, 1, nonce, buf);
    true
}
