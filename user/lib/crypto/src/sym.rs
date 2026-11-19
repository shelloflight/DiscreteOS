//! Symmetric pieces of TPM credential protection (TPM 2.0 Library Part 1, 11.4 and 24):
//! HMAC-SHA256, KDFa (SP 800-108 counter mode), and AES-128 in CFB mode (the EK's symmetric
//! algorithm). Used by `tpm::make_credential` (verifier) and the test TPM simulator.
//!
//! AES uses a table S-box (not constant-time): the keys here are a verifier's one-time credential
//! keys and the simulator's, never a long-lived secret on a shared machine.

use crate::sha2::Sha256;

/// HMAC-SHA256 over the concatenation of `parts`.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&crate::sha2::sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    let mut outer = Sha256::new();
    let (mut ipad, mut opad) = ([0x36u8; 64], [0x5Cu8; 64]);
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    inner.update(&ipad);
    for p in parts {
        inner.update(p);
    }
    outer.update(&opad);
    outer.update(&inner.finish());
    k.fill(0);
    outer.finish()
}

/// KDFa with HMAC-SHA256: `out.len()` bytes of key from `key`, `label` (its terminating zero is
/// added here) and the two contexts.
pub fn kdfa(key: &[u8], label: &str, context_u: &[u8], context_v: &[u8], out: &mut [u8]) {
    let bits = (out.len() as u32) * 8;
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let counter = (i as u32 + 1).to_be_bytes();
        let h = hmac_sha256(key, &[&counter, label.as_bytes(), &[0], context_u, context_v, &bits.to_be_bytes()]);
        chunk.copy_from_slice(&h[..chunk.len()]);
    }
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
    0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
    0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
    0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
    0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
    0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
    0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
    0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
    0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1B } else { 0 }
}

/// AES-128 (FIPS 197), encryption only (CFB needs no decryption).
pub struct Aes128 {
    rk: [[u8; 16]; 11],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Aes128 {
        let mut w = [[0u8; 4]; 44];
        for i in 0..4 {
            w[i].copy_from_slice(&key[4 * i..4 * i + 4]);
        }
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut t = w[i - 1];
            if i % 4 == 0 {
                t = [SBOX[t[1] as usize] ^ rcon, SBOX[t[2] as usize], SBOX[t[3] as usize], SBOX[t[0] as usize]];
                rcon = xtime(rcon);
            }
            for j in 0..4 {
                w[i][j] = w[i - 4][j] ^ t[j];
            }
        }
        let mut rk = [[0u8; 16]; 11];
        for (r, k) in rk.iter_mut().enumerate() {
            for c in 0..4 {
                k[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
        }
        Aes128 { rk }
    }

    pub fn encrypt_block(&self, b: &mut [u8; 16]) {
        for (x, k) in b.iter_mut().zip(self.rk[0].iter()) {
            *x ^= k;
        }
        for (round, rk) in self.rk.iter().enumerate().skip(1) {
            for x in b.iter_mut() {
                *x = SBOX[*x as usize];
            }
            // ShiftRows (column-major state: byte r + 4c is row r, column c).
            let s = *b;
            for c in 0..4 {
                for r in 0..4 {
                    b[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
                }
            }
            if round != 10 {
                for c in 0..4 {
                    let col = [b[4 * c], b[4 * c + 1], b[4 * c + 2], b[4 * c + 3]];
                    let all = col[0] ^ col[1] ^ col[2] ^ col[3];
                    for r in 0..4 {
                        b[4 * c + r] = col[r] ^ all ^ xtime(col[r] ^ col[(r + 1) % 4]);
                    }
                }
            }
            for (x, k) in b.iter_mut().zip(rk.iter()) {
                *x ^= k;
            }
        }
    }

    /// CFB-128 with a zero IV (what the TPM uses for credential and parameter protection).
    pub fn cfb_encrypt(&self, data: &mut [u8]) {
        let mut iv = [0u8; 16];
        for chunk in data.chunks_mut(16) {
            self.encrypt_block(&mut iv);
            for (d, k) in chunk.iter_mut().zip(iv.iter()) {
                *d ^= k;
            }
            iv[..chunk.len()].copy_from_slice(chunk);
        }
    }

    pub fn cfb_decrypt(&self, data: &mut [u8]) {
        let mut iv = [0u8; 16];
        for chunk in data.chunks_mut(16) {
            self.encrypt_block(&mut iv);
            let mut next = [0u8; 16];
            next[..chunk.len()].copy_from_slice(chunk);
            for (d, k) in chunk.iter_mut().zip(iv.iter()) {
                *d ^= k;
            }
            iv = next;
        }
    }
}
