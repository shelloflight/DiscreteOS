//! BLAKE3 (portable implementation, hash and keyed-hash modes, 32-byte output), after the
//! specification's reference implementation. DFS hashes every block with it (docs/storage.md).
//! Checked against the official test vectors (tests below).

const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;

const IV: [u32; 8] = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
const PERM: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline(always)]
fn g(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(x);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(y);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

fn compress(cv: &[u32; 8], block: &[u32; 16], counter: u64, len: u32, flags: u32) -> [u32; 16] {
    let mut s = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7], IV[0], IV[1], IV[2], IV[3],
        counter as u32, (counter >> 32) as u32, len, flags,
    ];
    let mut m = *block;
    for r in 0..7 {
        g(&mut s, 0, 4, 8, 12, m[0], m[1]);
        g(&mut s, 1, 5, 9, 13, m[2], m[3]);
        g(&mut s, 2, 6, 10, 14, m[4], m[5]);
        g(&mut s, 3, 7, 11, 15, m[6], m[7]);
        g(&mut s, 0, 5, 10, 15, m[8], m[9]);
        g(&mut s, 1, 6, 11, 12, m[10], m[11]);
        g(&mut s, 2, 7, 8, 13, m[12], m[13]);
        g(&mut s, 3, 4, 9, 14, m[14], m[15]);
        if r < 6 {
            let mut p = [0u32; 16];
            for i in 0..16 {
                p[i] = m[PERM[i]];
            }
            m = p;
        }
    }
    for i in 0..8 {
        s[i] ^= s[i + 8];
        s[i + 8] ^= cv[i];
    }
    s
}

fn words(b: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut w = [0u32; 16];
    for (i, c) in b.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    w
}

fn first8(s: &[u32; 16]) -> [u32; 8] {
    [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]
}

struct Output {
    cv: [u32; 8],
    block: [u32; 16],
    counter: u64,
    len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first8(&compress(&self.cv, &self.block, self.counter, self.len, self.flags))
    }
    fn root(&self, out: &mut [u8]) {
        for (n, chunk) in out.chunks_mut(2 * OUT_LEN).enumerate() {
            let w = compress(&self.cv, &self.block, n as u64, self.len, self.flags | ROOT);
            for (i, b) in chunk.iter_mut().enumerate() {
                *b = (w[i / 4] >> (8 * (i % 4))) as u8;
            }
        }
    }
}

struct Chunk {
    cv: [u32; 8],
    counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: usize,
    compressed: usize,
    flags: u32,
}

impl Chunk {
    fn new(key: &[u32; 8], counter: u64, flags: u32) -> Chunk {
        Chunk { cv: *key, counter, block: [0; BLOCK_LEN], block_len: 0, compressed: 0, flags }
    }
    fn len(&self) -> usize {
        BLOCK_LEN * self.compressed + self.block_len
    }
    fn start(&self) -> u32 {
        if self.compressed == 0 { CHUNK_START } else { 0 }
    }
    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len == BLOCK_LEN {
                let w = words(&self.block);
                self.cv = first8(&compress(&self.cv, &w, self.counter, BLOCK_LEN as u32, self.flags | self.start()));
                self.compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let take = (BLOCK_LEN - self.block_len).min(input.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&input[..take]);
            self.block_len += take;
            input = &input[take..];
        }
    }
    fn output(&self) -> Output {
        Output { cv: self.cv, block: words(&self.block), counter: self.counter, len: self.block_len as u32, flags: self.flags | self.start() | CHUNK_END }
    }
}

fn parent(l: [u32; 8], r: [u32; 8], key: &[u32; 8], flags: u32) -> Output {
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(&l);
    block[8..].copy_from_slice(&r);
    Output { cv: *key, block, counter: 0, len: BLOCK_LEN as u32, flags: PARENT | flags }
}

/// An incremental BLAKE3 hasher.
pub struct Hasher {
    chunk: Chunk,
    key: [u32; 8],
    stack: [[u32; 8]; 54],
    depth: usize,
    flags: u32,
}

impl Hasher {
    pub fn new() -> Hasher {
        Hasher::with(IV, 0)
    }

    /// Keyed mode: a MAC under `key`.
    pub fn keyed(key: &[u8; 32]) -> Hasher {
        let mut k = [0u32; 8];
        for (i, c) in key.as_chunks::<4>().0.iter().enumerate() {
            k[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        }
        Hasher::with(k, KEYED_HASH)
    }

    fn with(key: [u32; 8], flags: u32) -> Hasher {
        Hasher { chunk: Chunk::new(&key, 0, flags), key, stack: [[0; 8]; 54], depth: 0, flags }
    }

    fn push_chunk(&mut self, mut cv: [u32; 8], mut total: u64) {
        while total & 1 == 0 {
            self.depth -= 1;
            cv = parent(self.stack[self.depth], cv, &self.key, self.flags).chaining_value();
            total >>= 1;
        }
        self.stack[self.depth] = cv;
        self.depth += 1;
    }

    pub fn update(&mut self, mut input: &[u8]) -> &mut Hasher {
        while !input.is_empty() {
            if self.chunk.len() == CHUNK_LEN {
                let cv = self.chunk.output().chaining_value();
                let total = self.chunk.counter + 1;
                self.push_chunk(cv, total);
                self.chunk = Chunk::new(&self.key, total, self.flags);
            }
            let take = (CHUNK_LEN - self.chunk.len()).min(input.len());
            self.chunk.update(&input[..take]);
            input = &input[take..];
        }
        self
    }

    /// The hash; `out` may be any length (extendable output).
    pub fn finalize_into(&self, out: &mut [u8]) {
        let mut o = self.chunk.output();
        let mut n = self.depth;
        while n > 0 {
            n -= 1;
            o = parent(self.stack[n], o.chaining_value(), &self.key, self.flags);
        }
        o.root(out);
    }

    pub fn finalize(&self) -> [u8; 32] {
        let mut h = [0u8; 32];
        self.finalize_into(&mut h);
        h
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Hasher::new()
    }
}

/// BLAKE3 of `data`.
pub fn hash(data: &[u8]) -> [u8; 32] {
    Hasher::new().update(data).finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> std::string::String {
        b.iter().map(|x| std::format!("{:02x}", x)).collect()
    }

    fn input(n: usize) -> std::vec::Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn vectors() {
        // From the official test_vectors.json (input = bytes i % 251), first 32 bytes of output.
        let v: &[(usize, &str)] = &[
            (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
            (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
            (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"),
            (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
            (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
            (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
            (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"),
            (31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"),
        ];
        for &(n, want) in v {
            assert_eq!(hex(&hash(&input(n))), want, "input length {}", n);
            // Incremental updates in odd pieces give the same hash.
            let mut h = Hasher::new();
            for c in input(n).chunks(7) {
                h.update(c);
            }
            assert_eq!(hex(&h.finalize()), want, "incremental, length {}", n);
        }
    }

    #[test]
    fn keyed() {
        let key = *b"whats the Elvish word for friend";
        let v: &[(usize, &str)] = &[
            (0, "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"),
            (1024, "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4"),
        ];
        for &(n, want) in v {
            assert_eq!(hex(&Hasher::keyed(&key).update(&input(n)).finalize()), want, "keyed, length {}", n);
        }
    }
}
