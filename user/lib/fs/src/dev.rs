//! Block devices: the interface every filesystem here is written against, partitions (a window
//! into a disk), an in-memory disk (host tools and tests), and `CutDev`, which simulates a
//! power failure under a filesystem (crash-consistency tests).

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::{Error, Result};

pub const SECTOR: usize = 512;

/// A disk of 512-byte sectors. Buffers are whole sectors. `flush` returns once everything
/// written before it is durable (the write barrier filesystems order their commits with).
pub trait BlockDev {
    fn sectors(&self) -> u64;
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<()>;
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
}

impl<T: BlockDev + ?Sized> BlockDev for alloc::boxed::Box<T> {
    fn sectors(&self) -> u64 {
        (**self).sectors()
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
        (**self).read(lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
        (**self).write(lba, buf)
    }
    fn flush(&mut self) -> Result<()> {
        (**self).flush()
    }
}

fn check(lba: u64, len: usize, sectors: u64) -> Result<()> {
    if !len.is_multiple_of(SECTOR) || lba.checked_add((len / SECTOR) as u64).is_none_or(|e| e > sectors) {
        return Err(Error::Io);
    }
    Ok(())
}

/// A disk shared by its partitions.
pub type Shared = Rc<RefCell<dyn BlockDev>>;

/// Sectors `start .. start + len` of a shared disk.
pub struct Part {
    pub disk: Shared,
    pub start: u64,
    pub len: u64,
}

impl BlockDev for Part {
    fn sectors(&self) -> u64 {
        self.len
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
        check(lba, buf.len(), self.len)?;
        self.disk.borrow_mut().read(self.start + lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
        check(lba, buf.len(), self.len)?;
        self.disk.borrow_mut().write(self.start + lba, buf)
    }
    fn flush(&mut self) -> Result<()> {
        self.disk.borrow_mut().flush()
    }
}

/// A disk in memory.
pub struct MemDev {
    pub data: Vec<u8>,
}

impl MemDev {
    pub fn new(sectors: u64) -> MemDev {
        MemDev { data: vec![0; sectors as usize * SECTOR] }
    }
}

impl BlockDev for MemDev {
    fn sectors(&self) -> u64 {
        (self.data.len() / SECTOR) as u64
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
        check(lba, buf.len(), self.sectors())?;
        let o = lba as usize * SECTOR;
        buf.copy_from_slice(&self.data[o..o + buf.len()]);
        Ok(())
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
        check(lba, buf.len(), self.sectors())?;
        let o = lba as usize * SECTOR;
        self.data[o..o + buf.len()].copy_from_slice(buf);
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Power-failure simulation. Writes are held in a volatile "drive cache" until `flush` (as a
/// real drive with a write cache may do), then reach the disk below. `arm(n)`: after `n` more
/// sectors are written the power fails (possibly in the middle of a write): of the writes still in the cache, a pseudo-random subset (chosen by
/// `seed`) reaches the disk and the rest is lost, in any order; every later write is dropped
/// while still reporting success, as the host would not notice either. `restore` brings the
/// power back (the cache is empty).
pub struct CutDev<D: BlockDev> {
    pub inner: D,
    cache: BTreeMap<u64, [u8; SECTOR]>,
    armed: Option<u64>,
    pub cut: bool,
    seed: u64,
    pub writes: u64,
}

impl<D: BlockDev> CutDev<D> {
    pub fn new(inner: D) -> CutDev<D> {
        CutDev { inner, cache: BTreeMap::new(), armed: None, cut: false, seed: 0, writes: 0 }
    }

    pub fn arm(&mut self, writes: u64, seed: u64) {
        self.armed = Some(writes);
        self.seed = seed | 1;
    }

    fn rand(&mut self) -> u64 {
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        self.seed
    }

    fn power_fail(&mut self) {
        let cache = core::mem::take(&mut self.cache);
        for (lba, s) in cache {
            if self.rand().is_multiple_of(2) {
                let _ = self.inner.write(lba, &s);
            }
        }
        self.cut = true;
        self.armed = None;
    }

    /// Power back on: an empty cache, writes reach the disk again.
    pub fn restore(&mut self) {
        self.cache.clear();
        self.cut = false;
        self.armed = None;
    }
}

impl<D: BlockDev> BlockDev for CutDev<D> {
    fn sectors(&self) -> u64 {
        self.inner.sectors()
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read(lba, buf)?;
        for (i, s) in buf.chunks_mut(SECTOR).enumerate() {
            if let Some(c) = self.cache.get(&(lba + i as u64)) {
                s.copy_from_slice(c);
            }
        }
        Ok(())
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
        check(lba, buf.len(), self.sectors())?;
        if self.armed.is_none() {
            if !self.cut {
                self.writes += (buf.len() / SECTOR) as u64;
                return self.inner.write(lba, buf); // not armed: no cache to model
            }
            return Ok(());
        }
        // Armed: sector by sector, so the power can fail in the middle of a write (torn).
        for (i, s) in buf.chunks(SECTOR).enumerate() {
            if self.cut {
                return Ok(());
            }
            match self.armed {
                Some(0) => {
                    self.power_fail();
                    return Ok(());
                }
                Some(n) => self.armed = Some(n - 1),
                None => {}
            }
            self.writes += 1;
            let mut c = [0u8; SECTOR];
            c.copy_from_slice(s);
            self.cache.insert(lba + i as u64, c);
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        if self.cut {
            return Ok(());
        }
        let cache = core::mem::take(&mut self.cache);
        let mut run: Vec<u8> = Vec::new();
        let mut start = 0;
        for (lba, s) in cache {
            if !run.is_empty() && (start + (run.len() / SECTOR) as u64 != lba || run.len() >= 64 * SECTOR) {
                self.inner.write(start, &run)?;
                run.clear();
            }
            if run.is_empty() {
                start = lba;
            }
            run.extend_from_slice(&s);
        }
        if !run.is_empty() {
            self.inner.write(start, &run)?;
        }
        self.inner.flush()
    }
}

/// A read cache with read-ahead over a disk: 4 KiB blocks in one buffer allocated up front,
/// evicted by the clock algorithm (a block read since the hand last passed it gets another round).
/// Write-through: a write reaches the disk below before it returns and updates the cached copy,
/// so the cache never holds anything the disk does not (a power cut loses nothing extra).
///
/// - Reads of `BYPASS` bytes or more go straight to the disk (they are as large as one disk
///   request already, and a long sequential read would only push useful blocks out).
/// - Smaller reads are served from the cache; missing blocks are fetched in runs. A miss that
///   continues where the last run ended is sequential: the run grows (`window` doubles, up to
///   `MAX_RUN` blocks) and reaches past the request (read-ahead), so a file read 4 KiB at a time
///   costs one disk request per 128 KiB. Any other miss fetches only what was asked.
pub struct CacheDev<D: BlockDev> {
    pub inner: D,
    data: Vec<u8>,
    /// Per slot: the block it holds (`u64::MAX`: free) and whether it was used since the hand passed.
    slots: Vec<(u64, bool)>,
    index: BTreeMap<u64, usize>,
    hand: usize,
    /// The block after the last run fetched, and the read-ahead window then.
    next_seq: u64,
    window: u64,
    pub stats: CacheStats,
}

pub const BLOCK: usize = 4096;
const SPB: u64 = (BLOCK / SECTOR) as u64;
/// Largest run fetched at once: 128 KiB.
pub const MAX_RUN: u64 = 32;
/// Reads at least this large bypass the cache.
pub const BYPASS: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    /// Reads sent to the disk below.
    pub requests: u64,
    /// Blocks fetched ahead of a request.
    pub ahead: u64,
    /// Large reads that went straight to the disk.
    pub bypassed: u64,
}

impl<D: BlockDev> CacheDev<D> {
    /// A cache of `bytes` (rounded down to whole blocks, at least 16), allocated now.
    pub fn new(inner: D, bytes: usize) -> CacheDev<D> {
        let cap = (bytes / BLOCK).max(16);
        CacheDev { inner, data: vec![0u8; cap * BLOCK], slots: vec![(u64::MAX, false); cap], index: BTreeMap::new(), hand: 0, next_seq: u64::MAX, window: 1, stats: CacheStats::default() }
    }

    fn whole_blocks(&self) -> u64 {
        self.inner.sectors() / SPB
    }

    fn slot_of(&self, b: u64) -> Option<usize> {
        self.index.get(&b).copied()
    }

    /// A slot for block `b`: a free one, else the first the clock hand finds unused.
    fn take_slot(&mut self, b: u64) -> usize {
        loop {
            let i = self.hand;
            self.hand = (self.hand + 1) % self.slots.len();
            let (old, used) = self.slots[i];
            if old == u64::MAX || !used {
                if old != u64::MAX {
                    self.index.remove(&old);
                }
                // Just fetched: it gets a round before it can go (it is about to be read).
                self.slots[i] = (b, true);
                self.index.insert(b, i);
                return i;
            }
            self.slots[i].1 = false;
        }
    }

    fn block(&self, slot: usize) -> &[u8] {
        &self.data[slot * BLOCK..(slot + 1) * BLOCK]
    }

    /// Fetch blocks `first .. first + n` (none cached) with one read and cache them.
    fn fetch(&mut self, first: u64, n: u64) -> Result<()> {
        let mut buf = vec![0u8; n as usize * BLOCK];
        self.inner.read(first * SPB, &mut buf)?;
        self.stats.requests += 1;
        for i in 0..n as usize {
            let s = self.take_slot(first + i as u64);
            self.data[s * BLOCK..(s + 1) * BLOCK].copy_from_slice(&buf[i * BLOCK..(i + 1) * BLOCK]);
        }
        Ok(())
    }

    /// Forget every cached block (tests).
    pub fn clear(&mut self) {
        self.index.clear();
        self.slots.iter_mut().for_each(|s| *s = (u64::MAX, false));
    }

    /// Blocks cached now.
    pub fn cached(&self) -> usize {
        self.index.len()
    }
}

impl<D: BlockDev> BlockDev for CacheDev<D> {
    fn sectors(&self) -> u64 {
        self.inner.sectors()
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
        check(lba, buf.len(), self.sectors())?;
        let n = (buf.len() / SECTOR) as u64;
        let (b0, b1) = (lba / SPB, (lba + n).div_ceil(SPB));
        if buf.len() >= BYPASS || b1 > self.whole_blocks() {
            // Large, or the disk's last partial block: straight from the disk (the cached copies
            // of those blocks are the same bytes: the cache is write-through).
            self.stats.requests += 1;
            self.stats.bypassed += u64::from(buf.len() >= BYPASS);
            return self.inner.read(lba, buf);
        }
        let mut b = b0;
        while b < b1 {
            let slot = match self.slot_of(b) {
                Some(s) => {
                    self.stats.hits += 1;
                    s
                }
                None => {
                    // A run of missing blocks from here (within the request), plus read-ahead.
                    // At most half the cache per fetch: what is fetched stays until it is read.
                    let max_run = MAX_RUN.min(self.slots.len() as u64 / 2);
                    let mut end = b + 1;
                    while end < b1 && self.slot_of(end).is_none() && end - b < max_run {
                        end += 1;
                    }
                    self.stats.misses += end - b;
                    self.window = if b == self.next_seq { (self.window * 2).clamp(4, MAX_RUN) } else { 1 };
                    let want = (end - b).max(self.window).min(max_run).max(end - b);
                    let limit = (b + want).min(self.whole_blocks());
                    let mut stop = end;
                    while stop < limit && self.slot_of(stop).is_none() {
                        stop += 1;
                    }
                    self.stats.ahead += stop - end;
                    self.fetch(b, stop - b)?;
                    self.next_seq = stop;
                    self.slot_of(b).ok_or(Error::Io)?
                }
            };
            self.slots[slot].1 = true;
            // Copy the overlap of block b with the request.
            let blk_lo = b * SPB;
            let lo = lba.max(blk_lo);
            let hi = (lba + n).min(blk_lo + SPB);
            let src = &self.block(slot)[((lo - blk_lo) as usize * SECTOR)..((hi - blk_lo) as usize * SECTOR)];
            let dst = (lo - lba) as usize * SECTOR;
            buf[dst..dst + src.len()].copy_from_slice(src);
            b += 1;
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
        check(lba, buf.len(), self.sectors())?;
        let r = self.inner.write(lba, buf);
        let n = (buf.len() / SECTOR) as u64;
        let (b0, b1) = (lba / SPB, (lba + n).div_ceil(SPB));
        for b in b0..b1 {
            let Some(s) = self.slot_of(b) else { continue };
            if r.is_err() {
                // What reached the disk is unknown: forget the block.
                self.index.remove(&b);
                self.slots[s] = (u64::MAX, false);
                continue;
            }
            let blk_lo = b * SPB;
            let lo = lba.max(blk_lo);
            let hi = (lba + n).min(blk_lo + SPB);
            let src = &buf[((lo - lba) as usize * SECTOR)..((hi - lba) as usize * SECTOR)];
            let at = s * BLOCK + (lo - blk_lo) as usize * SECTOR;
            self.data[at..at + src.len()].copy_from_slice(src);
        }
        r
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}
/// A shared handle to a `CutDev` (so a test can arm it while a filesystem owns it).
pub struct SharedCut<D: BlockDev>(pub Rc<RefCell<CutDev<D>>>);

impl<D: BlockDev> BlockDev for SharedCut<D> {
    fn sectors(&self) -> u64 {
        self.0.borrow().sectors()
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
        self.0.borrow_mut().read(lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
        self.0.borrow_mut().write(lba, buf)
    }
    fn flush(&mut self) -> Result<()> {
        self.0.borrow_mut().flush()
    }
}

/// CRC-32 (IEEE 802.3, reflected, as GPT uses).
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    /// Counts the reads that reach it.
    struct Counting(MemDev, u64);
    impl BlockDev for Counting {
        fn sectors(&self) -> u64 {
            self.0.sectors()
        }
        fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
            self.1 += 1;
            self.0.read(lba, buf)
        }
        fn write(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
            self.0.write(lba, buf)
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn cache_reads_ahead_and_stays_coherent() {
        let sectors = 8 * 512 + 3; // a partial last block
        let mut mem = MemDev::new(sectors);
        for (i, b) in mem.data.iter_mut().enumerate() {
            *b = (i / SECTOR) as u8 ^ (i as u8);
        }
        let reference = mem.data.clone();
        let mut c = CacheDev::new(Counting(mem, 0), 64 * BLOCK);
        // Sequential 4 KiB reads: far fewer requests than blocks.
        let mut b = [0u8; BLOCK];
        for blk in 0..256u64 {
            c.read(blk * SPB, &mut b).unwrap();
            assert_eq!(&b[..], &reference[blk as usize * BLOCK..(blk as usize + 1) * BLOCK]);
        }
        assert!(c.inner.1 < 20, "{} requests for 256 sequential blocks", c.inner.1);
        // Unaligned reads, across cached and uncached blocks, and the partial tail.
        let mut x = vec![0u8; 13 * SECTOR];
        for lba in [1u64, 7, 9, 1000, 2040, sectors - 13] {
            c.read(lba, &mut x).unwrap();
            assert_eq!(&x[..], &reference[lba as usize * SECTOR..lba as usize * SECTOR + x.len()], "lba {}", lba);
        }
        // Writes go through and update the cached copy.
        let w = [0xAAu8; 3 * SECTOR];
        c.write(5, &w).unwrap();
        c.read(4, &mut x[..5 * SECTOR]).unwrap();
        assert_eq!(&x[SECTOR..4 * SECTOR], &w[..]);
        let mut direct = [0u8; 3 * SECTOR];
        c.inner.0.read(5, &mut direct).unwrap();
        assert_eq!(direct, w);
        // Random reads: no read-ahead, eviction keeps the cache bounded.
        let before = c.stats.ahead;
        for k in 0..200u64 {
            let blk = (k * 7919) % 500;
            c.read(blk * SPB, &mut b).unwrap();
            let mut want = reference[blk as usize * BLOCK..(blk as usize + 1) * BLOCK].to_vec();
            if blk == 0 {
                want[5 * SECTOR..8 * SECTOR].copy_from_slice(&w[..3 * SECTOR]);
            }
            assert_eq!(&b[..], &want[..]);
        }
        assert!(c.stats.ahead - before < 50);
        assert!(c.cached() <= 64);
        // A large read goes straight to the disk.
        let mut big = vec![0u8; BYPASS];
        let reqs = c.inner.1;
        c.read(400 * SPB, &mut big).unwrap();
        assert_eq!(c.inner.1, reqs + 1);
        assert_eq!(&big[..], &reference[400 * BLOCK..400 * BLOCK + BYPASS]);
    }

    #[test]
    fn cut_drops_later_writes() {
        let mut d = CutDev::new(MemDev::new(16));
        d.write(0, &[1; SECTOR]).unwrap();
        d.arm(1, 7);
        d.write(1, &[2; SECTOR]).unwrap(); // cached
        d.flush().unwrap(); // durable
        d.write(2, &[3; SECTOR]).unwrap(); // power fails here: dropped
        assert!(d.cut);
        d.write(3, &[4; SECTOR]).unwrap();
        d.restore();
        let mut b = [0u8; SECTOR];
        for (lba, want) in [(0, 1), (1, 2), (2, 0), (3, 0)] {
            d.read(lba, &mut b).unwrap();
            assert_eq!(b[0], want, "sector {}", lba);
        }
    }
}
