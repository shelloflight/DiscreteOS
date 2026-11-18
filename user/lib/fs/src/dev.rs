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
